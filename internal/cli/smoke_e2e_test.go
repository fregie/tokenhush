package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/gateway"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// smokeHTTPTimeout bounds every client-side network step of the smoke test, so
// a daemon that stops answering fails the test instead of hanging CI
// (adversarial class: hung_or_long_commands). The daemon lifecycle helper has
// its own 15s ready/shutdown bounds.
const smokeHTTPTimeout = 30 * time.Second

// smokeClient is the bounded HTTP client every smoke request uses.
var smokeClient = &http.Client{Timeout: smokeHTTPTimeout}

// smokeUpstream is the fake upstream. It records every request body
// byte-for-byte and echoes the received body back inside a JSON envelope, so
// the client round-trip exercises the daemon's inbound backfill.
type smokeUpstream struct {
	mu     sync.Mutex
	bodies [][]byte
	hits   atomic.Int64
}

// ServeHTTP records the exact request bytes and answers with the JSON echo.
func (u *smokeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.bodies = append(u.bodies, append([]byte(nil), body...))
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"echo":%q}`, string(body))
}

// bodyn returns a copy of the n-th request body the upstream received.
func (u *smokeUpstream) bodyn(t *testing.T, n int) []byte {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if n >= len(u.bodies) {
		t.Fatalf("upstream received %d requests, want at least %d", len(u.bodies), n+1)
	}
	return append([]byte(nil), u.bodies[n]...)
}

// smokeConfig is a hermetic daemon configuration: an ephemeral loopback port
// and a single fake upstream for the Messages path the smoke bodies target.
func smokeConfig(upstreamURL string) config.Config {
	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamURL}
	return cfg
}

// smokePost sends body to url with the bounded smoke client and reads the
// response fully, so no caller can leak a live connection.
func smokePost(t *testing.T, url, body string) (status int, respBody []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new smoke request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := smokeClient.Do(req)
	if err != nil {
		t.Fatalf("smoke POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read smoke response: %v", err)
	}
	return resp.StatusCode, respBody
}

// assertDaemonCleanup is the cleanup receipt for one smoke daemon: stop() must
// report a clean RunServer exit, both session discovery files must be gone, no
// half-written session temp file may remain, and the loopback port must no
// longer accept connections.
func assertDaemonCleanup(t *testing.T, dataDir, base string, stop func() error) {
	t.Helper()
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	for _, name := range []string{gateway.RunStateFileName, proxy.ControlTokenFileName} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("session file %s still present after shutdown (err=%v)", name, err)
		}
	}
	if leftovers, err := filepath.Glob(filepath.Join(dataDir, ".run-state-*")); err != nil {
		t.Fatalf("glob session temp files: %v", err)
	} else if len(leftovers) != 0 {
		t.Errorf("session temp files left behind: %v", leftovers)
	}
	addr := strings.TrimPrefix(base, "http://")
	conn, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("daemon still accepting connections on %s after shutdown", addr)
	}
}

// TestSmokeE2E is the W6.4 cross-platform integration smoke test
// (docs/deployment.md): it starts the real daemon through RunServer against a
// fake upstream and pins the redaction contract in exact bytes.
//
// Outbound, the upstream receives this session's placeholder and never the
// secret. Inbound, the client receives the original secret and never the
// placeholder. And the reverse mapping is never consulted outbound: a request
// body that already carries a placeholder literal is forwarded upstream
// verbatim (docs/security.md).
//
// The test is hermetic — temp data dir, in-memory SecretStore, ephemeral
// loopback port, httptest upstream — and every network step is bounded. Each
// subtest ends with a cleanup receipt: clean RunServer exit, session files
// removed, port released.
func TestSmokeE2E(t *testing.T) {
	t.Run("redact_upstream_backfill_client", func(t *testing.T) {
		upstream := &smokeUpstream{}
		upstreamSrv := httptest.NewServer(upstream)
		t.Cleanup(upstreamSrv.Close)

		dataDir := t.TempDir()
		cfg := smokeConfig(upstreamSrv.URL)
		installNoPackRulesSeam(t)
		base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir})
		t.Cleanup(func() { _ = stop() })

		secret := runSecret()
		request := fmt.Sprintf(`{"model":"smoke-e2e","messages":[{"role":"user","content":%q}]}`, secret)

		status, clientBody := smokePost(t, base+"/v1/messages", request)
		if status != http.StatusOK {
			t.Fatalf("data-plane status = %d, want %d", status, http.StatusOK)
		}

		// Exact outbound bytes: the single secret occurrence became exactly one
		// placeholder and every other byte is unchanged.
		received := upstream.bodyn(t, 0)
		if bytes.Contains(received, []byte(secret)) {
			t.Fatal("upstream received the raw secret; outbound redaction is broken")
		}
		matches := runPlaceholderRe.FindAll(received, -1)
		if len(matches) != 1 {
			t.Fatalf("upstream body carries %d placeholders, want exactly 1: %s", len(matches), received)
		}
		wantUpstream := bytes.Replace([]byte(request), []byte(secret), matches[0], 1)
		if !bytes.Equal(received, wantUpstream) {
			t.Fatalf("upstream bytes differ: got %d bytes, want %d bytes", len(received), len(wantUpstream))
		}

		// Exact inbound bytes: the echo of the placeholder comes back to the
		// client with the secret restored and no placeholder left behind.
		wantClient := fmt.Sprintf(`{"echo":%q}`, strings.ReplaceAll(string(received), string(matches[0]), secret))
		if !bytes.Equal(clientBody, []byte(wantClient)) {
			t.Fatalf("client bytes differ: got %d bytes, want %d bytes", len(clientBody), len(wantClient))
		}
		if !bytes.Contains(clientBody, []byte(secret)) {
			t.Fatal("client body lost the original secret after inbound backfill")
		}
		if runPlaceholderRe.Match(clientBody) {
			t.Fatal("client body still carries a placeholder after inbound backfill")
		}

		assertDaemonCleanup(t, dataDir, base, stop)
	})

	t.Run("outbound_placeholder_not_backfilled", func(t *testing.T) {
		upstream := &smokeUpstream{}
		upstreamSrv := httptest.NewServer(upstream)
		t.Cleanup(upstreamSrv.Close)

		dataDir := t.TempDir()
		cfg := smokeConfig(upstreamSrv.URL)
		// Only the prefix detector: the replay body carries a placeholder
		// literal whose hex digest other heuristics may legitimately flag.
		// This subtest isolates the outbound direction (never consult the
		// reverse mapping), mirroring the pkg/proxy unit test of the same
		// invariant.
		cfg.Detectors = config.Detectors{Prefix: true}
		installNoPackRulesSeam(t)
		base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir})
		t.Cleanup(func() { _ = stop() })

		// Request 1: learn this session's placeholder for the secret.
		secret := runSecret()
		learn := fmt.Sprintf(`{"model":"smoke-e2e","messages":[{"role":"user","content":%q}]}`, secret)
		if status, _ := smokePost(t, base+"/v1/messages", learn); status != http.StatusOK {
			t.Fatalf("learn-request status = %d, want %d", status, http.StatusOK)
		}
		matches := runPlaceholderRe.FindAll(upstream.bodyn(t, 0), -1)
		if len(matches) != 1 {
			t.Fatalf("learn request carries %d placeholders, want exactly 1", len(matches))
		}
		placeholder := string(matches[0])

		// Request 2: replay the session's own placeholder as content. The
		// outbound path must forward it byte-for-byte; restoring it would send
		// the secret upstream.
		replay := fmt.Sprintf(`{"model":"smoke-e2e","messages":[{"role":"user","content":%q}]}`, placeholder)
		status, clientBody := smokePost(t, base+"/v1/messages", replay)
		if status != http.StatusOK {
			t.Fatalf("replay status = %d, want %d", status, http.StatusOK)
		}
		got := upstream.bodyn(t, 1)
		if !bytes.Equal(got, []byte(replay)) {
			t.Fatalf("upstream bytes differ: outbound backfill restored the placeholder (got %d bytes, want %d)", len(got), len(replay))
		}
		if bytes.Contains(got, []byte(secret)) {
			t.Fatal("upstream received the raw secret; outbound backfill is reachable")
		}

		// The reply to the replay proves the inbound direction still restores:
		// the echoed placeholder comes back as the secret.
		wantClient := fmt.Sprintf(`{"echo":%q}`, strings.ReplaceAll(replay, placeholder, secret))
		if !bytes.Equal(clientBody, []byte(wantClient)) {
			t.Fatalf("client bytes differ: got %d bytes, want %d bytes", len(clientBody), len(wantClient))
		}
		if !bytes.Contains(clientBody, []byte(secret)) {
			t.Fatal("client body lost the original secret after inbound backfill")
		}
		if got := upstream.hits.Load(); got != 2 {
			t.Fatalf("upstream hits = %d, want 2", got)
		}

		assertDaemonCleanup(t, dataDir, base, stop)
	})
}
