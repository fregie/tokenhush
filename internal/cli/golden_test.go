package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
)

// goldenBaselinePath is the committed pre-extraction baseline of the core
// daemon's observable behavior. It is the oracle WA.1b must keep green while
// pkg/gateway is extracted from internal/cli.
var goldenBaselinePath = filepath.Join("testdata", "golden_baseline.txt")

// updateGolden rewrites the baseline from the current run instead of comparing.
// It is an explicit opt-in so a normal `go test` never mutates committed data:
//
//	go test ./internal/cli -run TestGoldenBaseline -update-golden
var updateGolden = flag.Bool("update-golden", false, "rewrite internal/cli/testdata golden files")

// Volatile-value normalizers. Every substitution below removes exactly one
// run-to-run value that the refactor cannot be asked to preserve; everything
// else in the output is compared byte for byte.
var (
	// goldenUptimeRe strips the moving GET /status uptime_ms counter.
	goldenUptimeRe = regexp.MustCompile(`"uptime_ms":\d+`)
	// goldenPortRe collapses the ephemeral loopback port in bound addresses
	// and the startup line to <PORT>.
	goldenPortRe = regexp.MustCompile(`(127\.0\.0\.1|\[::1\]):\d+`)
	// goldenDigestRe strips the per-session random HMAC digest from a
	// placeholder token, leaving the grammar and detector type pinned.
	goldenDigestRe = regexp.MustCompile(`(__PII_[a-z][a-z0-9_]*_)[0-9a-f]{8,}__`)
)

// normalizeGolden rewrites one captured output so only the volatile runtime
// values remain symbolic. dataDir and tokenPath are the per-test temp paths;
// secret is the synthetic credential the request carried.
func normalizeGolden(s, dataDir, tokenPath, secret string) string {
	s = strings.ReplaceAll(s, tokenPath, "<DATADIR>/control.token")
	s = strings.ReplaceAll(s, dataDir, "<DATADIR>")
	s = goldenUptimeRe.ReplaceAllString(s, `"uptime_ms":<UPTIME>`)
	s = goldenPortRe.ReplaceAllString(s, "$1:<PORT>")
	s = goldenDigestRe.ReplaceAllString(s, "${1}<DIGEST>__")
	s = strings.ReplaceAll(s, secret, "<SECRET>")
	return s
}

// TestGoldenBaseline pins the core daemon's observable behavior before the
// pkg/gateway extraction: the normalized /status JSON, the startup lines, the
// /audit fallback on core (there is no control-plane audit endpoint, so an
// unknown data-plane path is a 502, never an empty audit payload), one
// redacted request's exact upstream and client-backfill bytes, and the
// graceful-shutdown exit code.
//
// The test is hermetic — temp data dir, ephemeral loopback port, httptest
// upstream — and deterministic under -count=N: every run-to-run value (port,
// uptime, temp path, per-session placeholder digest) is normalized before the
// byte comparison, and nothing the refactor must preserve is normalized away.
func TestGoldenBaseline(t *testing.T) {
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	dataDir := t.TempDir()
	var startup bytes.Buffer

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

	base, token, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir, Stdout: &startup})

	secret := runSecret()
	request := fmt.Sprintf(`{"model":"golden-baseline","messages":[{"role":"user","content":%q}]}`, secret)

	// One redacted request: the client body carries the secret, the upstream
	// must receive a placeholder instead, and the echoed placeholder must come
	// back to the client restored. These assertions stand on their own so the
	// test is never a no-op even if the golden file were regenerated blindly.
	resp := postBody(t, base+"/v1/messages", "application/json", request, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("data-plane status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	clientRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read client body: %v", err)
	}
	upstreamRaw := upstream.received()

	if bytes.Contains(upstreamRaw, []byte(secret)) {
		t.Fatal("upstream received the raw secret; outbound redaction is broken")
	}
	if matches := runPlaceholderRe.FindAll(upstreamRaw, -1); len(matches) != 1 {
		t.Fatalf("upstream body carries %d placeholders, want exactly 1: %q", len(matches), upstreamRaw)
	}
	if !bytes.Contains(clientRaw, []byte(secret)) {
		t.Fatal("client body lost the original secret after inbound backfill")
	}
	if runPlaceholderRe.Match(clientRaw) {
		t.Fatal("client body still carries a placeholder after inbound backfill")
	}

	// GET /status after exactly the one data-plane request, so the counters in
	// the baseline are stable (1 request, 1 redaction).
	statusResp := doGet(t, base+"/status", token, "")
	statusRaw, err := io.ReadAll(statusResp.Body)
	if err != nil {
		t.Fatalf("read status body: %v", err)
	}
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", statusResp.StatusCode, http.StatusOK)
	}

	// /audit is not a core control endpoint. It falls through to the data
	// plane, resolves to no upstream and becomes a 502 — the baseline must not
	// accept an empty/200 audit payload as the fallback.
	auditResp := doGet(t, base+"/audit", token, "")
	auditRaw, err := io.ReadAll(auditResp.Body)
	if err != nil {
		t.Fatalf("read audit body: %v", err)
	}
	if auditResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("GET /audit status = %d, want %d (core has no /audit control endpoint)",
			auditResp.StatusCode, http.StatusBadGateway)
	}

	// Graceful shutdown: RunServer returning nil is the daemon's clean exit.
	shutdownErr := stop()
	exitCode := ExitOK
	if shutdownErr != nil {
		exitCode = ExitFailure
	}
	if exitCode != ExitOK {
		t.Fatalf("graceful shutdown exit code = %d, want %d (err %v)", exitCode, ExitOK, shutdownErr)
	}

	tokenPath := controlTokenPath(dataDir)
	norm := func(s string) string { return normalizeGolden(s, dataDir, tokenPath, secret) }

	var b strings.Builder
	fmt.Fprintf(&b, "# tokenhush core pre-extraction golden baseline (WA.1a)\n")
	fmt.Fprintf(&b, "# Compared by TestGoldenBaseline. All lines are byte-exact after\n")
	fmt.Fprintf(&b, "# normalizing only these runtime-volatile values:\n")
	fmt.Fprintf(&b, "#   <PORT>     ephemeral loopback port\n")
	fmt.Fprintf(&b, "#   <UPTIME>   GET /status uptime_ms\n")
	fmt.Fprintf(&b, "#   <DATADIR>  per-test temp data directory\n")
	fmt.Fprintf(&b, "#   <DIGEST>   per-session random HMAC digest inside a placeholder\n")
	fmt.Fprintf(&b, "#   <SECRET>   synthetic credential the request carried\n")
	fmt.Fprintf(&b, "# Regenerate after an intentional change:\n")
	fmt.Fprintf(&b, "#   go test ./internal/cli -run TestGoldenBaseline -update-golden\n")
	fmt.Fprintf(&b, "\n[status] HTTP %d\n%s", statusResp.StatusCode, norm(string(statusRaw)))
	fmt.Fprintf(&b, "\n[startup]\n%s", norm(startup.String()))
	fmt.Fprintf(&b, "\n[audit-fallback] HTTP %d Content-Type: %s\n%s",
		auditResp.StatusCode, auditResp.Header.Get("Content-Type"), norm(string(auditRaw)))
	fmt.Fprintf(&b, "\n[redacted-request]\nrequest=%s\nupstream=%s\nclient=%s\n",
		norm(request), norm(string(upstreamRaw)), norm(string(clientRaw)))
	fmt.Fprintf(&b, "\n[shutdown]\nexit_code=%d\n", exitCode)
	want := b.String()

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenBaselinePath), 0o755); err != nil {
			t.Fatalf("create testdata dir: %v", err)
		}
		if err := os.WriteFile(goldenBaselinePath, []byte(want), 0o644); err != nil {
			t.Fatalf("write golden baseline: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", goldenBaselinePath, len(want))
		return
	}

	gotRaw, err := os.ReadFile(goldenBaselinePath)
	if err != nil {
		t.Fatalf("read golden baseline (regenerate with -update-golden): %v", err)
	}
	if string(gotRaw) != want {
		t.Errorf("golden baseline mismatch for %s\n--- want ---\n%s\n--- got ---\n%s",
			goldenBaselinePath, want, gotRaw)
	}
}
