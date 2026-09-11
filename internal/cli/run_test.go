package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// Synthetic credential assembled at runtime: the fragments never appear as one
// contiguous key-shaped literal in the tree (gitleaks-clean), while the joined
// value still matches the built-in `sk-` prefix detector.
const (
	runSecretHead = "sk"
	runSecretA    = "Te5tA1b2"
	runSecretB    = "C3d4E5f6"
	runSecretC    = "G7h8I9j0"
)

func runSecret() string {
	return runSecretHead + "-" + "proj" + "-" + runSecretA + runSecretB + runSecretC
}

var runPlaceholderRe = regexp.MustCompile(`__PII_[a-z][a-z0-9_]*_[0-9a-f]{8,}__`)

// recordingSink captures audit rows so a test can assert the daemon emitted
// its lifecycle events without a real store.
type recordingSink struct {
	mu   sync.Mutex
	recs []audit.Record
}

func (s *recordingSink) Record(rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, rec)
	return nil
}

func (s *recordingSink) paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.recs))
	for _, rec := range s.recs {
		out = append(out, rec.Path)
	}
	return out
}

// echoUpstream records the request body it received and echoes it back inside a
// JSON string, so an inbound round-trip proves backfill.
type echoUpstream struct {
	mu   sync.Mutex
	body []byte
	hits atomic.Int64
}

func (u *echoUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.body = body
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"echo":%q}`, string(body))
}

func (u *echoUpstream) received() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]byte(nil), u.body...)
}

// startTestDaemon runs RunServer on an ephemeral port and returns once it is
// ready, plus the control token read back from the session file. stop cancels
// the context, waits for a clean shutdown and returns RunServer's error.
func startTestDaemon(t *testing.T, cfg *config.Config, deps RunDeps) (base, token string, stop func() error) {
	t.Helper()
	if deps.DataDir == "" {
		deps.DataDir = t.TempDir()
	}
	ready := make(chan RunInfo, 1)
	deps.Ready = func(info RunInfo) { ready <- info }

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunServer(ctx, cfg, deps) }()

	select {
	case info := <-ready:
		tok, err := proxy.ReadControlToken(deps.DataDir)
		if err != nil {
			cancel()
			t.Fatalf("read control token: %v", err)
		}
		var once sync.Once
		var runErr error
		stop = func() error {
			once.Do(func() {
				cancel()
				select {
				case runErr = <-errCh:
				case <-time.After(15 * time.Second):
					t.Fatalf("RunServer did not shut down within 15s")
				}
			})
			return runErr
		}
		return fmt.Sprintf("http://127.0.0.1:%d", info.Port), tok, stop
	case err := <-errCh:
		cancel()
		t.Fatalf("RunServer exited before ready: %v", err)
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatalf("RunServer did not become ready within 15s")
	}
	return "", "", func() error { return nil }
}

// postBody sends a request with the given body and optional headers.
func postBody(t *testing.T, url, contentType, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// doGet sends a GET with an optional bearer token and Host override.
func doGet(t *testing.T, url, token, host string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestRunServerEndToEnd(t *testing.T) {
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

	secrets := newStubSecrets()
	dataDir := t.TempDir()
	base, token, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir, Secrets: secrets})

	secret := runSecret()
	body := fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`, secret)

	// Data plane: no bearer token required.
	resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("data-plane status = %d, want 200", resp.StatusCode)
	}
	clientBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(clientBody), secret) {
		t.Errorf("client body %q does not contain backfilled secret", clientBody)
	}

	upstreamBody := upstream.received()
	if bytes.Contains(upstreamBody, []byte(secret)) {
		t.Fatalf("upstream received the raw secret: %q", upstreamBody)
	}
	if !runPlaceholderRe.Match(upstreamBody) {
		t.Fatalf("upstream body %q has no placeholder", upstreamBody)
	}

	// GET /audit with the session token: the real store serves the daemon
	// lifecycle rows plus one metadata-only row per proxied request.
	auditResp := doGet(t, base+"/audit", token, "")
	if auditResp.StatusCode != http.StatusOK {
		t.Fatalf("audit code = %d, want 200", auditResp.StatusCode)
	}
	rawAudit, err := io.ReadAll(auditResp.Body)
	if err != nil {
		t.Fatalf("read audit body: %v", err)
	}
	if bytes.Contains(rawAudit, []byte(secret)) {
		t.Fatalf("audit output leaked the request secret: %s", rawAudit)
	}
	var records []audit.Record
	if err := json.Unmarshal(rawAudit, &records); err != nil {
		t.Fatalf("decode audit rows: %v", err)
	}
	if findAuditRecord(records, "daemon", "start") == nil {
		t.Errorf("startup audit row missing; got %+v", records)
	}
	requestRow := findAuditRecord(records, "anthropic", "/v1/messages")
	if requestRow == nil {
		t.Fatalf("per-request audit row missing; got %+v", records)
	}
	if requestRow.Method != http.MethodPost || requestRow.Status != http.StatusOK {
		t.Errorf("request row = %s/%d, want POST/200", requestRow.Method, requestRow.Status)
	}
	if requestRow.ReqBytes <= 0 || requestRow.RespBytes <= 0 {
		t.Errorf("request row bytes = %d/%d, want both positive", requestRow.ReqBytes, requestRow.RespBytes)
	}
	if requestRow.Redactions < 1 {
		t.Errorf("request row redactions = %d, want >= 1", requestRow.Redactions)
	}
	if len(requestRow.Detectors) == 0 {
		t.Errorf("request row detectors = %v, want at least one detector id", requestRow.Detectors)
	}

	// GET /status with the session token.
	statusResp := doGet(t, base+"/status", token, "")
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want 200", statusResp.StatusCode)
	}
	var status proxy.ControlStatus
	if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.State != proxy.ControlStateRunning {
		t.Errorf("state = %q, want %q", status.State, proxy.ControlStateRunning)
	}
	if len(status.Addrs) != 2 {
		t.Errorf("addrs = %v, want the v4 and v6 loopback listeners", status.Addrs)
	}
	if status.Requests < 1 {
		t.Errorf("requests = %d, want >= 1", status.Requests)
	}

	// Graceful shutdown via context cancel.
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	for _, name := range []string{RunStateFileName, proxy.ControlTokenFileName} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("session file %s still present after shutdown (err=%v)", name, err)
		}
	}
}

func TestRunServerControlGuards(t *testing.T) {
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}
	base, token, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: t.TempDir(), Secrets: newStubSecrets()})
	defer stop()

	if got := doGet(t, base+"/status", "", "").StatusCode; got != http.StatusUnauthorized {
		t.Errorf("control without token = %d, want 401", got)
	}
	if got := doGet(t, base+"/status", token, "evil.example").StatusCode; got != http.StatusForbidden {
		t.Errorf("foreign Host = %d, want 403", got)
	}
	if got := doGet(t, base+"/status", token, "").StatusCode; got != http.StatusOK {
		t.Errorf("control with token = %d, want 200", got)
	}
}

func TestRunServerPortInUse(t *testing.T) {
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = config.Port(port)
	dataDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = RunServer(ctx, &cfg, RunDeps{DataDir: dataDir, Secrets: newStubSecrets()})
	if !errors.Is(err, proxy.ErrAddrInUse) {
		t.Fatalf("RunServer error = %v, want ErrAddrInUse", err)
	}
	if _, statErr := os.Stat(filepath.Join(dataDir, proxy.ControlTokenFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("port-busy run wrote a control token (stat err=%v)", statErr)
	}
}

func TestRunServerFailClosedOnDetectorTimeout(t *testing.T) {
	tests := []struct {
		name       string
		timeout    time.Duration
		wantStatus int
		wantHits   int64
	}{
		{name: "detector timeout blocks instead of leaking", timeout: time.Nanosecond, wantStatus: http.StatusForbidden, wantHits: 0},
		{name: "default timeout forwards the redacted body", timeout: 0, wantStatus: http.StatusOK, wantHits: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := &echoUpstream{}
			upstreamSrv := httptest.NewServer(upstream)
			defer upstreamSrv.Close()

			cfg := config.Default()
			cfg.Listen.Host = "127.0.0.1"
			cfg.Listen.Port = 0
			cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}
			base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: t.TempDir(), Secrets: newStubSecrets(), PolicyTimeout: tt.timeout})
			defer stop()

			secret := runSecret()
			body := fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`,
				strings.Repeat("A", 1<<18)+" "+secret)

			resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if got := upstream.hits.Load(); got != tt.wantHits {
				t.Fatalf("upstream hits = %d, want %d", got, tt.wantHits)
			}
			if tt.wantHits == 1 {
				received := upstream.received()
				if bytes.Contains(received, []byte(secret)) {
					t.Errorf("upstream received the raw secret")
				}
				if !runPlaceholderRe.Match(received) {
					t.Errorf("upstream body has no placeholder")
				}
			}
		})
	}
}

func TestRunCommandPortInUse(t *testing.T) {
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	t.Setenv("TOKENHUSH_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := Run([]string{"run", "--port", strconv.Itoa(port)}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("exit code = %d, want %d (stderr %q)", code, ExitFailure, stderr.String())
	}
	if !strings.Contains(stderr.String(), "already in use") {
		t.Errorf("stderr = %q, want an address-in-use message", stderr.String())
	}
}

func TestRunCommandBadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokenhush.yaml")
	if err := os.WriteFile(path, []byte("listen:\n  host: 0.0.0.0\n  port: 8787\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TOKENHUSH_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := Run([]string{"run", "--config", path}, &stdout, &stderr)
	if code != ExitFailure {
		t.Fatalf("exit code = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "listen.host") {
		t.Errorf("stderr = %q, want it to name listen.host", stderr.String())
	}
}

// containsString reports whether want is in values.
func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
