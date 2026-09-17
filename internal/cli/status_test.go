package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/gateway"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// cliRun runs the CLI in-process and captures stdout, stderr and the exit
// code, mirroring a user invoking the built binary.
func cliRun(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

// seedControlSession writes the two discovery files a running daemon leaves in
// its data directory: run.json and control.token.
func seedControlSession(t *testing.T, dir string, st gateway.RunState, token string) {
	t.Helper()
	if err := gateway.WriteRunState(dir, st); err != nil {
		t.Fatalf("seed run state: %v", err)
	}
	if _, err := proxy.WriteControlToken(dir, token); err != nil {
		t.Fatalf("seed control token: %v", err)
	}
}

// freeLoopbackPort reserves and releases an ephemeral loopback port so a
// subsequent dial is refused deterministically.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return port
}

// controlStub is a minimal control-plane double: it enforces the bearer token,
// records what the CLI sent and serves the canned body for /status. It
// deliberately skips the production guards so a unit test can pin client
// behavior (headers, parsing) without the full daemon.
type controlStub struct {
	token  string
	code   int
	status string

	mu    sync.Mutex
	paths []string
	auths []string
}

// ServeHTTP implements the stub contract.
func (s *controlStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.auths = append(s.auths, r.Header.Get("Authorization"))
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	switch r.URL.Path {
	case controlStatusPath:
		w.WriteHeader(s.code)
		_, _ = io.WriteString(w, s.status)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// sawAuth reports whether any request carried exactly the given header value.
func (s *controlStub) sawAuth(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, got := range s.auths {
		if got == value {
			return true
		}
	}
	return false
}

// newControlStub serves the stub on an ephemeral loopback port and returns it.
func newControlStub(t *testing.T, s *controlStub) int {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	_, portText, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("stub listener address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("stub listener port: %v", err)
	}
	return port
}

// TestStatusAudit locks the W6.3 contract: `status` reads the daemon's control
// API with the per-session bearer token, renders metadata only, offers
// parseable `--json`, and degrades safely for every adversarial class (no
// session, stale session, missing token, malformed state/response, wrong
// token).
func TestStatusAudit(t *testing.T) {
	const (
		statusToken = "tok-status-7d1f"
	)

	t.Run("live_daemon_status", func(t *testing.T) {
		upstream := &echoUpstream{}
		upstreamSrv := httptest.NewServer(upstream)
		defer upstreamSrv.Close()

		dataDir := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", dataDir)

		cfg := config.Default()
		cfg.Listen.Host = "127.0.0.1"
		cfg.Listen.Port = 0
		cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

		base, token, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir})
		defer func() { _ = stop() }()

		// One real request through the data plane, carrying a synthetic secret
		// that the prefix detector redacts.
		secret := runSecret()
		body := fmt.Sprintf(`{"model":"status-audit","messages":[{"role":"user","content":%q}]}`, secret)
		resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
		clientBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read client body: %v", err)
		}
		if !strings.Contains(string(clientBody), secret) {
			t.Fatalf("client body %q lost the backfilled secret", clientBody)
		}
		upstreamBody := upstream.received()
		if bytes.Contains(upstreamBody, []byte(secret)) {
			t.Fatalf("upstream received the raw secret: %q", upstreamBody)
		}

		// status (text): running, address and session counters.
		stdout, stderr, code := cliRun(t, "status")
		if code != ExitOK {
			t.Fatalf("status code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		for _, want := range []string{
			"tokenhush: gateway running",
			"address: 127.0.0.1:",
			"uptime: ",
			"requests: 1",
			"redactions: 1",
			// W6.5: a clean run reports zero for every self-protection,
			// stream-guard and egress counter.
			"self-protection interceptions: 0",
			"allowlist mutations: 0",
			"stream guard refusals: 0",
			"stream guard fail-closed: 0",
			"egress blocks: 0",
			"content policy blocks: 0",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("status stdout = %q, want it to contain %q", stdout, want)
			}
		}
		if strings.Contains(stdout, token) || strings.Contains(stderr, token) {
			t.Fatalf("status leaked the control token (stdout=%q stderr=%q)", stdout, stderr)
		}

		// status --json: the same snapshot, parseable.
		stdout, stderr, code = cliRun(t, "status", "--json")
		if code != ExitOK {
			t.Fatalf("status --json code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		var view struct {
			Running                     bool     `json:"running"`
			PID                         int      `json:"pid"`
			State                       string   `json:"state"`
			Addrs                       []string `json:"addrs"`
			UptimeMS                    int64    `json:"uptime_ms"`
			Requests                    uint64   `json:"requests"`
			Redactions                  uint64   `json:"redactions"`
			SelfProtectionInterceptions uint64   `json:"self_protection_interceptions"`
			AllowlistMutations          uint64   `json:"allowlist_mutations"`
			StreamGuardRefusals         uint64   `json:"stream_guard_refusals"`
			StreamGuardFailClosed       uint64   `json:"stream_guard_fail_closed"`
			EgressBlocks                uint64   `json:"egress_blocks"`
			ContentPolicyBlocks         uint64   `json:"content_policy_blocks"`
		}
		if err := json.Unmarshal([]byte(stdout), &view); err != nil {
			t.Fatalf("status --json did not parse: %v (stdout=%q)", err, stdout)
		}
		if !view.Running || view.State != "running" || len(view.Addrs) == 0 {
			t.Fatalf("status --json = %+v, want running with at least one address", view)
		}
		if view.Requests < 1 || view.Redactions < 1 {
			t.Fatalf("status --json counters = requests %d redactions %d, want >= 1 each", view.Requests, view.Redactions)
		}
		// W6.5: this run performed no interception, mutation, streamed refusal
		// or egress block, so every new counter must be exactly zero.
		if view.SelfProtectionInterceptions != 0 || view.AllowlistMutations != 0 ||
			view.StreamGuardRefusals != 0 || view.StreamGuardFailClosed != 0 || view.EgressBlocks != 0 ||
			view.ContentPolicyBlocks != 0 {
			t.Fatalf("status --json self-protection counters = %+v, want all zero on a clean run", view)
		}
	})

	t.Run("status_fake_snapshot_text_and_json", func(t *testing.T) {
		stub := &controlStub{
			token: statusToken,
			code:  http.StatusOK,
			status: `{"state":"running","addrs":["127.0.0.1:8787","[::1]:8787"],"uptime_ms":83000,"requests":7,"redactions":3,` +
				`"allowlist":0,"self_protection_interceptions":5,"allowlist_mutations":2,` +
				`"stream_guard_refusals":3,"stream_guard_fail_closed":1,"egress_blocks":4,"content_policy_blocks":6}`,
		}
		port := newControlStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, gateway.RunState{PID: 4242, Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, statusToken)

		stdout, stderr, code := cliRun(t, "status")
		if code != ExitOK {
			t.Fatalf("status code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		for _, want := range []string{
			"tokenhush: gateway running",
			"pid: 4242",
			"address: 127.0.0.1:8787, [::1]:8787",
			"uptime: 1m23s",
			"requests: 7",
			"redactions: 3",
			// W6.5: the self-protection, stream-guard and egress counters are
			// rendered from the control snapshot, never hardcoded.
			"self-protection interceptions: 5",
			"allowlist mutations: 2",
			"stream guard refusals: 3",
			"stream guard fail-closed: 1",
			"egress blocks: 4",
			// The content-policy counter is rendered from the snapshot too: a
			// non-zero value proves the printer is not a hardcoded zero.
			"content policy blocks: 6",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("status stdout = %q, want it to contain %q", stdout, want)
			}
		}
		if !stub.sawAuth("Bearer " + statusToken) {
			t.Fatalf("status did not send the bearer token")
		}

		stdout, _, code = cliRun(t, "status", "--json")
		if code != ExitOK {
			t.Fatalf("status --json code = %d, want %d", code, ExitOK)
		}
		var view struct {
			Running                     bool     `json:"running"`
			PID                         int      `json:"pid"`
			State                       string   `json:"state"`
			Addrs                       []string `json:"addrs"`
			UptimeMS                    int64    `json:"uptime_ms"`
			Requests                    uint64   `json:"requests"`
			Redactions                  uint64   `json:"redactions"`
			SelfProtectionInterceptions uint64   `json:"self_protection_interceptions"`
			AllowlistMutations          uint64   `json:"allowlist_mutations"`
			StreamGuardRefusals         uint64   `json:"stream_guard_refusals"`
			StreamGuardFailClosed       uint64   `json:"stream_guard_fail_closed"`
			EgressBlocks                uint64   `json:"egress_blocks"`
			ContentPolicyBlocks         uint64   `json:"content_policy_blocks"`
		}
		if err := json.Unmarshal([]byte(stdout), &view); err != nil {
			t.Fatalf("status --json did not parse: %v (stdout=%q)", err, stdout)
		}
		if !view.Running || view.PID != 4242 || view.State != "running" ||
			view.UptimeMS != 83000 || view.Requests != 7 || view.Redactions != 3 {
			t.Fatalf("status --json = %+v, want the stubbed snapshot", view)
		}
		if view.SelfProtectionInterceptions != 5 || view.AllowlistMutations != 2 ||
			view.StreamGuardRefusals != 3 || view.StreamGuardFailClosed != 1 || view.EgressBlocks != 4 ||
			view.ContentPolicyBlocks != 6 {
			t.Fatalf("status --json self-protection counters = %+v, want the stubbed snapshot", view)
		}
		if len(view.Addrs) != 2 || view.Addrs[0] != "127.0.0.1:8787" || view.Addrs[1] != "[::1]:8787" {
			t.Fatalf("status --json addrs = %v, want the stubbed addresses", view.Addrs)
		}
	})

	t.Run("status_not_running_without_session", func(t *testing.T) {
		t.Setenv("TOKENHUSH_HOME", t.TempDir())

		stdout, stderr, code := cliRun(t, "status")
		if code != ExitFailure {
			t.Fatalf("status code = %d, want %d", code, ExitFailure)
		}
		if strings.TrimSpace(stdout) != "tokenhush: gateway not running" {
			t.Fatalf("status stdout = %q, want the not-running line", stdout)
		}
		if strings.Contains(stderr, "%!") {
			t.Fatalf("status stderr looks malformed: %q", stderr)
		}

		stdout, _, code = cliRun(t, "status", "--json")
		if code != ExitFailure {
			t.Fatalf("status --json code = %d, want %d", code, ExitFailure)
		}
		var view struct {
			Running bool `json:"running"`
		}
		if err := json.Unmarshal([]byte(stdout), &view); err != nil {
			t.Fatalf("status --json did not parse: %v (stdout=%q)", err, stdout)
		}
		if view.Running {
			t.Fatalf("status --json = %q, want running=false", stdout)
		}
	})

	t.Run("status_not_running_when_session_is_stale", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, gateway.RunState{PID: 999999, Port: freeLoopbackPort(t)}, statusToken)

		stdout, stderr, code := cliRun(t, "status")
		if code != ExitFailure {
			t.Fatalf("status code = %d, want %d", code, ExitFailure)
		}
		if !strings.Contains(stdout, "gateway not running") {
			t.Fatalf("status stdout = %q, want the not-running line", stdout)
		}
		if !strings.Contains(stderr, "not reachable") {
			t.Fatalf("status stderr = %q, want the unreachable detail", stderr)
		}
		if strings.Contains(stderr, statusToken) {
			t.Fatalf("status stderr leaked the control token: %q", stderr)
		}
	})

	t.Run("status_fails_when_control_token_is_missing", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		if err := gateway.WriteRunState(home, gateway.RunState{PID: 1, Port: freeLoopbackPort(t)}); err != nil {
			t.Fatalf("seed run state: %v", err)
		}

		_, stderr, code := cliRun(t, "status")
		if code != ExitFailure {
			t.Fatalf("status code = %d, want %d", code, ExitFailure)
		}
		if !strings.Contains(strings.ToLower(stderr), "control token") {
			t.Fatalf("status stderr = %q, want a missing control-token message", stderr)
		}
	})

	t.Run("status_fails_on_malformed_run_state", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		if err := os.WriteFile(filepath.Join(home, gateway.RunStateFileName), []byte("{not-json\n"), 0o600); err != nil {
			t.Fatalf("write malformed run state: %v", err)
		}
		if _, err := proxy.WriteControlToken(home, statusToken); err != nil {
			t.Fatalf("seed control token: %v", err)
		}

		_, stderr, code := cliRun(t, "status")
		if code != ExitFailure {
			t.Fatalf("status code = %d, want %d", code, ExitFailure)
		}
		if !strings.Contains(stderr, "session state") {
			t.Fatalf("status stderr = %q, want a session-state message", stderr)
		}
	})

	t.Run("status_fails_on_malformed_control_response", func(t *testing.T) {
		stub := &controlStub{token: statusToken, code: http.StatusOK, status: "{not-json"}
		port := newControlStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, gateway.RunState{PID: 1, Port: port}, statusToken)

		_, stderr, code := cliRun(t, "status")
		if code != ExitFailure {
			t.Fatalf("status code = %d, want %d", code, ExitFailure)
		}
		if !strings.Contains(strings.ToLower(stderr), "malformed") {
			t.Fatalf("status stderr = %q, want a malformed-response message", stderr)
		}
	})

	t.Run("status_fails_on_non_200_control_response", func(t *testing.T) {
		stub := &controlStub{token: statusToken, code: http.StatusInternalServerError, status: `{"error":"audit query failed"}`}
		port := newControlStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, gateway.RunState{PID: 1, Port: port}, statusToken)

		_, stderr, code := cliRun(t, "status")
		if code != ExitFailure {
			t.Fatalf("status code = %d, want %d", code, ExitFailure)
		}
		if !strings.Contains(stderr, "500") || !strings.Contains(stderr, "audit query failed") {
			t.Fatalf("status stderr = %q, want the HTTP status and the stable API error", stderr)
		}
	})

	t.Run("status_fails_on_wrong_control_token", func(t *testing.T) {
		stub := &controlStub{token: "the-right-token", code: http.StatusOK, status: `{"state":"running"}`}
		port := newControlStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, gateway.RunState{PID: 1, Port: port}, "the-wrong-token")

		_, stderr, code := cliRun(t, "status")
		if code != ExitFailure {
			t.Fatalf("status code = %d, want %d", code, ExitFailure)
		}
		if !strings.Contains(strings.ToLower(stderr), "rejected") {
			t.Fatalf("status stderr = %q, want a rejected-token message", stderr)
		}
		for _, leak := range []string{"the-wrong-token", "the-right-token"} {
			if strings.Contains(stderr, leak) {
				t.Fatalf("status stderr leaked a token: %q", stderr)
			}
		}
	})

	t.Run("unknown_flags_and_extra_args_are_usage_errors", func(t *testing.T) {
		for _, args := range [][]string{
			{"status", "--bogus"},
			{"audit", "--bogus"},
			{"status", "extra"},
			{"audit", "extra"},
		} {
			_, stderr, code := cliRun(t, args...)
			if code != ExitUsage {
				t.Fatalf("%v code = %d, want %d (stderr=%q)", args, code, ExitUsage, stderr)
			}
			if !strings.Contains(strings.ToLower(stderr), "usage") {
				t.Fatalf("%v stderr = %q, want a usage line", args, stderr)
			}
		}
	})

}
