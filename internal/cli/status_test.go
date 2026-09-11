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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
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
func seedControlSession(t *testing.T, dir string, st RunState, token string) {
	t.Helper()
	if err := writeRunState(dir, st); err != nil {
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
// records what the CLI sent and serves the canned bodies for /status and
// /audit. It deliberately skips the production guards so a unit test can pin
// client behavior (headers, query, parsing) without the full daemon.
type controlStub struct {
	token  string
	code   int
	status string
	audit  string

	mu     sync.Mutex
	paths  []string
	auths  []string
	limits []string
}

// ServeHTTP implements the stub contract.
func (s *controlStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.auths = append(s.auths, r.Header.Get("Authorization"))
	s.limits = append(s.limits, r.URL.Query().Get("limit"))
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
	case controlAuditPath:
		w.WriteHeader(s.code)
		_, _ = io.WriteString(w, s.audit)
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

// lastLimit returns the limit query parameter of the most recent request.
func (s *controlStub) lastLimit() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.limits) == 0 {
		return ""
	}
	return s.limits[len(s.limits)-1]
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

// findAuditPath returns the first record whose path equals path.
func findAuditPath(records []audit.Record, path string) *audit.Record {
	for i := range records {
		if records[i].Path == path {
			return &records[i]
		}
	}
	return nil
}

// TestStatusAudit locks the W6.3 contract: `status` and `audit` read the
// daemon's control API with the per-session bearer token, render metadata only,
// offer parseable `--json`, and degrade safely for every adversarial class (no
// session, stale session, missing token, malformed state/response, wrong
// token, out-of-range limit).
func TestStatusAudit(t *testing.T) {
	const (
		statusToken = "tok-status-7d1f"
		auditToken  = "tok-audit-3c9a"
	)

	t.Run("live_daemon_status_and_audit", func(t *testing.T) {
		upstream := &echoUpstream{}
		upstreamSrv := httptest.NewServer(upstream)
		defer upstreamSrv.Close()

		dataDir := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", dataDir)

		cfg := config.Default()
		cfg.Listen.Host = "127.0.0.1"
		cfg.Listen.Port = 0
		cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

		base, token, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir, Secrets: newStubSecrets()})
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
		placeholder := runPlaceholderRe.Find(upstreamBody)
		if placeholder == nil {
			t.Fatalf("upstream body has no placeholder: %q", upstreamBody)
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
			Running    bool     `json:"running"`
			PID        int      `json:"pid"`
			State      string   `json:"state"`
			Addrs      []string `json:"addrs"`
			UptimeMS   int64    `json:"uptime_ms"`
			Requests   uint64   `json:"requests"`
			Redactions uint64   `json:"redactions"`
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

		// audit (text): the audited request is visible as metadata.
		stdout, stderr, code = cliRun(t, "audit")
		if code != ExitOK {
			t.Fatalf("audit code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		if !strings.Contains(stdout, "/v1/messages") {
			t.Fatalf("audit stdout = %q, want the audited path", stdout)
		}
		if strings.Contains(stdout, secret) || strings.Contains(stdout, string(placeholder)) {
			t.Fatalf("audit text leaked request content: %q", stdout)
		}

		// audit --json: non-vacuous (the request row exists) and metadata-only.
		// The per-request row is committed after the response handler returns,
		// so wait for that append boundary instead of racing it.
		deadline := time.Now().Add(5 * time.Second)
		var (
			records []audit.Record
			raw     string
		)
		for {
			raw, stderr, code = cliRun(t, "audit", "--json")
			if code != ExitOK {
				t.Fatalf("audit --json code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
			}
			if err := json.Unmarshal([]byte(raw), &records); err != nil {
				t.Fatalf("audit --json did not parse: %v (stdout=%q)", err, raw)
			}
			if findAuditPath(records, "/v1/messages") != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("audited request row never appeared: %q", raw)
			}
			time.Sleep(10 * time.Millisecond)
		}
		row := findAuditPath(records, "/v1/messages")
		if row.Redactions < 1 {
			t.Fatalf("audited row = %+v, want at least one redaction (non-vacuous)", *row)
		}
		if bytes.Contains([]byte(raw), []byte(secret)) {
			t.Fatalf("audit --json contains the raw secret bytes")
		}
		if bytes.Contains([]byte(raw), placeholder) {
			t.Fatalf("audit --json contains the placeholder bytes")
		}
	})

	t.Run("status_fake_snapshot_text_and_json", func(t *testing.T) {
		stub := &controlStub{
			token:  statusToken,
			code:   http.StatusOK,
			status: `{"state":"running","addrs":["127.0.0.1:8787","[::1]:8787"],"uptime_ms":83000,"requests":7,"redactions":3}`,
		}
		port := newControlStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, RunState{PID: 4242, Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, statusToken)

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
			Running    bool     `json:"running"`
			PID        int      `json:"pid"`
			State      string   `json:"state"`
			Addrs      []string `json:"addrs"`
			UptimeMS   int64    `json:"uptime_ms"`
			Requests   uint64   `json:"requests"`
			Redactions uint64   `json:"redactions"`
		}
		if err := json.Unmarshal([]byte(stdout), &view); err != nil {
			t.Fatalf("status --json did not parse: %v (stdout=%q)", err, stdout)
		}
		if !view.Running || view.PID != 4242 || view.State != "running" ||
			view.UptimeMS != 83000 || view.Requests != 7 || view.Redactions != 3 {
			t.Fatalf("status --json = %+v, want the stubbed snapshot", view)
		}
		if len(view.Addrs) != 2 || view.Addrs[0] != "127.0.0.1:8787" || view.Addrs[1] != "[::1]:8787" {
			t.Fatalf("status --json addrs = %v, want the stubbed addresses", view.Addrs)
		}
	})

	t.Run("audit_fake_rows_text_and_json", func(t *testing.T) {
		stub := &controlStub{
			token: auditToken,
			code:  http.StatusOK,
			audit: `[
				{"id":1,"ts":1789000000000,"provider":"anthropic","path":"/v1/messages","method":"POST","status":200,"req_bytes":11,"resp_bytes":22,"redactions":1,"detectors":["sk-prefix","email"]},
				{"id":2,"ts":1789000001000,"provider":"openai","path":"/v1/chat/completions","method":"POST","status":200,"req_bytes":33,"resp_bytes":44,"redactions":0}
			]`,
		}
		port := newControlStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, RunState{PID: 7, Port: port}, auditToken)

		stdout, stderr, code := cliRun(t, "audit")
		if code != ExitOK {
			t.Fatalf("audit code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(lines) != 3 {
			t.Fatalf("audit stdout has %d lines, want a header plus 2 rows: %q", len(lines), stdout)
		}
		header := strings.Fields(lines[0])
		if len(header) != 9 {
			t.Fatalf("audit header = %v, want 9 columns", header)
		}
		row := strings.Fields(lines[1])
		if len(row) != 9 {
			t.Fatalf("audit row = %v, want 9 columns", row)
		}
		wantTime := time.UnixMilli(1789000000000).UTC().Format(time.RFC3339)
		for i, want := range []string{wantTime, "anthropic", "POST", "/v1/messages", "200", "11", "22", "1", "sk-prefix,email"} {
			if row[i] != want {
				t.Fatalf("audit row column %d = %q, want %q (row=%v)", i, row[i], want, row)
			}
		}
		if !stub.sawAuth("Bearer " + auditToken) {
			t.Fatalf("audit did not send the bearer token")
		}

		stdout, _, code = cliRun(t, "audit", "--json")
		if code != ExitOK {
			t.Fatalf("audit --json code = %d, want %d", code, ExitOK)
		}
		var records []audit.Record
		if err := json.Unmarshal([]byte(stdout), &records); err != nil {
			t.Fatalf("audit --json did not parse: %v (stdout=%q)", err, stdout)
		}
		if len(records) != 2 || records[0].Path != "/v1/messages" || records[1].Path != "/v1/chat/completions" {
			t.Fatalf("audit --json = %+v, want the two stubbed rows", records)
		}
		if len(records[0].Detectors) != 2 || records[0].Detectors[0] != "sk-prefix" {
			t.Fatalf("audit --json detectors = %v, want [sk-prefix email]", records[0].Detectors)
		}
		if records[0].ReqBytes != 11 || records[0].RespBytes != 22 || records[0].Redactions != 1 {
			t.Fatalf("audit --json row = %+v, want the stubbed metadata", records[0])
		}
	})

	t.Run("audit_empty_and_limit_parameter", func(t *testing.T) {
		stub := &controlStub{token: auditToken, code: http.StatusOK, audit: `[]`}
		port := newControlStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, RunState{PID: 7, Port: port}, auditToken)

		stdout, stderr, code := cliRun(t, "audit")
		if code != ExitOK || strings.TrimSpace(stdout) != "tokenhush: no audit rows" {
			t.Fatalf("empty audit = (%q, code %d, stderr %q), want the no-rows line", stdout, code, stderr)
		}
		if got := stub.lastLimit(); got != strconv.Itoa(proxy.MaxControlAuditLimit) {
			t.Fatalf("audit page limit = %q, want the API cap %d", got, proxy.MaxControlAuditLimit)
		}

		stdout, _, code = cliRun(t, "audit", "--json")
		if code != ExitOK {
			t.Fatalf("empty audit --json code = %d, want %d", code, ExitOK)
		}
		var records []audit.Record
		if err := json.Unmarshal([]byte(stdout), &records); err != nil {
			t.Fatalf("empty audit --json did not parse: %v (stdout=%q)", err, stdout)
		}
		if len(records) != 0 {
			t.Fatalf("empty audit --json = %+v, want an empty array", records)
		}
	})

	t.Run("audit_limit_keeps_the_newest_rows", func(t *testing.T) {
		const total = 30
		rows := make([]audit.Record, total)
		for i := range rows {
			rows[i] = audit.Record{
				ID:       int64(i + 1),
				TS:       int64(i+1) * 1000,
				Provider: "anthropic",
				Method:   http.MethodPost,
				Path:     fmt.Sprintf("/row/%02d", i+1),
			}
		}
		body, err := json.Marshal(rows)
		if err != nil {
			t.Fatalf("marshal stub rows: %v", err)
		}
		stub := &controlStub{token: auditToken, code: http.StatusOK, audit: string(body)}
		port := newControlStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, RunState{PID: 7, Port: port}, auditToken)

		paths := func(stdout string) []string {
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			out := make([]string, 0, len(lines)-1)
			for _, line := range lines[1:] {
				out = append(out, strings.Fields(line)[3])
			}
			return out
		}

		stdout, stderr, code := cliRun(t, "audit")
		if code != ExitOK {
			t.Fatalf("audit code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		got := paths(stdout)
		if len(got) != defaultAuditLimit || got[0] != "/row/11" || got[len(got)-1] != "/row/30" {
			t.Fatalf("default audit window = %v, want the newest %d rows /row/11../row/30", got, defaultAuditLimit)
		}

		stdout, _, code = cliRun(t, "audit", "--limit", "5")
		if code != ExitOK {
			t.Fatalf("audit --limit 5 code = %d, want %d", code, ExitOK)
		}
		got = paths(stdout)
		if len(got) != 5 || got[0] != "/row/26" || got[4] != "/row/30" {
			t.Fatalf("audit --limit 5 window = %v, want the newest 5 rows /row/26../row/30", got)
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

		stdout, _, code = cliRun(t, "audit")
		if code != ExitFailure || !strings.Contains(stdout, "gateway not running") {
			t.Fatalf("audit without a session = (%q, code %d), want the not-running line", stdout, code)
		}
		stdout, _, code = cliRun(t, "audit", "--json")
		if code != ExitFailure {
			t.Fatalf("audit --json code = %d, want %d", code, ExitFailure)
		}
		if err := json.Unmarshal([]byte(stdout), &view); err != nil {
			t.Fatalf("audit --json did not parse: %v (stdout=%q)", err, stdout)
		}
		if view.Running {
			t.Fatalf("audit --json = %q, want running=false", stdout)
		}
	})

	t.Run("status_not_running_when_session_is_stale", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, RunState{PID: 999999, Port: freeLoopbackPort(t)}, statusToken)

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
		if err := writeRunState(home, RunState{PID: 1, Port: freeLoopbackPort(t)}); err != nil {
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
		if err := os.WriteFile(filepath.Join(home, RunStateFileName), []byte("{not-json\n"), 0o600); err != nil {
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
		seedControlSession(t, home, RunState{PID: 1, Port: port}, statusToken)

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
		seedControlSession(t, home, RunState{PID: 1, Port: port}, statusToken)

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
		seedControlSession(t, home, RunState{PID: 1, Port: port}, "the-wrong-token")

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

	t.Run("audit_rejects_out_of_range_limit", func(t *testing.T) {
		for _, value := range []string{"0", "-1", "1001", "abc"} {
			_, stderr, code := cliRun(t, "audit", "--limit", value)
			if code != ExitUsage {
				t.Fatalf("audit --limit %s code = %d, want %d (stderr=%q)", value, code, ExitUsage, stderr)
			}
			if !strings.Contains(stderr, "limit") {
				t.Fatalf("audit --limit %s stderr = %q, want a limit message", value, stderr)
			}
		}
	})

	t.Run("audit_window_pages_past_the_api_page_cap", func(t *testing.T) {
		const total = 2500
		rows := make([]audit.Record, total)
		for i := range rows {
			rows[i] = audit.Record{
				ID:     int64(i + 1),
				TS:     int64(i+1) * 1000,
				Method: http.MethodGet,
				Path:   "/v1/messages",
			}
		}
		fetch := func(_ context.Context, q url.Values) ([]audit.Record, error) {
			since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
			limit, _ := strconv.Atoi(q.Get("limit"))
			out := make([]audit.Record, 0, limit)
			for _, rec := range rows {
				if rec.TS < since {
					continue
				}
				out = append(out, rec)
				if len(out) == limit {
					break
				}
			}
			return out, nil
		}

		got, err := recentAudit(context.Background(), fetch, 10)
		if err != nil {
			t.Fatalf("recentAudit: %v", err)
		}
		if len(got) != 10 {
			t.Fatalf("recentAudit returned %d rows, want 10", len(got))
		}
		if got[0].ID != total-9 || got[len(got)-1].ID != total {
			t.Fatalf("recentAudit window = %d..%d, want %d..%d", got[0].ID, got[len(got)-1].ID, total-9, total)
		}
		for i := 1; i < len(got); i++ {
			if got[i].ID <= got[i-1].ID {
				t.Fatalf("recentAudit window is not ascending: %d then %d", got[i-1].ID, got[i].ID)
			}
		}
	})

	t.Run("audit_fetcher_error_is_reported", func(t *testing.T) {
		boom := errors.New("boom")
		fetch := func(context.Context, url.Values) ([]audit.Record, error) { return nil, boom }
		_, err := recentAudit(context.Background(), fetch, 10)
		if !errors.Is(err, boom) {
			t.Fatalf("recentAudit error = %v, want the fetcher error", err)
		}
	})
}
