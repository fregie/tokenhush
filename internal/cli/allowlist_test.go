package cli

// Tests for `tokenhush allowlist <list|add|remove>`: the thin CLI client of
// the W5.3 control-plane routes. The control plane is the only writer, so the
// tests pin (a) the exact wire shape the CLI sends to a stub, (b) the
// daemon-down failure contract (ExitFailure + actionable hint + zero disk
// writes) and (c) a real-daemon end-to-end round trip where the CLI mutation
// changes live redaction behavior and the daemon persists the change.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/gateway"
)

// allowlistWireRequest is one request the stub observed.
type allowlistWireRequest struct {
	method string
	path   string
	auth   string
	ctype  string
	body   []byte
}

// allowlistStub is a minimal control-plane double for the /allowlist routes: it
// enforces the bearer token, records every request and answers a canned body
// per route. It deliberately skips the production guards, so a CLI unit test
// can pin method, path, headers and body without a full daemon.
type allowlistStub struct {
	token     string
	getStatus int
	getBody   string
	mutStatus int
	mutBody   string

	mu       sync.Mutex
	requests []allowlistWireRequest
}

// ServeHTTP implements the stub contract: 401 without the exact bearer token,
// canned answers for GET/POST/DELETE /allowlist, 404 elsewhere.
func (s *allowlistStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, allowlistWireRequest{
		method: r.Method,
		path:   r.URL.Path,
		auth:   r.Header.Get("Authorization"),
		ctype:  r.Header.Get("Content-Type"),
		body:   append([]byte(nil), body...),
	})
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	if r.URL.Path != "/allowlist" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"not found"}`)
		return
	}
	switch r.Method {
	case http.MethodGet:
		code := s.getStatus
		if code == 0 {
			code = http.StatusOK
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, s.getBody)
	case http.MethodPost, http.MethodDelete:
		code := s.mutStatus
		if code == 0 {
			code = http.StatusOK
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, s.mutBody)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// lastRequest returns the most recent request the stub saw.
func (s *allowlistStub) lastRequest(t *testing.T) allowlistWireRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		t.Fatal("the CLI sent no control request")
	}
	return s.requests[len(s.requests)-1]
}

// newAllowlistStub serves the stub on an ephemeral loopback port and returns
// the port to seed into run.json.
func newAllowlistStub(t *testing.T, s *allowlistStub) int {
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

// seedAllowlistStubHome points a fresh TOKENHUSH_HOME at a live stub, so cliRun
// discovers it through run.json exactly like a real daemon.
func seedAllowlistStubHome(t *testing.T, stub *allowlistStub, token string) string {
	t.Helper()
	port := newAllowlistStub(t, stub)
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	seedControlSession(t, home, gateway.RunState{PID: 1, Port: port}, token)
	return home
}

// hasLine reports whether s contains line as a complete newline-terminated
// line.
func hasLine(s, line string) bool {
	for _, got := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if got == line {
			return true
		}
	}
	return false
}

// dirFingerprint records every file below dir as size|mtime|sha256, so a test
// can assert a command changed nothing on disk.
func dirFingerprint(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[rel] = fmt.Sprintf("%d|%s|%s", info.Size(), info.ModTime().UTC(), hex.EncodeToString(sum[:]))
		return nil
	})
	if err != nil {
		t.Fatalf("fingerprint %s: %v", dir, err)
	}
	return out
}

// TestAllowlistCommandUsage pins the usage contract of the command group: every
// malformed invocation is a usage error (exit 2), writes a usage line to stderr
// and never touches the control plane.
func TestAllowlistCommandUsage(t *testing.T) {
	t.Setenv("TOKENHUSH_HOME", t.TempDir())

	tests := []struct {
		name       string
		args       []string
		wantStderr []string
	}{
		{
			name:       "no_subcommand",
			args:       []string{"allowlist"},
			wantStderr: []string{"Usage of allowlist:", "list", "add", "remove"},
		},
		{
			name:       "unknown_subcommand",
			args:       []string{"allowlist", "bogus"},
			wantStderr: []string{`tokenhush: allowlist: unknown subcommand "bogus"`, "Usage of allowlist:"},
		},
		{
			name:       "add_without_entry",
			args:       []string{"allowlist", "add"},
			wantStderr: []string{"tokenhush: allowlist:", "<entry>"},
		},
		{
			name:       "remove_without_entry",
			args:       []string{"allowlist", "remove"},
			wantStderr: []string{"tokenhush: allowlist:", "<entry>"},
		},
		{
			name:       "add_with_two_entries",
			args:       []string{"allowlist", "add", "one", "two"},
			wantStderr: []string{"tokenhush: allowlist:", `"two"`},
		},
		{
			name:       "list_with_extra_argument",
			args:       []string{"allowlist", "list", "extra"},
			wantStderr: []string{"tokenhush: allowlist:", `"extra"`},
		},
		{
			name:       "list_rejects_flags",
			args:       []string{"allowlist", "list", "--json"},
			wantStderr: []string{"tokenhush: allowlist:", `"--json"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := cliRun(t, tt.args...)
			if code != ExitUsage {
				t.Fatalf("Run(%q) = %d, want %d (stderr=%q)", tt.args, code, ExitUsage, stderr)
			}
			if stdout != "" {
				t.Errorf("Run(%q) stdout = %q, want empty on a usage error", tt.args, stdout)
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr, want) {
					t.Errorf("Run(%q) stderr = %q, want it to contain %q", tt.args, stderr, want)
				}
			}
		})
	}

	t.Run("group_help_exits_zero", func(t *testing.T) {
		stdout, stderr, code := cliRun(t, "allowlist", "--help")
		if code != ExitOK {
			t.Fatalf("allowlist --help = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		if !strings.Contains(stderr, "Usage of allowlist:") {
			t.Errorf("allowlist --help stderr = %q, want the usage header", stderr)
		}
		if stdout != "" {
			t.Errorf("allowlist --help stdout = %q, want empty", stdout)
		}
	})
}

// TestAllowlistControlPlaneRequests pins the CLI's control-plane client: the
// exact method, path, bearer token, content type and JSON body of every
// subcommand, the deterministic list rendering, and the verbatim surfacing of
// the API's error strings.
func TestAllowlistControlPlaneRequests(t *testing.T) {
	const token = "tok-allowlist-7d1f"

	t.Run("list_prints_entries_one_per_line", func(t *testing.T) {
		stub := &allowlistStub{token: token, getBody: `["alpha","runtime.entry"]`}
		seedAllowlistStubHome(t, stub, token)

		stdout, stderr, code := cliRun(t, "allowlist", "list")
		if code != ExitOK {
			t.Fatalf("allowlist list = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		if stdout != "alpha\nruntime.entry\n" {
			t.Errorf("allowlist list stdout = %q, want the entries one per line", stdout)
		}
		if stderr != "" {
			t.Errorf("allowlist list stderr = %q, want empty", stderr)
		}
		req := stub.lastRequest(t)
		if req.method != http.MethodGet || req.path != "/allowlist" {
			t.Errorf("list sent %s %s, want GET /allowlist", req.method, req.path)
		}
		if req.auth != "Bearer "+token {
			t.Errorf("list Authorization = %q, want the bearer token", req.auth)
		}
	})

	t.Run("list_empty_prints_nothing", func(t *testing.T) {
		stub := &allowlistStub{token: token, getBody: `[]`}
		seedAllowlistStubHome(t, stub, token)

		stdout, stderr, code := cliRun(t, "allowlist", "list")
		if code != ExitOK {
			t.Fatalf("allowlist list = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		if stdout != "" {
			t.Errorf("allowlist list stdout = %q, want zero lines for an empty store", stdout)
		}
		if stderr != "" {
			t.Errorf("allowlist list stderr = %q, want empty", stderr)
		}
	})

	t.Run("add_posts_the_entry", func(t *testing.T) {
		stub := &allowlistStub{token: token, mutBody: `["keep.this"]`}
		seedAllowlistStubHome(t, stub, token)

		stdout, stderr, code := cliRun(t, "allowlist", "add", "keep.this")
		if code != ExitOK {
			t.Fatalf("allowlist add = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		if !strings.Contains(stdout, "allowlist: added") || !strings.Contains(stdout, "keep.this") {
			t.Errorf("allowlist add stdout = %q, want the added confirmation naming the entry", stdout)
		}
		if stderr != "" {
			t.Errorf("allowlist add stderr = %q, want empty", stderr)
		}
		req := stub.lastRequest(t)
		if req.method != http.MethodPost || req.path != "/allowlist" {
			t.Errorf("add sent %s %s, want POST /allowlist", req.method, req.path)
		}
		if req.auth != "Bearer "+token {
			t.Errorf("add Authorization = %q, want the bearer token", req.auth)
		}
		if req.ctype != "application/json" {
			t.Errorf("add Content-Type = %q, want application/json", req.ctype)
		}
		if want := `{"entry":"keep.this"}`; string(req.body) != want {
			t.Errorf("add body = %q, want %q", req.body, want)
		}
	})

	t.Run("remove_deletes_the_entry", func(t *testing.T) {
		stub := &allowlistStub{token: token, mutBody: `[]`}
		seedAllowlistStubHome(t, stub, token)

		stdout, stderr, code := cliRun(t, "allowlist", "remove", "keep.this")
		if code != ExitOK {
			t.Fatalf("allowlist remove = %d, want %d (stderr=%q)", code, ExitOK, stderr)
		}
		if !strings.Contains(stdout, "allowlist: removed") || !strings.Contains(stdout, "keep.this") {
			t.Errorf("allowlist remove stdout = %q, want the removed confirmation naming the entry", stdout)
		}
		req := stub.lastRequest(t)
		if req.method != http.MethodDelete || req.path != "/allowlist" {
			t.Errorf("remove sent %s %s, want DELETE /allowlist", req.method, req.path)
		}
		if req.ctype != "application/json" {
			t.Errorf("remove Content-Type = %q, want application/json", req.ctype)
		}
		if want := `{"entry":"keep.this"}`; string(req.body) != want {
			t.Errorf("remove body = %q, want %q", req.body, want)
		}
	})

	t.Run("store_errors_are_surfaced_verbatim", func(t *testing.T) {
		tests := []struct {
			name string
			stub *allowlistStub
			args []string
			want []string
		}{
			{
				name: "duplicate_add",
				stub: &allowlistStub{token: token, mutStatus: http.StatusBadRequest, mutBody: `{"error":"allowlist: entry already present: \"x\""}`},
				args: []string{"allowlist", "add", "x"},
				want: []string{"HTTP 400", "entry already present"},
			},
			{
				name: "missing_remove",
				stub: &allowlistStub{token: token, mutStatus: http.StatusNotFound, mutBody: `{"error":"allowlist: entry not present"}`},
				args: []string{"allowlist", "remove", "x"},
				want: []string{"HTTP 404", "entry not present"},
			},
			{
				name: "unconfigured_list",
				stub: &allowlistStub{token: token, getStatus: http.StatusServiceUnavailable, getBody: `{"error":"allowlist is not configured"}`},
				args: []string{"allowlist", "list"},
				want: []string{"HTTP 503", "allowlist is not configured"},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				seedAllowlistStubHome(t, tt.stub, token)
				stdout, stderr, code := cliRun(t, tt.args...)
				if code != ExitFailure {
					t.Fatalf("Run(%q) = %d, want %d (stderr=%q)", tt.args, code, ExitFailure, stderr)
				}
				if stdout != "" {
					t.Errorf("Run(%q) stdout = %q, want empty on failure", tt.args, stdout)
				}
				if !strings.Contains(stderr, "tokenhush: allowlist:") {
					t.Errorf("Run(%q) stderr = %q, want the tokenhush: allowlist: prefix", tt.args, stderr)
				}
				for _, want := range tt.want {
					if !strings.Contains(stderr, want) {
						t.Errorf("Run(%q) stderr = %q, want it to contain %q", tt.args, stderr, want)
					}
				}
			})
		}
	})

	t.Run("wrong_token_is_a_failure", func(t *testing.T) {
		stub := &allowlistStub{token: "the-real-token"}
		port := newAllowlistStub(t, stub)
		home := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", home)
		seedControlSession(t, home, gateway.RunState{PID: 1, Port: port}, "the-wrong-token")

		_, stderr, code := cliRun(t, "allowlist", "list")
		if code != ExitFailure {
			t.Fatalf("allowlist list with a wrong token = %d, want %d", code, ExitFailure)
		}
		if !strings.Contains(strings.ToLower(stderr), "rejected") {
			t.Errorf("stderr = %q, want a rejected-token message", stderr)
		}
		for _, leak := range []string{"the-wrong-token", "the-real-token"} {
			if strings.Contains(stderr, leak) {
				t.Errorf("stderr leaked a token: %q", stderr)
			}
		}
	})

	t.Run("malformed_list_response_is_a_failure", func(t *testing.T) {
		stub := &allowlistStub{token: token, getBody: "{not-json"}
		seedAllowlistStubHome(t, stub, token)

		_, stderr, code := cliRun(t, "allowlist", "list")
		if code != ExitFailure {
			t.Fatalf("allowlist list on a malformed body = %d, want %d", code, ExitFailure)
		}
		if !strings.Contains(stderr, "tokenhush: allowlist:") || !strings.Contains(strings.ToLower(stderr), "malformed") {
			t.Errorf("stderr = %q, want a prefixed malformed-response message", stderr)
		}
	})
}

// TestAllowlistDaemonDownFailsWithoutWriting is the single-writer contract:
// with no live gateway (no session at all, or a stale run.json pointing at a
// dead port) every subcommand fails with ExitFailure, an actionable
// `tokenhush run` hint and the `tokenhush: allowlist:` stderr prefix — and the
// data directory is byte-for-byte and mtime-for-mtime unchanged, in particular
// <DataDir>/allowlist.json is never created.
func TestAllowlistDaemonDownFailsWithoutWriting(t *testing.T) {
	seeds := []struct {
		name string
		seed func(t *testing.T, home string)
	}{
		{name: "no_session", seed: func(*testing.T, string) {}},
		{name: "unreachable_session", seed: func(t *testing.T, home string) {
			seedControlSession(t, home, gateway.RunState{PID: 999999, Port: freeLoopbackPort(t)}, "tok-stale")
		}},
	}
	invocations := []struct {
		name string
		args []string
	}{
		{name: "add", args: []string{"allowlist", "add", "sk-proj-allow-me"}},
		{name: "remove", args: []string{"allowlist", "remove", "sk-proj-allow-me"}},
		{name: "list", args: []string{"allowlist", "list"}},
	}

	for _, seedCase := range seeds {
		for _, inv := range invocations {
			t.Run(seedCase.name+"_"+inv.name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("TOKENHUSH_HOME", home)
				seedCase.seed(t, home)
				before := dirFingerprint(t, home)

				stdout, stderr, code := cliRun(t, inv.args...)
				if code != ExitFailure {
					t.Fatalf("Run(%q) = %d, want %d (stderr=%q)", inv.args, code, ExitFailure, stderr)
				}
				if stdout != "" {
					t.Errorf("Run(%q) stdout = %q, want empty", inv.args, stdout)
				}
				if !strings.Contains(stderr, "tokenhush: allowlist:") {
					t.Errorf("Run(%q) stderr = %q, want the tokenhush: allowlist: prefix", inv.args, stderr)
				}
				if !strings.Contains(stderr, "tokenhush run") {
					t.Errorf("Run(%q) stderr = %q, want an actionable `tokenhush run` hint", inv.args, stderr)
				}
				if _, err := os.Stat(filepath.Join(home, allowlist.FileName)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("Run(%q) touched <DataDir>/%s: stat err = %v", inv.args, allowlist.FileName, err)
				}
				after := dirFingerprint(t, home)
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("Run(%q) changed the data directory:\nbefore = %v\nafter  = %v", inv.args, before, after)
				}
			})
		}
	}
}

// TestAllowlistCLIEndToEnd drives the real CLI against a real daemon (the
// W6.4 harness): the whole C7 round trip must hold over the actual control
// plane and the actual redaction pipeline.
//
//  1. a request carrying a synthetic secret reaches the fake upstream as a
//     placeholder (redaction is on);
//  2. `tokenhush allowlist add <secret>` succeeds;
//  3. `tokenhush allowlist list` shows the entry, and the daemon has persisted
//     it to <DataDir>/allowlist.json (the CLI itself never writes the file);
//  4. the same request now reaches the upstream as the plaintext (C7);
//  5. `tokenhush allowlist remove <secret>` succeeds and redaction is restored.
func TestAllowlistCLIEndToEnd(t *testing.T) {
	secret := runSecret()

	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	dataDir := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", dataDir)

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

	base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir})
	defer func() { _ = stop() }()

	request := fmt.Sprintf(`{"model":"allowlist-e2e","messages":[{"role":"user","content":%q}]}`, secret)
	storeFile := filepath.Join(dataDir, allowlist.FileName)

	// Step 1: no entry yet — the upstream must receive a placeholder, and the
	// store must not exist (the daemon never writes the file before a change).
	resp := postBody(t, base+"/v1/messages", "application/json", request, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("step 1: data-plane status = %d, want 200", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	redacted := upstream.received()
	if bytes.Contains(redacted, []byte(secret)) {
		t.Fatalf("step 1: upstream received the raw secret: %q", redacted)
	}
	if !runPlaceholderRe.Match(redacted) {
		t.Fatalf("step 1: upstream body carries no placeholder: %q", redacted)
	}
	if _, err := os.Stat(storeFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("step 1: %s exists before any mutation (stat err=%v)", storeFile, err)
	}
	t.Logf("step 1 (no entry): upstream body = %s", redacted)

	// Step 2: add the exact secret through the CLI.
	addOut, addErr, addCode := cliRun(t, "allowlist", "add", secret)
	if addCode != ExitOK {
		t.Fatalf("step 2: allowlist add = %d, want 0 (stderr=%q)", addCode, addErr)
	}
	if !strings.Contains(addOut, "allowlist: added") {
		t.Fatalf("step 2: stdout = %q, want the added confirmation", addOut)
	}
	t.Logf("step 2 (`tokenhush allowlist add <secret>`):\n  stdout=%q\n  stderr=%q\n  exit=%d", addOut, addErr, addCode)

	// Step 2b: the store's own rejections are surfaced verbatim — a duplicate
	// entry is the daemon's HTTP 400 with the store message, and an invalid
	// entry (control character) is the invalid-entry 400.
	_, dupErr, dupCode := cliRun(t, "allowlist", "add", secret)
	if dupCode != ExitFailure {
		t.Fatalf("step 2b: duplicate add = %d, want %d (stderr=%q)", dupCode, ExitFailure, dupErr)
	}
	if !strings.Contains(dupErr, "HTTP 400") || !strings.Contains(dupErr, "already present") {
		t.Fatalf("step 2b: duplicate add stderr = %q, want the store's 400 message verbatim", dupErr)
	}
	t.Logf("step 2b (duplicate add): stderr=%q exit=%d", dupErr, dupCode)
	_, badErr, badCode := cliRun(t, "allowlist", "add", "bad\nentry")
	if badCode != ExitFailure {
		t.Fatalf("step 2c: invalid add = %d, want %d (stderr=%q)", badCode, ExitFailure, badErr)
	}
	if !strings.Contains(badErr, "HTTP 400") || !strings.Contains(badErr, "control characters") {
		t.Fatalf("step 2c: invalid add stderr = %q, want the store's validation message verbatim", badErr)
	}
	t.Logf("step 2c (invalid entry add): stderr=%q exit=%d", badErr, badCode)

	// Step 3: the list shows the entry and the daemon persisted it.
	listOut, listErr, listCode := cliRun(t, "allowlist", "list")
	if listCode != ExitOK {
		t.Fatalf("step 3: allowlist list = %d, want 0 (stderr=%q)", listCode, listErr)
	}
	if !hasLine(listOut, secret) {
		t.Fatalf("step 3: list stdout = %q, want the entry on its own line", listOut)
	}
	t.Logf("step 3 (`tokenhush allowlist list`):\n  stdout=%q\n  stderr=%q\n  exit=%d", listOut, listErr, listCode)
	persisted, err := os.ReadFile(storeFile)
	if err != nil {
		t.Fatalf("step 3: read %s: %v", storeFile, err)
	}
	if !bytes.Contains(persisted, []byte(secret)) {
		t.Fatalf("step 3: persisted store %q does not contain the entry", persisted)
	}
	t.Logf("step 3 persisted by the daemon: %s", persisted)

	// Step 4: the same request now leaves unredacted (C7; W2.3's egress
	// re-check exempts a secret already leaving verbatim).
	resp = postBody(t, base+"/v1/messages", "application/json", request, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("step 4: data-plane status = %d, want 200 (a 403 here would be an unexpected egress block)", resp.StatusCode)
	}
	clientRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("step 4: read client body: %v", err)
	}
	allowed := upstream.received()
	if runPlaceholderRe.Match(allowed) {
		t.Fatalf("step 4: upstream still received a placeholder: %q", allowed)
	}
	if !bytes.Equal(allowed, []byte(request)) {
		t.Fatalf("step 4: upstream bytes differ:\ngot  = %q\nwant = %q", allowed, request)
	}
	if !bytes.Contains(clientRaw, []byte(secret)) {
		t.Fatalf("step 4: client body lost the secret: %q", clientRaw)
	}
	t.Logf("step 4 (allowlisted): upstream body = %s", allowed)
	t.Logf("step 4 (allowlisted): client body = %s", clientRaw)

	// Step 5: removing the entry restores redaction.
	rmOut, rmErr, rmCode := cliRun(t, "allowlist", "remove", secret)
	if rmCode != ExitOK {
		t.Fatalf("step 5: allowlist remove = %d, want 0 (stderr=%q)", rmCode, rmErr)
	}
	if !strings.Contains(rmOut, "allowlist: removed") {
		t.Fatalf("step 5: stdout = %q, want the removed confirmation", rmOut)
	}
	t.Logf("step 5 (`tokenhush allowlist remove <secret>`):\n  stdout=%q\n  stderr=%q\n  exit=%d", rmOut, rmErr, rmCode)

	listOut, listErr, listCode = cliRun(t, "allowlist", "list")
	if listCode != ExitOK {
		t.Fatalf("step 5: allowlist list = %d, want 0 (stderr=%q)", listCode, listErr)
	}
	if strings.TrimSpace(listOut) != "" {
		t.Fatalf("step 5: list stdout = %q, want the empty list after remove", listOut)
	}

	resp = postBody(t, base+"/v1/messages", "application/json", request, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("step 5: data-plane status = %d, want 200", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	restored := upstream.received()
	if bytes.Contains(restored, []byte(secret)) {
		t.Fatalf("step 5: upstream received the raw secret after remove: %q", restored)
	}
	if !runPlaceholderRe.Match(restored) {
		t.Fatalf("step 5: upstream body carries no placeholder after remove: %q", restored)
	}
	t.Logf("step 5 (after remove): upstream body = %s", restored)

	// Step 5b: removing the entry again is the store's HTTP 404, surfaced
	// verbatim.
	_, goneErr, goneCode := cliRun(t, "allowlist", "remove", secret)
	if goneCode != ExitFailure {
		t.Fatalf("step 5b: remove of a missing entry = %d, want %d (stderr=%q)", goneCode, ExitFailure, goneErr)
	}
	if !strings.Contains(goneErr, "HTTP 404") || !strings.Contains(goneErr, "not present") {
		t.Fatalf("step 5b: missing-remove stderr = %q, want the store's 404 message verbatim", goneErr)
	}
	t.Logf("step 5b (remove of a missing entry): stderr=%q exit=%d", goneErr, goneCode)
}
