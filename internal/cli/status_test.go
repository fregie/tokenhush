package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/proxy"
)

// frozenStatusKeys is the exact key set `status --json` may emit. It is the
// frozen ten: no self_protection_interceptions and no egress_blocks exist.
var frozenStatusKeys = []string{
	"state", "addrs", "port", "uptime_ms", "requests", "redactions",
	"content_policy_blocks", "rule_blocks", "walk_skips", "pack_serial",
}

// fakeGateway writes a session into dataDir and serves the proxy-owned
// nine-key payload, requiring the session token.
func fakeGateway(t *testing.T, dataDir string) *httptest.Server {
	t.Helper()
	token, err := proxy.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token.String() {
			http.Error(w, "control token required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"state":"running","addrs":["127.0.0.1:1"],"port":1,"uptime_ms":7,`+
			`"requests":1,"redactions":2,"content_policy_blocks":3,"rule_blocks":4,"walk_skips":5}`)
	}))
	t.Cleanup(server.Close)

	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	state := proxy.NewRunState(port, []string{strings.TrimPrefix(server.URL, "http://")})
	if err := proxy.WriteSession(dataDir, state, token); err != nil {
		t.Fatalf("WriteSession: %v", err)
	}
	return server
}

// TestStatusJSONKeySetEqualsFrozenTen asserts set EQUALITY, not a subset: the
// decoded document must carry exactly the ten frozen keys, with pack_serial
// merged from the rules cache and the counters taken from the proxy payload.
func TestStatusJSONKeySetEqualsFrozenTen(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")
	fakeGateway(t, dataDir)
	if err := os.MkdirAll(filepath.Join(dataDir, "rules"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "rules", "active"), []byte(`{"serial":7}`), 0o600); err != nil {
		t.Fatalf("write active pointer: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := statusCommand([]string{"--json"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("status --json = %d, want %d (stderr %q)", code, exitOK, stderr.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode %q: %v", stdout.String(), err)
	}
	got := make([]string, 0, len(decoded))
	for key := range decoded {
		got = append(got, key)
	}
	sort.Strings(got)
	want := append([]string(nil), frozenStatusKeys...)
	sort.Strings(want)
	if !equalStrings(got, want) {
		t.Fatalf("status --json keys = %v, want exactly %v", got, want)
	}
	if serial := decoded["pack_serial"]; serial != float64(7) {
		t.Errorf("pack_serial = %v, want the rules cache's 7", serial)
	}
	if blocks := decoded["content_policy_blocks"]; blocks != float64(3) {
		t.Errorf("content_policy_blocks = %v, want the proxy payload's 3", blocks)
	}
}

// TestStatusNotRunningExitsOne pins the absent-gateway behaviour: "not
// running" and exit 1.
func TestStatusNotRunningExitsOne(t *testing.T) {
	t.Setenv("TOKENHUSH_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := statusCommand(nil, &stdout, &stderr); code != exitFailure {
		t.Fatalf("status = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stdout.String(), "not running") {
		t.Fatalf("stdout = %q, want it to say not running", stdout.String())
	}
}

// TestStatusSessionWithoutTokenIsNotRunning pins that a stale run.json alone
// is not enough: without the control token there is no gateway to ask.
func TestStatusSessionWithoutTokenIsNotRunning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "run.json"), []byte(`{"pid":1,"port":1,"addrs":["127.0.0.1:1"]}`), 0o600); err != nil {
		t.Fatalf("write run.json: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := statusCommand(nil, &stdout, &stderr); code != exitFailure {
		t.Fatalf("status = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stdout.String(), "not running") {
		t.Fatalf("stdout = %q, want not running", stdout.String())
	}
}

// TestStatusTextOutputCarriesEveryFrozenKey keeps the human-readable form and
// the JSON form in step.
func TestStatusTextOutputCarriesEveryFrozenKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	fakeGateway(t, filepath.Join(home, "data"))
	var stdout, stderr bytes.Buffer
	if code := statusCommand(nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("status = %d, want %d (stderr %q)", code, exitOK, stderr.String())
	}
	for _, key := range frozenStatusKeys {
		if !strings.Contains(stdout.String(), key+": ") {
			t.Errorf("text output %q is missing %s", stdout.String(), key)
		}
	}
}

// TestStatusRejectsExtraArguments pins the usage error.
func TestStatusRejectsExtraArguments(t *testing.T) {
	t.Setenv("TOKENHUSH_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := statusCommand([]string{"extra"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("status extra = %d, want %d", code, exitUsage)
	}
}
