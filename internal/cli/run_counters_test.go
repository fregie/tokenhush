package cli

// run_counters_test.go is the corrective live proof for the frozen status
// surface: the assembler must move `requests` and `redactions` on the real
// serving path, and GET /status must report them. Nothing here calls a counter
// directly -- every observation is an HTTP read of the running gateway.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/supply"
)

// countedStatus is the subset of the frozen status document this test reads.
type countedStatus struct {
	Requests   int64 `json:"requests"`
	Redactions int64 `json:"redactions"`
}

// TestRunCountsLiveRequestsAndRedactions starts the real run on an ephemeral
// port with a loopback upstream stub and proves, end to end, that a live
// GET /status reports the traffic the gateway actually served: one request with
// a redactable secret moves both counters, a secret-free request moves only
// requests, and a locally refused request is still one request with no
// redaction.
func TestRunCountsLiveRequestsAndRedactions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")

	var (
		upstreamMu   sync.Mutex
		upstreamBody []byte
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the upstream body: %v", err)
		}
		upstreamMu.Lock()
		upstreamBody = body
		upstreamMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	stop := make(chan struct{})
	seams := defaultRunSeams()
	seams.recoverRun = func(string) (supply.RecoveryResult, error) { return supply.RecoveryNone, nil }
	seams.loadConfig = func(string) (config.Config, error) {
		cfg := config.Default()
		cfg.Listen.Port = 0
		cfg.Upstreams = []config.Upstream{{Match: "/v1/chat/completions", Target: upstream.URL}}
		return cfg, nil
	}
	seams.notify = func(signals chan<- os.Signal) {
		<-stop
		signals <- syscall.SIGTERM
	}
	done := make(chan int, 1)
	go func() { done <- runWith(nil, io.Discard, seams) }()

	state := waitForSession(t, dataDir)
	token := readControlToken(t, dataDir)
	base := fmt.Sprintf("http://127.0.0.1:%d", state.Port)

	before := readLiveCounters(t, base, token)
	if before.Requests != 0 || before.Redactions != 0 {
		t.Fatalf("fresh gateway counters = %+v, want requests 0 redactions 0", before)
	}

	secret := "sk-" + strings.Repeat("Ab3", 14)
	withSecret := []byte(`{"messages":[{"role":"user","content":"` + secret + `"}]}`)
	postJSON(t, base+"/v1/chat/completions", withSecret)

	afterSecret := readLiveCounters(t, base, token)
	t.Logf("after the secret request: requests=%d redactions=%d", afterSecret.Requests, afterSecret.Redactions)
	if afterSecret.Requests < 1 {
		t.Errorf("requests = %d after one served request, want >= 1", afterSecret.Requests)
	}
	if afterSecret.Redactions < 1 {
		t.Errorf("redactions = %d after one redacted request, want >= 1", afterSecret.Redactions)
	}
	upstreamMu.Lock()
	sent := bytes.Clone(upstreamBody)
	upstreamMu.Unlock()
	if bytes.Contains(sent, []byte(secret)) {
		t.Errorf("the secret reached the upstream: %s", sent)
	}

	noSecret := []byte(`{"messages":[{"role":"user","content":"hello there"}]}`)
	postJSON(t, base+"/v1/chat/completions", noSecret)
	afterPlain := readLiveCounters(t, base, token)
	t.Logf("after the plain request: requests=%d redactions=%d", afterPlain.Requests, afterPlain.Redactions)
	if got, want := afterPlain.Requests, afterSecret.Requests+1; got != want {
		t.Errorf("requests = %d after a secret-free request, want %d", got, want)
	}
	if afterPlain.Redactions != afterSecret.Redactions {
		t.Errorf("redactions moved on a secret-free request: %d -> %d", afterSecret.Redactions, afterPlain.Redactions)
	}

	if status := postJSONStatus(t, base+"/v1/chat/completions", []byte(`{"broken":`)); status != http.StatusBadRequest {
		t.Fatalf("unwalkable declared-JSON request = %d, want 400", status)
	}
	afterRefusal := readLiveCounters(t, base, token)
	t.Logf("after the refused request: requests=%d redactions=%d", afterRefusal.Requests, afterRefusal.Redactions)
	if got, want := afterRefusal.Requests, afterPlain.Requests+1; got != want {
		t.Errorf("a refusal must count as exactly one request: requests = %d, want %d", got, want)
	}
	if afterRefusal.Redactions != afterPlain.Redactions {
		t.Errorf("a refusal moved redactions: %d -> %d", afterPlain.Redactions, afterRefusal.Redactions)
	}

	close(stop)
	if code := <-done; code != exitOK {
		t.Fatalf("runWith = %d, want %d", code, exitOK)
	}
}

// postJSON sends one application/json request and returns its status.
func postJSONStatus(t *testing.T, url string, body []byte) int {
	t.Helper()
	response, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

// postJSON sends one application/json request and requires a 200.
func postJSON(t *testing.T, url string, body []byte) {
	t.Helper()
	if status := postJSONStatus(t, url, body); status != http.StatusOK {
		t.Fatalf("POST %s = %d, want 200", url, status)
	}
}

// readLiveCounters reads the two counters from the running gateway's status
// endpoint with the session token.
func readLiveCounters(t *testing.T, base, token string) countedStatus {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, base+"/status", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /status = %d, want 200", response.StatusCode)
	}
	var status countedStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatalf("decode /status: %v", err)
	}
	return status
}
