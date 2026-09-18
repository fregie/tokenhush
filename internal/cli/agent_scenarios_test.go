// agent_scenarios_test.go is the agent-workload scenario matrix: a table of
// realistic vibe-coding-agent requests driven through the REAL run gateway
// against a loopback echo upstream that records the exact bytes, headers and
// declared length of every request it receives. Every scenario asserts both
// directions of the product contract:
//
//   - protection: a real secret is replaced by a session placeholder in the
//     upstream-received bytes and the original returns in the client-bound
//     bytes;
//   - non-interference: legitimate content is byte-identical upstream, the
//     request is never interrupted (HTTP 200, no content_policy_blocks, no
//     rule_blocks, no walk_skips), the upstream body is valid JSON with an
//     honest Content-Length, and the client round-trip is byte-exact.
//
// One shared gateway and one shared recording upstream serve the whole matrix;
// counters are read live through GET /status per case; the run prints one
// summary line per scenario. Large payloads (the 1.5 MB leaf, the 40 KB base64
// data URL, the runtime rule fixtures) are generated at run time, never checked
// in.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/supply"
)

// The upstream mode header: its sse value answers the one SSE scenario, so one
// recording upstream serves every body-level and streaming scenario.
const (
	agentModeHeader = "X-Agent-Scenario"
	agentModeSSE    = "sse"
)

// agentClientTimeout bounds one scenario POST. It is generous on purpose: the
// 1.5 MB leaf and the ten concurrent requests must complete under the race
// detector's slowdown without widening any per-case semantic bound.
const agentClientTimeout = 120 * time.Second

// recordedRequest is one request the recording upstream received, captured
// verbatim: the body bytes, the request headers and the declared length.
type recordedRequest struct {
	body     []byte
	header   http.Header
	declared int64
}

// scenarioUpstream is the loopback echo upstream of the matrix. Unlike the
// shared e2eUpstream it records EVERY request (not only the last) together with
// the headers and declared Content-Length, so the concurrency and
// Content-Length assertions are made on captured bytes.
type scenarioUpstream struct {
	server *httptest.Server

	mu      sync.Mutex
	records []recordedRequest
}

// newScenarioUpstream starts the recording echo upstream and closes it with the
// test.
func newScenarioUpstream(t *testing.T) *scenarioUpstream {
	t.Helper()
	upstream := &scenarioUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(upstream.serve))
	t.Cleanup(upstream.server.Close)
	return upstream
}

// serve records one request and answers it: the sse mode emits a split
// placeholder stream, every other request is echoed with an explicit
// Content-Length.
func (u *scenarioUpstream) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	u.mu.Lock()
	u.records = append(u.records, recordedRequest{body: bytes.Clone(body), header: r.Header.Clone(), declared: r.ContentLength})
	u.mu.Unlock()
	if r.Header.Get(agentModeHeader) == agentModeSSE {
		u.serveSSE(w, body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

// serveSSE emits an SSE stream in the shape a real model stream uses: every
// data frame is a whole JSON document and the session placeholder rides in one
// of them, so the first-event evaluation walks, no walk skip is counted, and
// the structure survives the client-bound writer.
func (u *scenarioUpstream) serveSSE(w http.ResponseWriter, body []byte) {
	placeholder := e2ePlaceholder.Find(body)
	if placeholder == nil {
		http.Error(w, "the request carried no placeholder", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	for _, frame := range []string{
		"data: " + agentSSEData("the key is ") + "\n\n",
		"data: " + agentSSEData(string(placeholder)) + "\n\n",
		"data: [DONE]\n\n",
	} {
		_, _ = io.WriteString(w, frame)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// agentSSEData wraps one delta fragment in a whole JSON event, so every frame
// a client sees is independently parseable.
func agentSSEData(fragment string) string {
	return `{"choices":[{"delta":{"content":"` + fragment + `"}}]}`
}

// count returns how many requests the upstream has served.
func (u *scenarioUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.records)
}

// lastRequest returns the most recent recorded request, or the zero value when
// the upstream has served none.
func (u *scenarioUpstream) lastRequest() recordedRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.records) == 0 {
		return recordedRequest{}
	}
	return u.records[len(u.records)-1]
}

// since returns the requests recorded from start onward.
func (u *scenarioUpstream) since(start int) []recordedRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	if start < 0 || start > len(u.records) {
		return nil
	}
	return append([]recordedRequest(nil), u.records[start:]...)
}

// agentEnv is one running gateway plus the handles a scenario needs.
type agentEnv struct {
	base     string
	dataDir  string
	token    string
	upstream *scenarioUpstream
}

// newAgentEnv starts the real run server over the recording upstream and
// returns its base URL. It reuses the production run seams and the in-package
// rule-registration seam, so the only difference from the production pipeline
// is the injected test rule set.
func newAgentEnv(t *testing.T, upstream *scenarioUpstream, rules ...filter.Rule) *agentEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")

	stop := make(chan struct{})
	seams := defaultRunSeams()
	seams.recoverRun = func(string) (supply.RecoveryResult, error) { return supply.RecoveryNone, nil }
	seams.loadConfig = func(string) (config.Config, error) {
		cfg := config.Default()
		cfg.Listen.Port = 0
		cfg.Upstreams = []config.Upstream{{Match: e2ePath, Target: upstream.server.URL}}
		return cfg, nil
	}
	seams.build = func(cfg config.Config, dir string, stderr io.Writer, logRedactions bool) (*gateway, error) {
		gw, err := buildGateway(cfg, dir, stderr, logRedactions)
		if err != nil {
			return nil, err
		}
		if err := injectTestRules(gw, cfg, rules); err != nil {
			return nil, err
		}
		return gw, nil
	}
	seams.notify = func(signals chan<- os.Signal) {
		<-stop
		signals <- syscall.SIGTERM
	}
	done := make(chan int, 1)
	go func() { done <- runWith(nil, io.Discard, seams) }()
	t.Cleanup(func() {
		close(stop)
		if code := <-done; code != exitOK {
			t.Errorf("runWith = %d, want %d", code, exitOK)
		}
	})

	state := waitForSession(t, dataDir)
	base := fmt.Sprintf("http://127.0.0.1:%d", state.Port)
	e2eWaitReady(t, base)
	return &agentEnv{base: base, dataDir: dataDir, token: readControlToken(t, dataDir), upstream: upstream}
}

// agentCapture is the client/upstream byte capture of one scenario request.
type agentCapture struct {
	status      int
	client      []byte
	respHeader  http.Header
	sent        []byte
	reqHeader   http.Header
	reqDeclared int64
}

// postRaw sends one request and returns its status, complete client-bound body
// and response headers. It never touches testing.T, so the concurrency
// scenario can call it from goroutines.
func (e *agentEnv) postRaw(body []byte, contentType string, extra map[string]string) (int, []byte, http.Header, error) {
	if contentType == "" {
		contentType = "application/json"
	}
	request, err := http.NewRequest(http.MethodPost, e.base+e2ePath, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	request.Header.Set("Content-Type", contentType)
	for name, value := range extra {
		request.Header.Set(name, value)
	}
	response, err := (&http.Client{Timeout: agentClientTimeout}).Do(request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	got, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	return response.StatusCode, got, response.Header.Clone(), nil
}

// post sends one scenario request and pairs the client-bound bytes with the
// upstream-received bytes.
func (e *agentEnv) post(t *testing.T, body []byte, contentType string, extra map[string]string) agentCapture {
	t.Helper()
	status, client, header, err := e.postRaw(body, contentType, extra)
	if err != nil {
		t.Fatalf("scenario POST %s: %v", e.base+e2ePath, err)
	}
	last := e.upstream.lastRequest()
	return agentCapture{
		status: status, client: client, respHeader: header,
		sent: last.body, reqHeader: last.header, reqDeclared: last.declared,
	}
}

// secretExpec names one secret a scenario sends and the category it must be
// redacted under.
type secretExpec struct {
	value    string
	category string
}

// agentCase is one table entry. A nil run uses the generic protection or
// byte-identity flow; a non-nil run takes over for the streaming and
// concurrency shapes and returns the table verdict itself.
type agentCase struct {
	name           string
	contentType    string
	extraHeaders   map[string]string
	body           func(t *testing.T, env *agentEnv) []byte
	secrets        []secretExpec
	wantRedactions int
	check          func(t *testing.T, env *agentEnv, capture agentCapture, request []byte)
	run            func(t *testing.T, env *agentEnv) string

	// requestCarriesPlaceholder marks the multi-turn case: its request
	// deliberately carries a session placeholder, so the client-bound bytes
	// are the request with the placeholder restored, not the request itself.
	requestCarriesPlaceholder bool
}

// scenarioResult is one printed matrix row.
type scenarioResult struct {
	name    string
	status  string
	verdict string
}

// TestAgentScenarioMatrix drives the whole agent-workload table through the
// real gateway and prints one summary line per scenario.
func TestAgentScenarioMatrix(t *testing.T) {
	upstream := newScenarioUpstream(t)
	quoted := "tok-\"quoted\"-\\slash-" + e2eRandomHex(t, 4)
	vendorToken := "cfat_" + e2eRandomHex(t, 20)
	wireSecret := "wire-" + e2eRandomHex(t, 6) + "@example.com"
	multiTurnSecret := "multi-" + e2eRandomHex(t, 6) + "@example.com"
	concurrentSecret := "concurrent-" + e2eRandomHex(t, 6) + "@example.com"
	sseSecret := "sse-" + e2eRandomHex(t, 6) + "@example.com"

	env := newAgentEnv(t, upstream,
		regexRedactRule{id: "scenario-vendor-token", pattern: regexp.MustCompile(`cfat_[A-Za-z0-9]{40}`), category: "custom"},
		redactRule{id: "scenario-quoted-keyword", trigger: quoted},
	)

	var turnPlaceholder []byte

	cases := []agentCase{
		// A. Protection: must be redacted upstream and restored client-side.
		{
			name:           "A1 go test fixture email",
			body:           func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentGoFixture) },
			secrets:        []secretExpec{{value: "user@example.com", category: "email"}},
			wantRedactions: 1,
		},
		{
			name: "A2 provider keys inside comments",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentKeysInComments) },
			secrets: []secretExpec{
				{value: "AKIAIOSFODNN7EXAMPLE", category: "api_key"},
				{value: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", category: "api_key"},
				{value: "sk-AbCdEfGhIjKlMnOpQrStUvWx", category: "api_key"},
			},
			wantRedactions: 3,
		},
		{
			name: "A3 Luhn-valid card",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return redactJSONBody(t, "Charge the test card "+agentLuhnValidCard+" now.")
			},
			secrets:        []secretExpec{{value: agentLuhnValidCard, category: "credit_card"}},
			wantRedactions: 1,
		},
		{
			name: "A4 multi-line PEM private key",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return redactJSONBody(t, "please use this key:\n"+agentPEM+"\nthanks")
			},
			secrets:        []secretExpec{{value: agentPEM, category: "private_key"}},
			wantRedactions: 1,
		},
		{
			name: "A5 JWT fixture",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return redactJSONBody(t, "Authorization: Bearer "+agentJWT+" end")
			},
			secrets:        []secretExpec{{value: agentJWT, category: "jwt"}},
			wantRedactions: 1,
		},
		{
			name: "A6 vendor regex token",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return redactJSONBody(t, "the vendor token "+vendorToken+" is live")
			},
			secrets:        []secretExpec{{value: vendorToken, category: "custom"}},
			wantRedactions: 1,
		},
		{
			name: "A7 quote and backslash keyword secret",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return redactJSONBody(t, agentQuotedSecretContent(quoted))
			},
			secrets:        []secretExpec{{value: quoted, category: "custom"}},
			wantRedactions: 1,
		},
		{
			name: "A8 JSON-in-JSON leaf",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return agentJSONInJSONBody(t, quoted)
			},
			secrets:        []secretExpec{{value: quoted, category: "custom"}},
			wantRedactions: 1,
		},
		{
			name: "A9 1.5 MB leaf with a trailing email",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return redactJSONBody(t, agentLargeLeaf(t, "user@example.com"))
			},
			secrets:        []secretExpec{{value: "user@example.com", category: "email"}},
			wantRedactions: 1,
		},
		{
			name: "A10 five secrets in one body",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentMultiSecretContent) },
			secrets: []secretExpec{
				{value: "user@example.com", category: "email"},
				{value: "AKIAIOSFODNN7EXAMPLE", category: "api_key"},
				{value: agentLuhnValidCard, category: "credit_card"},
				{value: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", category: "api_key"},
				{value: "sk-AbCdEfGhIjKlMnOpQrStUvWx", category: "api_key"},
			},
			wantRedactions: 5,
		},

		// B. Non-interference: must be byte-identical upstream.
		{
			name: "B11 hex identifiers and uuid",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentHexIdentifiers) },
		},
		{
			name: "B12 Luhn-invalid and all-same cards",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentInvalidCards) },
		},
		{
			name: "B13 bare at and localhost address",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentBareAt) },
		},
		{
			name: "B14 AKIA embedded in a longer word",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentEmbeddedAKIA) },
		},
		{
			name: "B15 too-short sk and short base64",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentShortPrefixTokens) },
		},
		{
			name: "B16 certificate block",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentCertificate) },
		},
		{
			name: "B17 plain URL",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentURL) },
		},
		{
			name: "B18 40 KB base64 data URL",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentDataURL(t)) },
		},
		{
			name: "B19 version and host text",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentVersionHost) },
		},

		// C. Realistic shapes: structure must survive.
		{
			name: "C20 tool-call arguments JSON string",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return agentToolCallBody(t, "sk-AbCdEfGhIjKlMnOpQrStUvWx")
			},
			secrets:        []secretExpec{{value: "sk-AbCdEfGhIjKlMnOpQrStUvWx", category: "api_key"}},
			wantRedactions: 1,
		},
		{
			name: "C21 anthropic tool_result block",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return agentToolResultBody(t, "AKIAIOSFODNN7EXAMPLE")
			},
			secrets:        []secretExpec{{value: "AKIAIOSFODNN7EXAMPLE", category: "api_key"}},
			wantRedactions: 1,
		},
		{
			name:           "C22 unified diff patch",
			body:           func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentDiff) },
			secrets:        []secretExpec{{value: "sk-AbCdEfGhIjKlMnOpQrStUvWx", category: "api_key"}},
			wantRedactions: 1,
		},
		{
			name:           "C23 shell export command",
			body:           func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentShellCommand) },
			secrets:        []secretExpec{{value: "sk-AbCdEfGhIjKlMnOpQrStUvWx", category: "api_key"}},
			wantRedactions: 1,
		},
		{
			name:           "C24 env dump",
			body:           func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentEnvDump) },
			secrets:        []secretExpec{{value: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", category: "api_key"}},
			wantRedactions: 1,
		},
		{
			name: "C25 markdown credentials",
			body: func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentMarkdown) },
			secrets: []secretExpec{
				{value: "sk-AbCdEfGhIjKlMnOpQrStUvWx", category: "api_key"},
				{value: "dev@example.com", category: "email"},
			},
			wantRedactions: 2,
		},
		{
			name:           "C26 CJK content with a secret",
			body:           func(t *testing.T, _ *agentEnv) []byte { return redactJSONBody(t, agentUnicodeContent) },
			secrets:        []secretExpec{{value: "sk-AbCdEfGhIjKlMnOpQrStUvWx", category: "api_key"}},
			wantRedactions: 1,
			check: func(t *testing.T, _ *agentEnv, capture agentCapture, _ []byte) {
				if !bytes.Contains(capture.client, []byte(agentUnicodeMarker)) {
					t.Errorf("C26: the CJK bytes did not survive the round trip: %s", agentWindow(capture.client))
				}
			},
		},
		{
			name:        "C27a text/plain JSON-shaped body",
			contentType: "text/plain",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return []byte(`{"messages":[{"role":"user","content":"mail ` + wireSecret + `"}]}`)
			},
			secrets:        []secretExpec{{value: wireSecret, category: "email"}},
			wantRedactions: 1,
		},
		{
			name:        "C27b application/json-seq JSON-shaped body",
			contentType: "application/json-seq",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return []byte(`{"messages":[{"role":"user","content":"mail ` + wireSecret + `"}]}`)
			},
			secrets:        []secretExpec{{value: wireSecret, category: "email"}},
			wantRedactions: 1,
		},
		{
			name: "C28a known placeholder on the next turn",
			body: func(t *testing.T, env *agentEnv) []byte {
				first := env.post(t, redactJSONBody(t, "mail "+multiTurnSecret), "", nil)
				if first.status != http.StatusOK {
					t.Fatalf("C28a mint request = %d, want 200 (body %s)", first.status, agentWindow(first.client))
				}
				turnPlaceholder = e2ePlaceholder.Find(first.sent)
				if turnPlaceholder == nil {
					t.Fatalf("C28a mint request carried no placeholder: %s", agentWindow(first.sent))
				}
				return redactJSONBody(t, "note "+string(turnPlaceholder)+" here")
			},
			secrets:                   []secretExpec{{value: multiTurnSecret, category: "email"}},
			wantRedactions:            0,
			requestCarriesPlaceholder: true,
			check: func(t *testing.T, _ *agentEnv, capture agentCapture, request []byte) {
				if !bytes.Contains(capture.sent, turnPlaceholder) {
					t.Errorf("C28a: the known placeholder was not forwarded intact: %s", agentWindow(capture.sent))
				}
				if bytes.Contains(capture.sent, []byte(multiTurnSecret)) {
					t.Errorf("C28a: the outbound path backfilled the placeholder into its secret: %s", agentWindow(capture.sent))
				}
				want := bytes.ReplaceAll(request, turnPlaceholder, []byte(multiTurnSecret))
				if !bytes.Equal(capture.client, want) {
					t.Errorf("C28a: client bytes = %s, want the placeholder restored to the original secret: %s",
						agentWindow(capture.client), agentWindowDiff(want, capture.client))
				}
			},
		},
		{
			name: "C28b foreign placeholder unchanged",
			body: func(t *testing.T, _ *agentEnv) []byte {
				return redactJSONBody(t, "foreign __PII_email_deadbeefcafe__ here")
			},
			check: func(t *testing.T, _ *agentEnv, capture agentCapture, _ []byte) {
				if !bytes.Contains(capture.client, []byte("__PII_email_deadbeefcafe__")) {
					t.Errorf("C28b: the foreign placeholder did not return unchanged: %s", agentWindow(capture.client))
				}
				if bytes.Contains(capture.client, []byte(multiTurnSecret)) {
					t.Errorf("C28b: the session fabricated its secret into a foreign placeholder: %s", agentWindow(capture.client))
				}
			},
		},
		{
			name: "C29 ten concurrent requests",
			run: func(t *testing.T, env *agentEnv) string {
				const workers = 10
				body := redactJSONBody(t, "mail "+concurrentSecret)
				before := readLiveCounters(t, env.base, env.token)
				beforeCount := env.upstream.count()
				type outcome struct {
					status int
					client []byte
					err    error
				}
				outcomes := make(chan outcome, workers)
				for i := 0; i < workers; i++ {
					go func() {
						status, client, _, err := env.postRaw(body, "", nil)
						outcomes <- outcome{status: status, client: client, err: err}
					}()
				}
				for i := 0; i < workers; i++ {
					result := <-outcomes
					switch {
					case result.err != nil:
						t.Errorf("C29 request %d: %v", i, result.err)
					case result.status != http.StatusOK:
						t.Errorf("C29 request %d: POST = %d, want 200 (body %s)", i, result.status, agentWindow(result.client))
					case !bytes.Contains(result.client, []byte(concurrentSecret)):
						t.Errorf("C29 request %d: the secret did not return to the client: %s", i, agentWindow(result.client))
					case bytes.Contains(result.client, []byte("__PII_")):
						t.Errorf("C29 request %d: a placeholder reached the client: %s", i, agentWindow(result.client))
					}
				}
				recorded := env.upstream.since(beforeCount)
				if len(recorded) != workers {
					t.Fatalf("C29: upstream saw %d requests, want %d", len(recorded), workers)
				}
				for i, request := range recorded {
					if bytes.Contains(request.body, []byte(concurrentSecret)) {
						t.Errorf("C29 upstream request %d: the secret left the process: %s", i, agentWindow(request.body))
					}
					if !bytes.Contains(request.body, []byte("__PII_email_")) {
						t.Errorf("C29 upstream request %d: no placeholder reached the upstream: %s", i, agentWindow(request.body))
					}
					if !json.Valid(request.body) {
						t.Errorf("C29 upstream request %d: the body is not valid JSON: %s", i, agentWindow(request.body))
					}
				}
				agentAssertCounters(t, "C29 ten concurrent requests", before, readLiveCounters(t, env.base, env.token), workers)
				return fmt.Sprintf("redacted upstream ×%d, restored client-side", workers)
			},
		},
		{
			name: "C30 SSE stream structure and restore",
			run: func(t *testing.T, env *agentEnv) string {
				body := redactJSONBody(t, "say "+sseSecret)
				before := readLiveCounters(t, env.base, env.token)
				status, client, _, err := env.postRaw(body, "", map[string]string{agentModeHeader: agentModeSSE})
				if err != nil {
					t.Fatalf("C30 POST: %v", err)
				}
				if status != http.StatusOK {
					t.Fatalf("C30 POST = %d, want 200 (body %s)", status, agentWindow(client))
				}
				sent := env.upstream.lastRequest().body
				if bytes.Contains(sent, []byte(sseSecret)) {
					t.Errorf("C30: the secret reached the upstream: %s", agentWindow(sent))
				}
				if !bytes.Contains(sent, []byte("__PII_email_")) {
					t.Errorf("C30: no placeholder reached the upstream: %s", agentWindow(sent))
				}
				if !bytes.Contains(client, []byte(sseSecret)) {
					t.Errorf("C30: the placeholder was not restored: %s", agentWindow(client))
				}
				if want := []byte(`{"choices":[{"delta":{"content":"` + sseSecret + `"}}]}`); !bytes.Contains(client, want) {
					t.Errorf("C30: the restored delta is not a whole JSON event: %s", agentWindow(client))
				}
				if bytes.Contains(client, []byte("__PII_")) {
					t.Errorf("C30: a placeholder fragment reached the client: %s", agentWindow(client))
				}
				if frames := bytes.Count(client, []byte("data: ")); frames != 3 {
					t.Errorf("C30: SSE framing changed: %d data frames, want 3: %s", frames, agentWindow(client))
				}
				if !bytes.Contains(client, []byte("data: [DONE]")) {
					t.Errorf("C30: the terminal SSE frame is missing: %s", agentWindow(client))
				}
				agentAssertCounters(t, "C30 SSE stream structure and restore", before, readLiveCounters(t, env.base, env.token), 1)
				return "redacted upstream, SSE event restored"
			},
		},
	}

	results := make([]scenarioResult, 0, len(cases))
	for _, tc := range cases {
		verdict, status := "FAIL", "FAIL"
		if t.Run(tc.name, func(t *testing.T) {
			if tc.run != nil {
				verdict = tc.run(t, env)
			} else {
				verdict = runAgentCase(t, env, tc)
			}
		}) {
			status = "PASS"
		}
		results = append(results, scenarioResult{name: tc.name, status: status, verdict: verdict})
	}
	printAgentMatrix(results)
}

// runAgentCase executes one generic scenario: it sends the body, captures both
// sides, asserts the transport facts and the counter deltas, then asserts the
// protection (redacted upstream, restored client-side) or non-interference
// (byte-identical both ways) contract. It returns the table verdict.
func runAgentCase(t *testing.T, env *agentEnv, tc agentCase) string {
	t.Helper()
	request := tc.body(t, env)
	before := readLiveCounters(t, env.base, env.token)
	capture := env.post(t, request, tc.contentType, tc.extraHeaders)
	after := readLiveCounters(t, env.base, env.token)

	if capture.status != http.StatusOK {
		t.Fatalf("scenario %q: POST = %d, want 200 (client body %s)", tc.name, capture.status, agentWindow(capture.client))
	}
	verdict := "redacted upstream, restored client-side"
	if len(tc.secrets) == 0 {
		verdict = "byte-identical upstream"
	}
	agentAssertTransport(t, tc.name, capture, request)
	agentAssertCounters(t, tc.name, before, after, tc.wantRedactions)
	if len(tc.secrets) == 0 {
		if !bytes.Equal(capture.sent, request) {
			t.Errorf("scenario %q false positive: the upstream bytes differ from the request: %s",
				tc.name, agentWindowDiff(request, capture.sent))
		}
	} else {
		for _, secret := range tc.secrets {
			agentAssertRedacted(t, tc.name, capture.sent, capture.client, secret)
		}
	}
	if !tc.requestCarriesPlaceholder {
		agentAssertClientRoundTrip(t, tc.name, request, capture, tc.secrets)
	}
	if tc.check != nil {
		tc.check(t, env, capture, request)
	}
	return verdict
}

// agentAssertClientRoundTrip pins the client-bound half of the matrix contract.
// A secret whose raw spelling is escape-free must round-trip byte-exactly. A
// secret that JSON escaping hides from the raw request spelling cannot be
// re-spelled by the byte-level restore (the frozen contract restores the
// ORIGINAL value, as docs/architecture.md and TestRedactRequestSplicesRawSpans
// pin), so the echo body must come back byte-for-byte with each session
// placeholder restored to the secret it was minted for.
func agentAssertClientRoundTrip(t *testing.T, name string, request []byte, capture agentCapture, secrets []secretExpec) {
	t.Helper()
	if len(secrets) == 0 || !agentNeedsRestoreEcho(request, secrets) {
		if !bytes.Equal(capture.client, request) {
			t.Errorf("scenario %q: the client round-trip is not byte-exact: %s", name, agentWindowDiff(request, capture.client))
		}
		return
	}
	want, err := agentRestoreEcho(capture.sent, secrets)
	if err != nil {
		t.Fatalf("scenario %q: %v", name, err)
	}
	if !bytes.Equal(capture.client, want) {
		t.Errorf("scenario %q: the client bytes are not the echo with the original secrets restored: %s",
			name, agentWindowDiff(want, capture.client))
	}
}

// agentNeedsRestoreEcho reports whether any secret's decoded value is not a raw
// substring of the request, which is exactly when JSON string escaping makes
// the byte-exact request round-trip impossible.
func agentNeedsRestoreEcho(request []byte, secrets []secretExpec) bool {
	for _, secret := range secrets {
		if !bytes.Contains(request, []byte(secret.value)) {
			return true
		}
	}
	return false
}

// agentPlaceholderPattern captures the frozen placeholder's type segment, so an
// echo body can be mapped back to the secrets it was minted for.
var agentPlaceholderPattern = regexp.MustCompile(`__PII_([a-z0-9_]{1,16})_[0-9a-f]{12,64}__`)

// agentRestoreEcho restores every session placeholder in the upstream-received
// body to the original secret of its category, the exact bytes a client must
// receive from an echo upstream. A category carrying more than one candidate
// value is ambiguous and fails loudly rather than guessing.
func agentRestoreEcho(sent []byte, secrets []secretExpec) ([]byte, error) {
	byCategory := make(map[string][]string, len(secrets))
	for _, secret := range secrets {
		byCategory[secret.category] = append(byCategory[secret.category], secret.value)
	}
	var failure error
	out := agentPlaceholderPattern.ReplaceAllFunc(sent, func(match []byte) []byte {
		parts := agentPlaceholderPattern.FindSubmatch(match)
		values := byCategory[string(parts[1])]
		if len(values) != 1 {
			if failure == nil {
				failure = fmt.Errorf("placeholder category %q carries %d candidate secrets, so the echo cannot be mapped unambiguously", parts[1], len(values))
			}
			return match
		}
		return []byte(values[0])
	})
	return out, failure
}

// agentAssertTransport pins the byte-level transport facts every scenario
// shares: valid JSON with an honest declared length on both directions, and a
// test-built request that is itself valid JSON.
func agentAssertTransport(t *testing.T, name string, capture agentCapture, request []byte) {
	t.Helper()
	if !json.Valid(capture.sent) {
		t.Errorf("scenario %q: the upstream body is not valid JSON: %s", name, agentWindow(capture.sent))
	}
	if capture.reqDeclared != int64(len(capture.sent)) {
		t.Errorf("scenario %q: upstream declared Content-Length %d, but received %d bytes", name, capture.reqDeclared, len(capture.sent))
	}
	if declared := capture.reqHeader.Get("Content-Length"); declared != "" && declared != strconv.Itoa(len(capture.sent)) {
		t.Errorf("scenario %q: upstream Content-Length header = %q, want %d", name, declared, len(capture.sent))
	}
	if declared := capture.respHeader.Get("Content-Length"); declared != "" && declared != strconv.Itoa(len(capture.client)) {
		t.Errorf("scenario %q: client-bound Content-Length = %q, want %d", name, declared, len(capture.client))
	}
	if !json.Valid(request) {
		t.Errorf("scenario %q: the test-built request is not valid JSON (test bug): %s", name, agentWindow(request))
	}
}

// agentAssertCounters pins the counter contract for one scenario: no
// interruption (no content-policy block, no rule block, no walk skip) and
// exactly the expected number of substitutions.
func agentAssertCounters(t *testing.T, name string, before, after countedStatus, wantRedactions int) {
	t.Helper()
	if got := after.ContentPolicyBlocks - before.ContentPolicyBlocks; got != 0 {
		t.Errorf("scenario %q: content_policy_blocks moved by %d, want 0", name, got)
	}
	if got := after.RuleBlocks - before.RuleBlocks; got != 0 {
		t.Errorf("scenario %q: rule_blocks moved by %d, want 0", name, got)
	}
	if got := after.WalkSkips - before.WalkSkips; got != 0 {
		t.Errorf("scenario %q: walk_skips moved by %d, want 0", name, got)
	}
	if got := after.Redactions - before.Redactions; got != int64(wantRedactions) {
		t.Errorf("scenario %q: redactions moved by %d, want %d", name, got, wantRedactions)
	}
}

// agentAssertRedacted pins one secret's protection: absent upstream under the
// expected category placeholder, restored client-side, no placeholder
// client-visible.
func agentAssertRedacted(t *testing.T, name string, sent, client []byte, secret secretExpec) {
	t.Helper()
	if bytes.Contains(sent, []byte(secret.value)) {
		t.Errorf("scenario %q: the %s secret reached the upstream: %s", name, secret.category, agentWindow(sent))
	}
	placeholder := []byte("__PII_" + secret.category + "_")
	if !bytes.Contains(sent, placeholder) {
		t.Errorf("scenario %q: no %s placeholder reached the upstream: %s", name, secret.category, agentWindow(sent))
	}
	if !bytes.Contains(client, []byte(secret.value)) {
		t.Errorf("scenario %q: the %s secret did not return to the client: %s", name, secret.category, agentWindow(client))
	}
	if bytes.Contains(client, placeholder) {
		t.Errorf("scenario %q: a %s placeholder reached the client: %s", name, secret.category, agentWindow(client))
	}
}

// agentWindow renders a bounded, quoted window for failure messages, so a
// failure in a megabyte payload never dumps the payload.
func agentWindow(data []byte) string {
	const window = 160
	if len(data) <= window {
		return strconv.Quote(string(data))
	}
	return strconv.Quote(string(data[:window])) + fmt.Sprintf("... (%d bytes total)", len(data))
}

// agentWindowDiff renders a short window around the first differing byte.
func agentWindowDiff(want, got []byte) string {
	at := 0
	for at < len(want) && at < len(got) && want[at] == got[at] {
		at++
	}
	return fmt.Sprintf("first difference at byte %d (want %d bytes, got %d bytes)\n  want[%d:]: %s\n   got[%d:]: %s",
		at, len(want), len(got), at, agentSnippet(want, at), at, agentSnippet(got, at))
}

// agentSnippet quotes a bounded byte window around at.
func agentSnippet(data []byte, at int) string {
	start := at - 48
	if start < 0 {
		start = 0
	}
	end := at + 144
	if end > len(data) {
		end = len(data)
	}
	snippet := strconv.Quote(string(data[start:end]))
	if end < len(data) {
		snippet += "..."
	}
	if start > 0 {
		snippet = "..." + snippet
	}
	return snippet
}

// printAgentMatrix prints one line per scenario: the name, the PASS/FAIL
// status and the upstream verdict.
func printAgentMatrix(results []scenarioResult) {
	width := len("SCENARIO")
	for _, result := range results {
		if len(result.name) > width {
			width = len(result.name)
		}
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "\n=== agent scenario matrix (%d scenarios) ===\n", len(results))
	fmt.Fprintf(&out, "%-*s  %-6s  %s\n", width, "SCENARIO", "STATUS", "UPSTREAM VERDICT")
	for _, result := range results {
		fmt.Fprintf(&out, "%-*s  %-6s  %s\n", width, result.name, result.status, result.verdict)
	}
	fmt.Print(out.String())
}

// regexRedactRule is a minimal third-party regex rule that requests
// request-phase redaction of one runtime-chosen pattern under the custom
// category. It reaches the evaluator through the same Registry.Register path
// any external rule takes.
type regexRedactRule struct {
	id       string
	pattern  *regexp.Regexp
	category string
}

// ID returns the registered rule id.
func (r regexRedactRule) ID() string { return r.id }

// Type returns the rule type the core records.
func (r regexRedactRule) Type() string { return "regex" }

// Category returns the finding category.
func (r regexRedactRule) Category() string { return r.category }

// Scope returns the request phase: only requests may substitute a placeholder.
func (r regexRedactRule) Scope() filter.Scope { return filter.ScopeRequest }

// Action returns redact, the direction the rule requests.
func (r regexRedactRule) Action() filter.Action { return filter.ActionRedact }

// Priority returns a priority below the built-ins.
func (r regexRedactRule) Priority() int { return 10 }

// Confidence returns a confidence inside (0,1].
func (r regexRedactRule) Confidence() float64 { return 0.9 }

// Inspect returns every pattern match inside leaf.
func (r regexRedactRule) Inspect(leaf []byte) []filter.Span {
	matches := r.pattern.FindAllIndex(leaf, -1)
	spans := make([]filter.Span, 0, len(matches))
	for _, match := range matches {
		spans = append(spans, filter.Span{Start: match[0], End: match[1]})
	}
	return spans
}
