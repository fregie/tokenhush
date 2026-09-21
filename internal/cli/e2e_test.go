// e2e_test.go is the W6.6 end-to-end acceptance suite. It starts the REAL run
// gateway (the production pipeline build, a real loopback listener, real
// session files, the real data plane and forwarder) against a loopback echo
// upstream that RECORDS the exact bytes of every request it receives and
// echoes them back. Every assertion is made on captured bytes -- the recorded
// upstream request and the client-bound response -- never on a log line.
//
// The secret is generated at run time, the two Block rules are injected through
// the frozen filter.Rule registry, and the captured transcripts are saved under
// .omo/evidence/W6.6/.
package cli

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/supply"
)

// The e2e fixture constants: one configured route, the mode header the upstream
// switches on, and the frozen foreign placeholder the upstream may echo back
// unaltered.
const (
	e2ePath        = "/v1/chat/completions"
	e2eModeHeader  = "X-E2E-Mode"
	e2eModeSSE     = "sse"
	e2eModeForeign = "foreign"
	e2eForeignBody = `{"content":"__PII_email_deadbeefcafe__"}`
)

// e2ePlaceholder matches the frozen placeholder grammar the session mints.
var e2ePlaceholder = regexp.MustCompile(`__PII_[a-z0-9_]{1,16}_[0-9a-f]{12,64}__`)

// e2eUpstream is the loopback echo upstream. It records every request body it
// receives and answers according to the mode header, so one upstream serves the
// buffered, SSE and foreign-placeholder cases.
type e2eUpstream struct {
	server *httptest.Server

	mu       sync.Mutex
	requests int
	last     []byte
}

// newE2EUpstream starts the recording echo upstream and closes it with the test.
func newE2EUpstream(t *testing.T) *e2eUpstream {
	t.Helper()
	upstream := &e2eUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(upstream.serve))
	t.Cleanup(upstream.server.Close)
	return upstream
}

// serve records one request and answers it.
func (u *e2eUpstream) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	u.mu.Lock()
	u.requests++
	u.last = bytes.Clone(body)
	u.mu.Unlock()
	switch r.Header.Get(e2eModeHeader) {
	case e2eModeSSE:
		u.serveSSE(w, body)
	case e2eModeForeign:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, e2eForeignBody)
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// serveSSE emits an SSE stream whose two data deltas split the placeholder the
// request carried: the first delta ends mid-placeholder, the second completes
// it, and the terminal frame is the conventional [DONE]. The fragments are the
// data payloads themselves, the shape the frozen backfill engine restores a
// token from across consecutive deltas.
func (u *e2eUpstream) serveSSE(w http.ResponseWriter, body []byte) {
	placeholder := e2ePlaceholder.Find(body)
	if placeholder == nil {
		http.Error(w, "the request carried no placeholder", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	half := len(placeholder) / 2
	for _, frame := range []string{
		"data: " + string(placeholder[:half]) + "\n\n",
		"data: " + string(placeholder[half:]) + " tail\n\n",
		"data: [DONE]\n\n",
	} {
		_, _ = io.WriteString(w, frame)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// count returns how many requests the upstream has served.
func (u *e2eUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests
}

// recorded returns a copy of the most recent request body.
func (u *e2eUpstream) recorded() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return bytes.Clone(u.last)
}

// blockRule is a minimal third-party filter.Rule: it blocks one runtime-chosen
// trigger literal in the phase it is scoped to. It reaches the evaluator
// through the same Registry.Register path any external rule takes.
type blockRule struct {
	id      string
	scope   filter.Scope
	trigger string
}

// ID returns the registered rule id.
func (r blockRule) ID() string { return r.id }

// Type returns the rule type the core records.
func (r blockRule) Type() string { return "keyword" }

// Category returns the finding category.
func (r blockRule) Category() string { return "custom" }

// Scope returns the one phase this rule evaluates in.
func (r blockRule) Scope() filter.Scope { return r.scope }

// Action returns block, the direction the rule requests.
func (r blockRule) Action() filter.Action { return filter.ActionBlock }

// Priority returns a priority below the built-ins.
func (r blockRule) Priority() int { return 10 }

// Confidence returns a confidence inside (0,1].
func (r blockRule) Confidence() float64 { return 0.9 }

// Inspect returns the trigger span inside leaf when it is present.
func (r blockRule) Inspect(leaf []byte) []filter.Span {
	at := bytes.Index(leaf, []byte(r.trigger))
	if at < 0 {
		return nil
	}
	return []filter.Span{{Start: at, End: at + len(r.trigger)}}
}

// TestE2EAcceptance drives the assembled gateway over a real loopback socket.
// The gateway and the echo upstream are shared by the six cases; each case
// asserts on the bytes that were actually captured.
func TestE2EAcceptance(t *testing.T) {
	upstream := newE2EUpstream(t)
	requestBlockTrigger := "BLOCK-" + e2eRandomHex(t, 8)
	responseBlockTrigger := "REFUSE-" + e2eRandomHex(t, 8)
	base := e2eGateway(t, upstream,
		blockRule{id: "e2e-request-block", scope: filter.ScopeRequest, trigger: requestBlockTrigger},
		blockRule{id: "e2e-response-block", scope: filter.ScopeResponse, trigger: responseBlockTrigger},
	)

	t.Run("placeholder leaves and the original returns", func(t *testing.T) {
		secret := e2eSecret(t)
		status, got := e2ePost(t, base+e2ePath, e2eBody("my email is "+secret), nil)
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		if bytes.Contains(sent, []byte(secret)) {
			t.Errorf("the secret left the process: %s", sent)
		}
		if !bytes.Contains(sent, []byte("__PII_email_")) {
			t.Errorf("no placeholder reached the upstream: %s", sent)
		}
		if !bytes.Contains(got, []byte(secret)) {
			t.Errorf("the original secret did not return to the client: %s", got)
		}
		if bytes.Contains(got, []byte("__PII_")) {
			t.Errorf("a placeholder reached the client: %s", got)
		}
		e2eTranscript(t, "buffered-upstream-request.txt", sent)
		e2eTranscript(t, "buffered-client-response.txt", got)
	})

	t.Run("a placeholder split across SSE deltas is restored", func(t *testing.T) {
		secret := e2eSecret(t)
		status, got := e2ePost(t, base+e2ePath, e2eBody("say "+secret), map[string]string{e2eModeHeader: e2eModeSSE})
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		if !bytes.Contains(got, []byte(secret)) {
			t.Errorf("the split placeholder was not restored: %s", got)
		}
		if bytes.Contains(got, []byte("__PII_")) {
			t.Errorf("a placeholder fragment reached the client: %s", got)
		}
		if frames := bytes.Count(got, []byte("data: ")); frames != 3 {
			t.Errorf("SSE framing changed: %d data frames, want 3: %s", frames, got)
		}
		if !bytes.Contains(got, []byte("data: [DONE]")) {
			t.Errorf("the terminal SSE frame is missing: %s", got)
		}
		e2eTranscript(t, "sse-client-stream.txt", got)
	})

	t.Run("a foreign placeholder is never fabricated into a secret", func(t *testing.T) {
		status, got := e2ePost(t, base+e2ePath, e2eBody("hello there"), map[string]string{e2eModeHeader: e2eModeForeign})
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		if !bytes.Equal(got, []byte(e2eForeignBody)) {
			t.Errorf("the client body = %q, want the upstream's foreign placeholder unchanged %q", got, e2eForeignBody)
		}
		e2eTranscript(t, "foreign-client-response.txt", got)
	})

	t.Run("a compressed request is refused before any dial", func(t *testing.T) {
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		if _, err := writer.Write(e2eBody("compressed request")); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		before := upstream.count()
		status, got := e2ePost(t, base+e2ePath, compressed.Bytes(), map[string]string{"Content-Encoding": "gzip"})
		if status != http.StatusUnsupportedMediaType {
			t.Fatalf("POST = %d, want 415 (body %s)", status, got)
		}
		if upstream.count() != before {
			t.Errorf("a compressed request dialled the upstream (%d -> %d)", before, upstream.count())
		}
	})

	t.Run("a request-scoped block names the rule and dials nothing", func(t *testing.T) {
		before := upstream.count()
		status, got := e2ePost(t, base+e2ePath, e2eBody("please block "+requestBlockTrigger), nil)
		if status != http.StatusForbidden {
			t.Fatalf("POST = %d, want 403 (body %s)", status, got)
		}
		if !bytes.Contains(got, []byte("e2e-request-block")) {
			t.Errorf("the 403 body does not name the rule id: %s", got)
		}
		if upstream.count() != before {
			t.Errorf("a request-scoped block dialled the upstream (%d -> %d)", before, upstream.count())
		}
	})

	t.Run("a response-scoped block names the rule", func(t *testing.T) {
		status, got := e2ePost(t, base+e2ePath, e2eBody("say "+responseBlockTrigger+" back"), nil)
		if status != http.StatusBadGateway {
			t.Fatalf("POST = %d, want 502 (body %s)", status, got)
		}
		if !bytes.Contains(got, []byte("e2e-response-block")) {
			t.Errorf("the 502 body does not name the rule id: %s", got)
		}
	})
}

// e2eGateway starts the real run server over the echo upstream and returns its
// base URL. It is the production gateway plus the injected test rules; the
// gateway is stopped with the test.
func e2eGateway(t *testing.T, upstream *e2eUpstream, rules ...filter.Rule) string {
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
	return base
}

// injectTestRules swaps the gateway policy for one over the production built-in
// detector selection plus the injected rules: the injected registry is the only
// difference from the production pipeline.
func injectTestRules(gw *gateway, cfg config.Config, rules []filter.Rule) error {
	registry := filter.NewRegistry()
	if err := registry.RegisterBuiltin(selectBuiltins(cfg.Detectors, scanBudget(cfg))...); err != nil {
		return err
	}
	if err := registry.Register(rules...); err != nil {
		return err
	}
	gw.policy = filter.NewPolicy(registry, filter.PolicyConfig{Timeout: cfg.DetectorTimeout})
	return nil
}

// e2eWaitReady polls the gateway's local route until it answers or the deadline
// passes.
func e2eWaitReady(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(base + "/v1/models")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the gateway at %s never answered GET /v1/models", base)
}

// e2ePost sends one JSON request and returns its status and complete
// client-bound body.
func e2ePost(t *testing.T, url string, body []byte, headers map[string]string) (int, []byte) {
	t.Helper()
	return e2ePostTimeout(t, url, body, headers, 15*time.Second)
}

// e2ePostTimeout is e2ePost with an explicit client timeout, so a large-body
// case can allow for the race detector's slowdown without widening the bound
// every other case relies on.
func e2ePostTimeout(t *testing.T, url string, body []byte, headers map[string]string, timeout time.Duration) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	client := &http.Client{Timeout: timeout}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the response: %v", err)
	}
	return response.StatusCode, got
}

// e2eBody builds one chat-completions request body around content.
func e2eBody(content string) []byte {
	return []byte(fmt.Sprintf(`{"model":"echo","messages":[{"role":"user","content":"%s"}]}`, content))
}

// e2eSecret returns a runtime-generated secret the email detector flags.
func e2eSecret(t *testing.T) string {
	t.Helper()
	return "e2e-" + e2eRandomHex(t, 8) + "@example.com"
}

// e2eRandomHex returns size cryptographically-random bytes as hex.
func e2eRandomHex(t *testing.T, size int) string {
	t.Helper()
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return hex.EncodeToString(buf)
}

// e2eTranscript saves one captured byte transcript under .omo/evidence/W6.6/.
func e2eTranscript(t *testing.T, name string, data []byte) {
	t.Helper()
	dir := filepath.Join(e2eRepoRoot(t), ".omo", "evidence", "W6.6")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create the evidence directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("write the transcript %s: %v", name, err)
	}
}

// e2eRepoRoot locates the repository root from this test file's own path.
func e2eRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed: cannot locate the repository root")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// TestE2EMultimodalBodySizeIsAdmitted is the CLI-level regression for the
// reported multimodal failure: a declared-JSON body above scan_budget_bytes
// (32 MiB) and below max_body_bytes (64 MiB), dominated by base64 image leaves
// and carrying exactly one detectable secret in a text leaf, used to be refused
// with 403 scan_budget_exceeded before the walk. Through the real run gateway it
// must be admitted, redacted outbound, restored inbound, and refused by
// nothing: no refusal line on stderr and no content-policy block.
func TestE2EMultimodalBodySizeIsAdmitted(t *testing.T) {
	const (
		imageLeaves = 20
		imageBytes  = 1_800_000
	)

	// Given a multimodal body above the per-leaf scan budget and below the cap,
	// built once from one shared detector-inert filler. The secret is the
	// runtime-generated e2e address, so no email-shaped literal sits in the
	// source.
	secret := e2eSecret(t)
	filler := strings.Repeat("A", imageBytes)
	var body bytes.Buffer
	body.Grow(imageLeaves*(imageBytes+96) + 256)
	body.WriteString(`{"model":"vision-probe","messages":[{"role":"user","content":[{"type":"text","text":"contact `)
	body.WriteString(secret)
	body.WriteString(`"}`)
	for i := 0; i < imageLeaves; i++ {
		body.WriteString(`,{"type":"image_url","image_url":{"url":"data:image/png;base64,`)
		body.WriteString(filler)
		body.WriteString(`"}}`)
	}
	body.WriteString(`]}]}`)
	raw := body.Bytes()
	if int64(len(raw)) <= config.ScanBudgetBytes || int64(len(raw)) >= config.MaxBodyBytes {
		t.Fatalf("the fixture body is %d bytes, want inside (scan budget %d, max body %d)", len(raw), config.ScanBudgetBytes, config.MaxBodyBytes)
	}

	upstream := newE2EUpstream(t)
	// The echo upstream answers with the redacted request body, so the
	// client-bound echo is ~36 MB and would trip the 32 MiB response cap -- a
	// documented response-side guard outside this request-path regression.
	// Raising it lets the real buffered restore path run over the admitted body.
	base, logs, dataDir := redactGatewayTuned(t, upstream, func(cfg *config.Config) {
		cfg.ResponseBufferBytes = config.MaxBodyBytes
	})
	token := readControlToken(t, dataDir)
	before := readLiveCounters(t, base, token)

	// When the real run gateway serves it.
	status, got := e2ePostTimeout(t, base+e2ePath, raw, nil, 120*time.Second)

	// Then (1) the request is admitted and the upstream observed it.
	if status != http.StatusOK {
		t.Fatalf("POST = %d, want 200 (client body %d bytes)", status, len(got))
	}
	if upstream.count() != 1 {
		t.Fatalf("the upstream served %d requests, want exactly 1", upstream.count())
	}
	sent := upstream.recorded()
	if !e2ePlaceholder.Match(sent) {
		t.Error("the upstream body carries no session placeholder")
	}
	// (2) the text-leaf secret never left the gateway.
	if bytes.Contains(sent, []byte(secret)) {
		t.Error("the text-leaf secret left the gateway")
	}
	// (3) the client-bound body restored the original secret.
	if !bytes.Contains(got, []byte(secret)) {
		t.Error("the client-bound body did not restore the text-leaf secret")
	}
	// (4) the request was admitted, not refused: no refusal line was logged and
	// the content-policy counter did not move.
	if count := logs.count("tokenhush: refused request"); count != 0 {
		t.Errorf("refusal lines = %d, want exactly 0 (stderr: %s)", count, logs.String())
	}
	after := readLiveCounters(t, base, token)
	if after.ContentPolicyBlocks != before.ContentPolicyBlocks {
		t.Errorf("content_policy_blocks moved: %d -> %d", before.ContentPolicyBlocks, after.ContentPolicyBlocks)
	}
	// The text leaf held exactly one detectable secret: exactly one
	// substitution was applied.
	if delta := after.Redactions - before.Redactions; delta != 1 {
		t.Errorf("redactions moved by %d, want exactly 1", delta)
	}
}

// TestE2EOverCapBodyRefusalCarriesTheFrozenDocument pins what the existing
// TestRefusalLogIsStderrOnly leaves open at the CLI level: a declared-JSON body
// exactly one byte over max_body_bytes is refused with the frozen
// {"error":"body_too_large"} document, dials nothing, and emits exactly one
// stderr line.
func TestE2EOverCapBodyRefusalCarriesTheFrozenDocument(t *testing.T) {
	const maxBody = 1 << 20
	upstream := newE2EUpstream(t)
	base, logs, _ := redactGatewayTuned(t, upstream, func(cfg *config.Config) {
		cfg.MaxBodyBytes = maxBody
	})

	// Given a declared-JSON body exactly one byte over the cap.
	pad := maxBody - len(`{"pad":""}`) + 1
	body := []byte(`{"pad":"` + strings.Repeat("E", pad) + `"}`)
	if int64(len(body)) != maxBody+1 {
		t.Fatalf("the fixture body is %d bytes, want exactly %d", len(body), maxBody+1)
	}

	// When the real run gateway serves it.
	before := upstream.count()
	status, got := e2ePost(t, base+e2ePath, body, nil)

	// Then it is refused with the frozen document, before any dial, and the
	// refusal is observable on stderr exactly once.
	if status != http.StatusForbidden {
		t.Fatalf("POST = %d, want 403 (client body %d bytes)", status, len(got))
	}
	if want := `{"error":"body_too_large"}`; string(got) != want {
		t.Errorf("refusal body = %q, want exactly %q", got, want)
	}
	if upstream.count() != before {
		t.Errorf("an over-cap body dialled the upstream (%d -> %d)", before, upstream.count())
	}
	if count := logs.count("tokenhush: refused request body_too_large"); count != 1 {
		t.Errorf("refusal lines = %d, want exactly 1 (stderr: %s)", count, logs.String())
	}
}
