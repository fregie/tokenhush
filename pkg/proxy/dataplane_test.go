package proxy

// dataplane_test.go pins the request-side half of invariant 5: a request that
// declares JSON is walked and evaluated before the forwarder ever sees it, and
// every failure in that pipeline is refused locally with a metadata-only body.
// A request that does not declare JSON takes the byte-for-byte passthrough
// with no walk and no counter change. The tests assert three things on every
// refusal: the status, the JSON classification body, and that neither the
// upstream nor the client ever saw a matched byte.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/protocol"
)

// dataPlaneSecret is planted in every refusal test body: a refusal that carries
// it has leaked matched content.
const dataPlaneSecret = "SECRET-LEAF-9f3a71"

// stubWalker is the injectable walker seam. It counts calls, so a test can
// prove a non-JSON body was never walked, and delegates to fn when set.
type stubWalker struct {
	calls atomic.Int32
	fn    func([]byte) ([]protocol.Leaf, error)
}

// Walk implements Walker.
func (w *stubWalker) Walk(data []byte) ([]protocol.Leaf, error) {
	w.calls.Add(1)
	if w.fn != nil {
		return w.fn(data)
	}
	return protocol.Walk(data)
}

// stubRequestEvaluator is the injectable request-evaluation seam.
type stubRequestEvaluator struct {
	decision RequestDecision
	err      error
	panics   bool
	hang     chan struct{}
	calls    atomic.Int32

	mu   sync.Mutex
	seen [][]protocol.Leaf
}

// EvaluateRequest implements RequestEvaluator. A non-nil hang blocks the call
// forever, so only the data plane's own bound can end it.
func (e *stubRequestEvaluator) EvaluateRequest(_ context.Context, leaves []protocol.Leaf) (RequestDecision, error) {
	e.calls.Add(1)
	e.mu.Lock()
	e.seen = append(e.seen, leaves)
	e.mu.Unlock()
	if e.panics {
		panic("stub evaluator panic")
	}
	if e.hang != nil {
		<-e.hang
	}
	return e.decision, e.err
}

// leaves returns the leaf sets the evaluator observed.
func (e *stubRequestEvaluator) leaves() [][]protocol.Leaf {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][]protocol.Leaf(nil), e.seen...)
}

// allowRequestEvaluator is the inert allow seam.
func allowRequestEvaluator() *stubRequestEvaluator {
	return &stubRequestEvaluator{decision: RequestDecision{Action: RequestAllow}}
}

// dataPlaneHarness builds a data plane over a real loopback stub upstream whose
// dials are recorded, so a test can assert both the client-bound verdict and
// what the upstream did or did not receive.
func dataPlaneHarness(t *testing.T, cfg DataPlaneConfig) (*DataPlane, *fakeUpstream, *dialRecorder) {
	t.Helper()
	upstream := newFakeUpstream(t)
	forwarder, recorder := recordedForwarder(t, upstream, nil)
	return NewDataPlane(forwarder, cfg), upstream, recorder
}

// dataPlanePost builds a POST for the data plane; setType controls whether a
// Content-Type header is present at all.
func dataPlanePost(body, contentType string, setType bool) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	if setType {
		request.Header.Set("Content-Type", contentType)
	}
	return request
}

// requireRefusal asserts the client-bound status and decodes the JSON refusal.
func requireRefusal(t *testing.T, response *httptest.ResponseRecorder, wantStatus int) map[string]string {
	t.Helper()
	if response.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body %q)", response.Code, wantStatus, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("refusal Content-Type = %q, want application/json", got)
	}
	var fields map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
		t.Fatalf("refusal body %q is not a JSON object: %v", response.Body.String(), err)
	}
	return fields
}

// requireNoUpstream proves a refused request never reached the stub upstream.
func requireNoUpstream(t *testing.T, upstream *fakeUpstream, recorder *dialRecorder) {
	t.Helper()
	select {
	case got := <-upstream.requests:
		t.Fatalf("a refused request reached the upstream: %+v", got)
	default:
	}
	if got := recorder.count(); got != 0 {
		t.Errorf("a refused request opened %d upstream dials, want 0", got)
	}
}

// requireUpstream returns the one request the stub upstream observed.
func requireUpstream(t *testing.T, upstream *fakeUpstream) upstreamRequest {
	t.Helper()
	select {
	case got := <-upstream.requests:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream never observed a request")
		return upstreamRequest{}
	}
}

// requireCounters asserts the counters the request side may move.
func requireCounters(t *testing.T, counters *Counters, contentPolicy, rule, walkSkips int64) {
	t.Helper()
	if got := counters.ContentPolicyBlocks(); got != contentPolicy {
		t.Errorf("content_policy_blocks = %d, want %d", got, contentPolicy)
	}
	if got := counters.RuleBlocks(); got != rule {
		t.Errorf("rule_blocks = %d, want %d", got, rule)
	}
	if got := counters.WalkSkips(); got != walkSkips {
		t.Errorf("walk_skips = %d, want %d", got, walkSkips)
	}
}

// TestDataPlaneDeclaredJSONWalkFailure: a request that declares JSON but whose
// body cannot be walked is a 400 classification refusal with zero upstream
// bytes, one content-policy block and no matched content in the body.
func TestDataPlaneDeclaredJSONWalkFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		setType     bool
	}{
		{name: "application/json", contentType: "application/json", setType: true},
		{name: "media type with parameters and case", contentType: "Application/JSON; charset=utf-8", setType: true},
		{name: "no content type sniffed as JSON", setType: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counters := NewCounters()
			walker := &stubWalker{}
			plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker, Evaluator: allowRequestEvaluator(), Counters: counters})
			response := httptest.NewRecorder()
			plane.ServeHTTP(response, dataPlanePost(`{"message": "`+dataPlaneSecret, tc.contentType, tc.setType))

			fields := requireRefusal(t, response, http.StatusBadRequest)
			if fields["error"] != "malformed_json" {
				t.Errorf("refusal error = %q, want malformed_json", fields["error"])
			}
			if bytes.Contains(response.Body.Bytes(), []byte(dataPlaneSecret)) {
				t.Error("the refusal body carries matched content")
			}
			if got := walker.calls.Load(); got != 1 {
				t.Errorf("walker calls = %d, want exactly 1", got)
			}
			requireNoUpstream(t, upstream, recorder)
			requireCounters(t, counters, 1, 0, 0)
			t.Logf("qa: malformed declared JSON -> status=%d body=%s upstream_dials=%d", response.Code, response.Body.String(), recorder.count())
		})
	}
}

// TestDataPlaneContentTypeGate: only an exact application/json media type or a
// JSON-looking first byte with no Content-Type declares JSON. Everything else,
// including application/json-seq, passes through byte-identically and unwalked.
func TestDataPlaneContentTypeGate(t *testing.T) {
	valid := `{"message":"hello"}`
	for _, tc := range []struct {
		name        string
		body        string
		contentType string
		setType     bool
		declared    bool
	}{
		{name: "exact media type", body: valid, contentType: "application/json", setType: true, declared: true},
		{name: "media type with parameters and case", body: valid, contentType: "Application/JSON; charset=utf-8", setType: true, declared: true},
		{name: "json-seq is a passthrough", body: valid, contentType: "application/json-seq", setType: true},
		{name: "json-patch+json is a passthrough", body: valid, contentType: "application/json-patch+json", setType: true},
		{name: "text/plain with a JSON-looking body is a passthrough", body: valid, contentType: "text/plain", setType: true},
		{name: "a blank media type is a passthrough", body: valid, contentType: "", setType: true},
		{name: "object first byte without a content type", body: "  \n\t" + valid, declared: true},
		{name: "array first byte without a content type", body: "[1,2]", declared: true},
		{name: "string first byte without a content type", body: `"hello"`, declared: true},
		{name: "other first byte without a content type", body: "hello world"},
		{name: "whitespace-only body without a content type", body: " \n\t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counters := NewCounters()
			walker := &stubWalker{}
			evaluator := allowRequestEvaluator()
			plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker, Evaluator: evaluator, Counters: counters})
			response := httptest.NewRecorder()
			plane.ServeHTTP(response, dataPlanePost(tc.body, tc.contentType, tc.setType))

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %q)", response.Code, response.Body.String())
			}
			got := requireUpstream(t, upstream)
			if string(got.body) != tc.body {
				t.Errorf("upstream body = %q, want the identical %q", got.body, tc.body)
			}
			if got.path != "/v1/chat/completions" {
				t.Errorf("upstream path = %q, want /v1/chat/completions", got.path)
			}
			if got := recorder.count(); got != 1 {
				t.Errorf("upstream dials = %d, want exactly 1", got)
			}
			wantWalks := int32(0)
			if tc.declared {
				wantWalks = 1
			}
			if got := walker.calls.Load(); got != wantWalks {
				t.Errorf("walker calls = %d, want %d (declared=%v)", got, wantWalks, tc.declared)
			}
			if got := evaluator.calls.Load(); got != wantWalks {
				t.Errorf("evaluator calls = %d, want %d (declared=%v)", got, wantWalks, tc.declared)
			}
			requireCounters(t, counters, 0, 0, 0)
			t.Logf("qa: %s -> status=%d walker_calls=%d declared=%v", tc.name, response.Code, walker.calls.Load(), tc.declared)
		})
	}
}

// TestDataPlaneAdmitsBodyAboveTheScanBudget pins the narrowed scan-budget
// semantics: the aggregate per-request refusal is gone, so a declared-JSON body
// larger than config.ScanBudgetBytes is walked and forwarded instead of
// refused, and the only request-side cap is config.MaxBodyBytes at the shared
// read seam. The per-leaf budget stays in pkg/filter and internal/cli.
func TestDataPlaneAdmitsBodyAboveTheScanBudget(t *testing.T) {
	t.Run("above the scan budget and under the cap is admitted whole", func(t *testing.T) {
		// Given a declared-JSON body one byte over the per-leaf scan budget,
		// streamed so the test does not materialise a second full payload.
		const total = int64(config.ScanBudgetBytes) + 1
		counters := NewCounters()
		walker := &stubWalker{}
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{
			Walker: walker, Evaluator: allowRequestEvaluator(), Counters: counters,
		})
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &sizedBody{Total: total, JSON: true})
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = total

		// When the data plane serves it.
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, request)

		// Then it is walked and forwarded byte-for-byte, with no refusal.
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: a body over scan_budget_bytes is no longer refused (body %q)", response.Code, response.Body.String())
		}
		if got := int64(len(requireUpstream(t, upstream).body)); got != total {
			t.Errorf("upstream body length = %d, want the full %d bytes", got, total)
		}
		if got := walker.calls.Load(); got != 1 {
			t.Errorf("walker calls = %d, want exactly 1: the body is scanned, not skipped", got)
		}
		if got := recorder.count(); got != 1 {
			t.Errorf("upstream dials = %d, want exactly 1", got)
		}
		requireCounters(t, counters, 0, 0, 0)
	})

	t.Run("over the cap is refused before any walk", func(t *testing.T) {
		counters := NewCounters()
		walker := &stubWalker{}
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{
			Walker: walker, Evaluator: allowRequestEvaluator(), Counters: counters,
		})
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", overCapJSONBody())
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = -1

		response := httptest.NewRecorder()
		plane.ServeHTTP(response, request)

		fields := requireRefusal(t, response, http.StatusForbidden)
		if fields["error"] != "body_too_large" {
			t.Errorf("refusal error = %q, want body_too_large", fields["error"])
		}
		if got := walker.calls.Load(); got != 0 {
			t.Errorf("walker calls = %d, want 0: the cap is decided before any walk", got)
		}
		requireNoUpstream(t, upstream, recorder)
		requireCounters(t, counters, 1, 0, 0)
	})

	t.Run("a non-JSON body is never walked", func(t *testing.T) {
		body := strings.Repeat("x", 4096)
		counters := NewCounters()
		walker := &stubWalker{}
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{
			Walker: walker, Evaluator: allowRequestEvaluator(), Counters: counters,
		})
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, dataPlanePost(body, "application/octet-stream", true))

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want the passthrough 200", response.Code)
		}
		if got := requireUpstream(t, upstream); string(got.body) != body {
			t.Error("the passthrough body was not identical")
		}
		if got := recorder.count(); got != 1 {
			t.Errorf("upstream dials = %d, want exactly 1", got)
		}
		if got := walker.calls.Load(); got != 0 {
			t.Errorf("walker calls = %d, want 0", got)
		}
		requireCounters(t, counters, 0, 0, 0)
	})
}

// TestDataPlanePluginFailuresFailClosed: every detection failure reason is a
// 403 plugin_failure naming that reason, with no matched byte and exactly one
// content-policy block.
func TestDataPlanePluginFailuresFailClosed(t *testing.T) {
	valid := `{"message":"` + dataPlaneSecret + `"}`
	for _, tc := range []struct {
		name   string
		err    error
		panics bool
		reason string
	}{
		{name: "budget", err: &DetectorFailure{RuleID: "rule-budget", Reason: FailureBudget}, reason: "budget"},
		{name: "timeout", err: &DetectorFailure{Reason: FailureTimeout}, reason: "timeout"},
		{name: "error", err: errors.New("detector exploded"), reason: "error"},
		{name: "malformed", err: &DetectorFailure{Reason: FailureMalformed}, reason: "malformed"},
		{name: "panic", panics: true, reason: "panic"},
		{name: "wrapped failure", err: fmt.Errorf("outer: %w", &DetectorFailure{Reason: FailureBudget}), reason: "budget"},
		{name: "unknown reason normalises to error", err: &DetectorFailure{Reason: "bogus"}, reason: "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counters := NewCounters()
			evaluator := &stubRequestEvaluator{err: tc.err, panics: tc.panics}
			plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: evaluator, Counters: counters})
			response := httptest.NewRecorder()
			plane.ServeHTTP(response, dataPlanePost(valid, "application/json", true))

			fields := requireRefusal(t, response, http.StatusForbidden)
			if fields["error"] != "plugin_failure" {
				t.Errorf("refusal error = %q, want plugin_failure", fields["error"])
			}
			if fields["reason"] != tc.reason {
				t.Errorf("refusal reason = %q, want %q", fields["reason"], tc.reason)
			}
			if bytes.Contains(response.Body.Bytes(), []byte(dataPlaneSecret)) || bytes.Contains(response.Body.Bytes(), []byte("exploded")) {
				t.Errorf("the refusal body leaked content: %q", response.Body.String())
			}
			if got := evaluator.calls.Load(); got != 1 {
				t.Errorf("evaluator calls = %d, want exactly 1", got)
			}
			requireNoUpstream(t, upstream, recorder)
			requireCounters(t, counters, 1, 0, 0)
		})
	}
}

// TestDataPlaneWalkerPanicFailsClosed: a panicking walker is a detection
// failure, so it is a 403 plugin_failure/panic rather than a 400.
func TestDataPlaneWalkerPanicFailsClosed(t *testing.T) {
	counters := NewCounters()
	walker := &stubWalker{fn: func([]byte) ([]protocol.Leaf, error) { panic("walker panic") }}
	plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker, Counters: counters})
	response := httptest.NewRecorder()
	plane.ServeHTTP(response, dataPlanePost(`{"a":"b"}`, "application/json", true))

	fields := requireRefusal(t, response, http.StatusForbidden)
	if fields["error"] != "plugin_failure" || fields["reason"] != "panic" {
		t.Errorf("refusal = %v, want plugin_failure/panic", fields)
	}
	requireNoUpstream(t, upstream, recorder)
	requireCounters(t, counters, 1, 0, 0)
}

// TestDataPlaneDetectorTimeoutFailsClosed: a detector that outlives the
// pkg/config-derived bound is a 403 plugin_failure/timeout with zero upstream
// bytes.
func TestDataPlaneDetectorTimeoutFailsClosed(t *testing.T) {
	counters := NewCounters()
	evaluator := &stubRequestEvaluator{hang: make(chan struct{})}
	plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{
		Evaluator: evaluator, Counters: counters, Timeout: 50 * time.Millisecond,
	})
	response := httptest.NewRecorder()
	plane.ServeHTTP(response, dataPlanePost(`{"a":"b"}`, "application/json", true))

	fields := requireRefusal(t, response, http.StatusForbidden)
	if fields["error"] != "plugin_failure" || fields["reason"] != "timeout" {
		t.Errorf("refusal = %v, want plugin_failure/timeout", fields)
	}
	if got := evaluator.calls.Load(); got != 1 {
		t.Errorf("evaluator calls = %d, want exactly 1", got)
	}
	requireNoUpstream(t, upstream, recorder)
	requireCounters(t, counters, 1, 0, 0)
}

// TestDataPlaneRuleBlockRefusesWithRuleID: a request-scoped Block -- including
// a global blocklist literal, reported as the rule id "blocklist" -- is a 403
// naming the id with zero upstream bytes and both content counters moved.
func TestDataPlaneRuleBlockRefusesWithRuleID(t *testing.T) {
	valid := `{"message":"` + dataPlaneSecret + `"}`
	for _, tc := range []struct {
		name   string
		action RequestAction
		ruleID string
	}{
		{name: "request-scoped rule", action: RequestBlock, ruleID: "qa-block-rule"},
		{name: "global blocklist literal", action: RequestBlock, ruleID: "blocklist"},
		{name: "an undefined action fails closed", action: RequestAction("redact"), ruleID: "rule-undefined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counters := NewCounters()
			evaluator := &stubRequestEvaluator{decision: RequestDecision{Action: tc.action, RuleIDs: []string{tc.ruleID}}}
			plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: evaluator, Counters: counters})
			response := httptest.NewRecorder()
			plane.ServeHTTP(response, dataPlanePost(valid, "application/json", true))

			fields := requireRefusal(t, response, http.StatusForbidden)
			if fields["error"] != "rule_blocked" {
				t.Errorf("refusal error = %q, want rule_blocked", fields["error"])
			}
			if fields["rule_id"] != tc.ruleID {
				t.Errorf("refusal rule_id = %q, want %q", fields["rule_id"], tc.ruleID)
			}
			if bytes.Contains(response.Body.Bytes(), []byte(dataPlaneSecret)) {
				t.Error("the refusal body carries matched content")
			}
			requireNoUpstream(t, upstream, recorder)
			requireCounters(t, counters, 1, 1, 0)
		})
	}
}

// TestDataPlaneForwardingIsByteIdentical: an admitted request reaches the
// upstream with the identical bytes and the walked leaves are what the
// evaluator sees, not the raw body.
func TestDataPlaneForwardingIsByteIdentical(t *testing.T) {
	t.Run("non-JSON body", func(t *testing.T) {
		body := "some,non-json\tbytes\x00with binary"
		counters := NewCounters()
		walker := &stubWalker{}
		evaluator := allowRequestEvaluator()
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker, Evaluator: evaluator, Counters: counters})
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, dataPlanePost(body, "application/octet-stream", true))

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.Code)
		}
		if got := requireUpstream(t, upstream); string(got.body) != body {
			t.Errorf("upstream body = %q, want the identical %q", got.body, body)
		}
		if got := walker.calls.Load(); got != 0 {
			t.Errorf("walker calls = %d, want 0", got)
		}
		if got := evaluator.calls.Load(); got != 0 {
			t.Errorf("evaluator calls = %d, want 0", got)
		}
		if got := recorder.count(); got != 1 {
			t.Errorf("upstream dials = %d, want exactly 1", got)
		}
		requireCounters(t, counters, 0, 0, 0)
	})

	t.Run("declared JSON with an allow verdict", func(t *testing.T) {
		body := `{"message":"` + dataPlaneSecret + `"}`
		counters := NewCounters()
		walker := &stubWalker{}
		evaluator := allowRequestEvaluator()
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker, Evaluator: evaluator, Counters: counters})
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, dataPlanePost(body, "application/json", true))

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.Code)
		}
		if got := requireUpstream(t, upstream); string(got.body) != body {
			t.Errorf("upstream body = %q, want the identical body", got.body)
		}
		seen := evaluator.leaves()
		if len(seen) != 1 || len(seen[0]) != 1 || string(seen[0][0].Value) != dataPlaneSecret {
			t.Errorf("evaluator saw %v, want one leaf carrying the body value", seen)
		}
		if got := recorder.count(); got != 1 {
			t.Errorf("upstream dials = %d, want exactly 1", got)
		}
		requireCounters(t, counters, 0, 0, 0)
	})
}

// TestDataPlaneEncodedRequestGoesStraightToTheForwarder: a non-identity
// Content-Encoding is the forwarder's 415, produced before a byte is read; the
// data plane must not consume the body on the way.
func TestDataPlaneEncodedRequestGoesStraightToTheForwarder(t *testing.T) {
	counters := NewCounters()
	walker := &stubWalker{}
	plane, _, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker, Evaluator: allowRequestEvaluator(), Counters: counters})
	body := &countingBody{data: []byte(`{"message":"` + dataPlaneSecret + `"}`)}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	response := httptest.NewRecorder()
	plane.ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", response.Code)
	}
	if got := body.bytesRead(); got != 0 {
		t.Errorf("the data plane read %d body bytes of an encoded request, want 0", got)
	}
	if got := walker.calls.Load(); got != 0 {
		t.Errorf("walker calls = %d, want 0", got)
	}
	if got := recorder.count(); got != 0 {
		t.Errorf("upstream dials = %d, want 0", got)
	}
	requireCounters(t, counters, 0, 0, 0)
}

// TestPerLeafBudgetTruncatesOnlyTheOverBudgetLeaf pins the scan-budget
// semantics that remain after the aggregate refusal was removed: the budget is
// per leaf and per primitive, so a leaf longer than the budget is inspected
// only over its first budget bytes, and a sibling leaf inside the budget is
// scanned whole. It composes the real detection stack exactly as internal/cli
// does -- registry, built-ins with an explicit small budget, action policy --
// and decides over the walked leaves.
func TestPerLeafBudgetTruncatesOnlyTheOverBudgetLeaf(t *testing.T) {
	// The address is assembled from fragments so no email-shaped literal sits
	// in the source.
	secret := "budget" + "-probe" + "@" + "fauxmail" + ".com"
	const budget = 64

	// Given two string leaves: A carries the address only past the budget, B
	// carries it at its start.
	type twoLeaves struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	body, err := json.Marshal(twoLeaves{A: strings.Repeat("A", 2*budget) + " " + secret, B: secret})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	registry := filter.NewRegistry()
	if err := registry.RegisterBuiltin(filter.BuiltinDetectorsBudget(budget)...); err != nil {
		t.Fatalf("RegisterBuiltin: %v", err)
	}
	policy := filter.NewPolicy(registry, filter.PolicyConfig{Timeout: config.DetectorTimeout})

	// When the walked leaves are evaluated on the request phase.
	leaves, err := protocol.Walk(body)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(leaves) != 2 {
		t.Fatalf("Walk returned %d leaves, want 2: %s", len(leaves), body)
	}
	decision, err := policy.Decide(leaves, filter.ScopeRequest)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}

	// Then only the in-budget sibling was seen: exactly one substitution, and
	// it is leaf B's, even though leaf A spells the same address past its
	// truncation point.
	leafB := -1
	for i := range leaves {
		if string(leaves[i].Value) == secret {
			leafB = i
		}
	}
	if leafB < 0 {
		t.Fatalf("no leaf carries the address at its start: %+v", leaves)
	}
	leafA := 1 - leafB
	if got := len(leaves[leafA].Value); got <= budget {
		t.Fatalf("the over-budget leaf is %d bytes, want more than the %d-byte budget", got, budget)
	}
	at := strings.Index(string(leaves[leafA].Value), secret)
	if at < 0 {
		t.Fatalf("the over-budget leaf does not carry the address at all")
	}
	if at <= budget {
		t.Fatalf("the over-budget leaf spells the address at byte %d, want it past the %d-byte truncation point", at, budget)
	}
	if decision.Action != filter.ActionRedact {
		t.Fatalf("decision action = %q, want %q", decision.Action, filter.ActionRedact)
	}
	if len(decision.Substitutions) != 1 {
		t.Fatalf("substitutions = %d, want exactly 1: the truncated tail of leaf A must not be seen (%+v)", len(decision.Substitutions), decision.Substitutions)
	}
	got := decision.Substitutions[0]
	if got.LeafIndex != leafB || got.Start != 0 || got.End != len(secret) || got.Category != filter.CategoryEmail {
		t.Fatalf("substitution = %+v, want leaf %d spanning [0,%d) as %s", got, leafB, len(secret), filter.CategoryEmail)
	}
	if spelled := string(leaves[leafB].Value[got.Start:got.End]); spelled != secret {
		t.Errorf("the substitution span spells %q, want the in-budget address", spelled)
	}
}

// failingBody always fails its read, so the forwarder's 400 unreadable-body
// refusal is reachable without a real transport fault.
type failingBody struct{}

// Read implements io.Reader.
func (failingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// Close implements io.Closer.
func (failingBody) Close() error { return nil }

// refusalCapture collects the NoticeWriter stream so a test can assert the
// exact refusal lines one request produced. Every refusal under test is served
// synchronously on the calling goroutine, so no lock is needed.
type refusalCapture struct {
	buf bytes.Buffer
}

// Write implements io.Writer.
func (c *refusalCapture) Write(p []byte) (int, error) { return c.buf.Write(p) }

// captureRefusals points the shared NoticeWriter at a fresh capture for the
// rest of the test and restores it afterwards, exactly as listen_test.go does.
func captureRefusals(t *testing.T) *refusalCapture {
	t.Helper()
	capture := &refusalCapture{}
	previous := NoticeWriter
	NoticeWriter = capture
	t.Cleanup(func() { NoticeWriter = previous })
	return capture
}

// requireOneRefusalLine asserts the capture holds exactly one refusal line,
// byte-identical to want, and that no marker literal from the request reached
// it. One line per refusal is the contract: a second line is a defect.
func requireOneRefusalLine(t *testing.T, capture *refusalCapture, want, marker string) {
	t.Helper()
	got := capture.buf.String()
	if marker != "" && strings.Contains(got, marker) {
		t.Errorf("the refusal log carries request content: %q", got)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("refusal lines = %q, want exactly one line %q", got, want)
	}
}

// TestRefusalsLogExactlyOneMetadataOnlyLine pins the observability contract for
// every request-side locally generated refusal: exactly one line naming the
// refusal code, plus the classified reason or the rule id where the refusal
// already carries one. The line is metadata only, so a distinctive marker
// literal planted in the request body must never appear in it.
func TestRefusalsLogExactlyOneMetadataOnlyLine(t *testing.T) {
	blockedBody := `{"message":"` + dataPlaneSecret + `"}`
	for _, tc := range []struct {
		name   string
		want   string
		marker string
		serve  func(t *testing.T)
	}{
		{
			name:   "data plane body_too_large",
			want:   "tokenhush: refused request body_too_large",
			marker: dataPlaneSecret,
			serve: func(t *testing.T) {
				plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: allowRequestEvaluator(), MaxBodyBytes: 8})
				request := dataPlanePost(blockedBody, "application/json", true)
				request.ContentLength = -1
				response := httptest.NewRecorder()
				plane.ServeHTTP(response, request)
				requireRefusal(t, response, http.StatusForbidden)
				requireNoUpstream(t, upstream, recorder)
			},
		},
		{
			name:   "data plane plugin_failure carries its reason",
			want:   "tokenhush: refused request plugin_failure reason=timeout",
			marker: dataPlaneSecret,
			serve: func(t *testing.T) {
				evaluator := &stubRequestEvaluator{err: &DetectorFailure{RuleID: "rule-timeout", Reason: FailureTimeout}}
				plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: evaluator})
				response := httptest.NewRecorder()
				plane.ServeHTTP(response, dataPlanePost(blockedBody, "application/json", true))
				requireRefusal(t, response, http.StatusForbidden)
				requireNoUpstream(t, upstream, recorder)
			},
		},
		{
			name:   "data plane unwalkable_json",
			want:   "tokenhush: refused request unwalkable_json",
			marker: dataPlaneSecret,
			serve: func(t *testing.T) {
				walker := &stubWalker{fn: func([]byte) ([]protocol.Leaf, error) { return nil, errors.New("walker exploded") }}
				plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker})
				response := httptest.NewRecorder()
				plane.ServeHTTP(response, dataPlanePost(blockedBody, "application/json", true))
				requireRefusal(t, response, http.StatusBadRequest)
				requireNoUpstream(t, upstream, recorder)
			},
		},
		{
			name:   "data plane rule block carries the rule id",
			want:   "tokenhush: refused request rule_blocked rule_id=qa-block-rule",
			marker: dataPlaneSecret,
			serve: func(t *testing.T) {
				evaluator := &stubRequestEvaluator{decision: RequestDecision{Action: RequestBlock, RuleIDs: []string{"qa-block-rule"}}}
				plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: evaluator})
				response := httptest.NewRecorder()
				plane.ServeHTTP(response, dataPlanePost(blockedBody, "application/json", true))
				requireRefusal(t, response, http.StatusForbidden)
				requireNoUpstream(t, upstream, recorder)
			},
		},
		{
			name: "forwarder body_too_large",
			want: "tokenhush: refused request body_too_large",
			serve: func(t *testing.T) {
				recorder := &dialRecorder{}
				forwarder, err := NewForwarder("http://upstream.test", nil, WithDialFunc(recorder.dial()), WithMaxBodyBytes(8))
				if err != nil {
					t.Fatalf("NewForwarder: %v", err)
				}
				request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(blockedBody))
				request.ContentLength = -1
				response := httptest.NewRecorder()
				forwarder.ServeHTTP(response, request)
				requireRefusal(t, response, http.StatusForbidden)
				if got := recorder.count(); got != 0 {
					t.Errorf("upstream dials = %d, want 0", got)
				}
			},
		},
		{
			name:   "forwarder 415 unsupported media type",
			want:   "tokenhush: refused request unsupported_media_type",
			marker: dataPlaneSecret,
			serve: func(t *testing.T) {
				forwarder, recorder := recordedForwarder(t, nil, nil)
				body := &countingBody{data: []byte(blockedBody)}
				request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
				request.Header.Set("Content-Encoding", "gzip")
				response := httptest.NewRecorder()
				forwarder.ServeHTTP(response, request)
				if response.Code != http.StatusUnsupportedMediaType {
					t.Errorf("status = %d, want 415", response.Code)
				}
				if got := body.bytesRead(); got != 0 {
					t.Errorf("body bytes read = %d, want 0", got)
				}
				if got := recorder.count(); got != 0 {
					t.Errorf("upstream dials = %d, want 0", got)
				}
			},
		},
		{
			name: "forwarder 400 unreadable body",
			want: "tokenhush: refused request unreadable_body",
			serve: func(t *testing.T) {
				forwarder, recorder := recordedForwarder(t, nil, nil)
				request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", failingBody{})
				response := httptest.NewRecorder()
				forwarder.ServeHTTP(response, request)
				if response.Code != http.StatusBadRequest {
					t.Errorf("status = %d, want 400", response.Code)
				}
				if got := recorder.count(); got != 0 {
					t.Errorf("upstream dials = %d, want 0", got)
				}
			},
		},
		{
			name: "forwarder 500 transform error",
			want: "tokenhush: refused request transform_error",
			serve: func(t *testing.T) {
				forwarder, recorder := recordedForwarder(t, nil, func([]byte) ([]byte, error) { return nil, errors.New("transform refused") })
				response := httptest.NewRecorder()
				forwarder.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader("payload")))
				if response.Code != http.StatusInternalServerError {
					t.Errorf("status = %d, want 500", response.Code)
				}
				if got := recorder.count(); got != 0 {
					t.Errorf("upstream dials = %d, want 0", got)
				}
			},
		},
		{
			name: "forwarder 500 request build error",
			want: "tokenhush: refused request request_build_error",
			serve: func(t *testing.T) {
				forwarder, recorder := recordedForwarder(t, nil, nil)
				request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
				request.Method = "BAD METHOD"
				response := httptest.NewRecorder()
				forwarder.ServeHTTP(response, request)
				if response.Code != http.StatusInternalServerError {
					t.Errorf("status = %d, want 500", response.Code)
				}
				if got := recorder.count(); got != 0 {
					t.Errorf("upstream dials = %d, want 0", got)
				}
			},
		},
		{
			name: "forwarder 502 bad gateway",
			want: "tokenhush: refused request bad_gateway",
			serve: func(t *testing.T) {
				forwarder, _ := recordedForwarder(t, nil, nil)
				response := httptest.NewRecorder()
				forwarder.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`)))
				if response.Code != http.StatusBadGateway {
					t.Errorf("status = %d, want 502", response.Code)
				}
			},
		},
		{
			name: "forwarder 504 gateway timeout",
			want: "tokenhush: refused request gateway_timeout",
			serve: func(t *testing.T) {
				forwarder, _ := recordedForwarder(t, nil, nil)
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`)).WithContext(ctx)
				response := httptest.NewRecorder()
				forwarder.ServeHTTP(response, request)
				if response.Code != http.StatusGatewayTimeout {
					t.Errorf("status = %d, want 504", response.Code)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := captureRefusals(t)
			tc.serve(t)
			requireOneRefusalLine(t, capture, tc.want, tc.marker)
		})
	}
}
