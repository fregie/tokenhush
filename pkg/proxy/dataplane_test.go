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

// TestDataPlaneScanBudgetIsDeterministic: the aggregate per-request scan-budget
// refusal is gone, so a declared-JSON body over the old scan budget is walked
// and forwarded like any other while a non-JSON body is still never walked. The
// per-leaf scan budget stays in pkg/filter and internal/cli; the bridge cases
// here are rewritten for the new body-size semantics in the next change.
func TestDataPlaneScanBudgetIsDeterministic(t *testing.T) {
	valid := `{"message":"` + strings.Repeat("x", 64) + `"}`

	t.Run("over the old aggregate budget is admitted", func(t *testing.T) {
		counters := NewCounters()
		walker := &stubWalker{}
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{
			Walker: walker, Evaluator: allowRequestEvaluator(), Counters: counters, Budget: 16,
		})
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, dataPlanePost(valid, "application/json", true))

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: the aggregate gate is gone (body %q)", response.Code, response.Body.String())
		}
		if got := requireUpstream(t, upstream); string(got.body) != valid {
			t.Errorf("upstream body = %q, want the identical body", got.body)
		}
		if got := walker.calls.Load(); got != 1 {
			t.Errorf("walker calls = %d, want 1: the body is scanned, not skipped", got)
		}
		if got := recorder.count(); got != 1 {
			t.Errorf("upstream dials = %d, want exactly 1", got)
		}
		requireCounters(t, counters, 0, 0, 0)
	})

	t.Run("exactly at budget", func(t *testing.T) {
		counters := NewCounters()
		walker := &stubWalker{}
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{
			Walker: walker, Evaluator: allowRequestEvaluator(), Counters: counters, Budget: int64(len(valid)),
		})
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, dataPlanePost(valid, "application/json", true))

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 at exactly the budget", response.Code)
		}
		if got := requireUpstream(t, upstream); string(got.body) != valid {
			t.Errorf("upstream body = %q, want the identical body", got.body)
		}
		if got := recorder.count(); got != 1 {
			t.Errorf("upstream dials = %d, want exactly 1", got)
		}
		if got := walker.calls.Load(); got != 1 {
			t.Errorf("walker calls = %d, want 1", got)
		}
		requireCounters(t, counters, 0, 0, 0)
	})

	t.Run("a non-JSON body is never budgeted", func(t *testing.T) {
		body := strings.Repeat("x", 4096)
		counters := NewCounters()
		walker := &stubWalker{}
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{
			Walker: walker, Evaluator: allowRequestEvaluator(), Counters: counters, Budget: 16,
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
