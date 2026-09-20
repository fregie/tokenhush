package proxy

// response_sse_buffered_test.go is the Wave-1 red-first regression suite for
// the whole-response buffered SSE path (plan todo 5). Every test compiles
// against the HandleBufferedSSE skeleton and fails on its assertions until todo
// 18 implements decode, evaluation and restore. The frozen counter contract
// (B-FD6) is: json.Valid(ev.Data) gates evaluation; a JSON event whose Walk
// fails counts exactly one walk_skip; non-JSON, [DONE], ping/comment,
// comment-only and zero-leaf events count zero; Block/Warn counters and warning
// lines move exactly once for the aggregate with rule ids deduped and sorted.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"testing"
)

// sseUpstreamResponse builds one upstream text/event-stream response with the
// given status, Content-Encoding and raw (possibly still encoded) body.
func sseUpstreamResponse(t *testing.T, status int, encoding string, body []byte) *http.Response {
	t.Helper()
	header := make(http.Header)
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	if encoding != "" {
		header.Set("Content-Encoding", encoding)
	}
	return &http.Response{
		StatusCode:    status,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// sseHandle drives one buffered SSE response through the handler and fails the
// test on a handler error.
func sseHandle(t *testing.T, handler *ResponseHandler, status int, encoding string, stream []byte) (int, http.Header, []byte) {
	t.Helper()
	code, header, body, err := handler.HandleBufferedSSE(sseUpstreamResponse(t, status, encoding, stream))
	if err != nil {
		t.Fatalf("HandleBufferedSSE: %v", err)
	}
	return code, header, body
}

// sseContentEvent renders one SSE delta record whose JSON envelope carries a
// single "content" string member.
func sseContentEvent(t *testing.T, content string) string {
	t.Helper()
	value, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("Marshal content: %v", err)
	}
	return sseRecord("delta", `{"content":`+string(value)+`}`)
}

// sseContentOf decodes the single "content" member of one envelope.
func sseContentOf(t *testing.T, data []byte) string {
	t.Helper()
	var doc struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Unmarshal envelope %q: %v", data, err)
	}
	return doc.Content
}

// TestResponseBufferSSENonJSONEventsDoNotWalkSkip: a buffered SSE stream whose
// non-JSON records are a ping, a comment, a plain non-JSON data value and
// [DONE] evaluates only the valid-JSON event, so walk_skips stays at 0 and the
// stream round-trips byte-identically.
func TestResponseBufferSSENonJSONEventsDoNotWalkSkip(t *testing.T) {
	evaluator := allowEvaluator()
	counters := NewCounters()
	handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: counters})

	jsonEvent := sseContentEvent(t, "hello")
	stream := jsonEvent +
		"data: [DONE]\n\n" +
		"event: ping\ndata: alive\n\n" +
		": keepalive\n\n" +
		sseRecord("delta", "not json at all")

	status, _, body := sseHandle(t, handler, http.StatusOK, "", []byte(stream))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if got := counters.WalkSkips(); got != 0 {
		t.Errorf("WalkSkips = %d, want 0: a non-JSON event must not count a walk skip", got)
	}
	if seen := evaluator.seen(); len(seen) != 1 || string(seen[0]) != `{"content":"hello"}` {
		t.Fatalf("evaluator saw %q, want only the valid-JSON event", seen)
	}
	if !bytes.Equal(body, []byte(stream)) {
		t.Fatalf("stream:\n got %q\nwant %q", body, stream)
	}
}

// TestBufferedSSEMultiDataLineJsonIsEvaluated: a multi-data:-line event whose
// joined Data is valid JSON is evaluated; the single-canonical-data-line
// DataSpans condition must NOT gate evaluation.
func TestBufferedSSEMultiDataLineJsonIsEvaluated(t *testing.T) {
	evaluator := allowEvaluator()
	counters := NewCounters()
	handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: counters})

	// Two data lines join with '\n' into a valid JSON document; the decoder
	// reports no DataSpans for a multi-line record.
	stream := "data: {\"a\":\ndata: 1}\n\n"
	status, _, body := sseHandle(t, handler, http.StatusOK, "", []byte(stream))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	seen := evaluator.seen()
	if len(seen) != 1 {
		t.Fatalf("evaluator saw %d events, want the multi-data-line event exactly once", len(seen))
	}
	if got, want := string(seen[0]), "{\"a\":\n1}"; got != want {
		t.Fatalf("evaluated joined Data = %q, want %q", got, want)
	}
	if got := counters.WalkSkips(); got != 0 {
		t.Errorf("WalkSkips = %d, want 0", got)
	}
	if !bytes.Equal(body, []byte(stream)) {
		t.Fatalf("stream:\n got %q\nwant %q", body, stream)
	}
}

// TestBufferedSSECounterMatrix pins the frozen B-FD6 matrix: non-JSON events are
// never evaluated and count no walk skip; a JSON event whose Walk fails counts
// exactly one walk skip; a Warn aggregate writes deduped, sorted warning lines
// exactly once; a Block aggregate moves both block counters exactly once and
// refuses.
func TestBufferedSSECounterMatrix(t *testing.T) {
	jsonOne := sseContentEvent(t, "one")
	jsonTwo := sseContentEvent(t, "two")
	done := "data: [DONE]\n\n"
	ping := "event: ping\ndata: alive\n\n"
	comment := ": keepalive\n\n"
	nonJSON := sseRecord("delta", "not json at all")

	t.Run("non-JSON events count no walk skip and are not evaluated", func(t *testing.T) {
		evaluator := allowEvaluator()
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: counters})
		stream := done + ping + comment + nonJSON + jsonOne

		status, _, _ := sseHandle(t, handler, http.StatusOK, "", []byte(stream))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want %d", status, http.StatusOK)
		}
		if got := counters.WalkSkips(); got != 0 {
			t.Errorf("WalkSkips = %d, want 0", got)
		}
		if got := counters.ContentPolicyBlocks(); got != 0 {
			t.Errorf("ContentPolicyBlocks = %d, want 0", got)
		}
		if got := counters.RuleBlocks(); got != 0 {
			t.Errorf("RuleBlocks = %d, want 0", got)
		}
		if seen := evaluator.seen(); len(seen) != 1 || string(seen[0]) != `{"content":"one"}` {
			t.Fatalf("evaluator saw %q, want only the valid-JSON event", seen)
		}
	})

	t.Run("a JSON event whose Walk fails counts exactly one walk skip", func(t *testing.T) {
		evaluator := &scriptedEvaluator{err: errors.New("walk: not JSON")}
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: counters})
		stream := nonJSON + jsonOne

		status, _, _ := sseHandle(t, handler, http.StatusOK, "", []byte(stream))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want %d", status, http.StatusOK)
		}
		if got := counters.WalkSkips(); got != 1 {
			t.Errorf("WalkSkips = %d, want exactly 1 for the one JSON event that failed Walk", got)
		}
		if seen := evaluator.seen(); len(seen) != 1 || string(seen[0]) != `{"content":"one"}` {
			t.Fatalf("evaluator saw %q, want only the valid-JSON event", seen)
		}
	})

	t.Run("aggregate Warn writes deduped sorted warnings once", func(t *testing.T) {
		evaluator := &scriptedEvaluator{decision: ResponseDecision{Action: ResponseWarn, RuleIDs: []string{"b", "a", "b"}}}
		counters := NewCounters()
		warnings := &recordingWarnings{}
		handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: counters, Warnings: warnings})
		stream := jsonOne + jsonTwo

		status, _, _ := sseHandle(t, handler, http.StatusOK, "", []byte(stream))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want %d", status, http.StatusOK)
		}
		if got := counters.WalkSkips(); got != 0 {
			t.Errorf("WalkSkips = %d, want 0", got)
		}
		if got := counters.ContentPolicyBlocks(); got != 0 {
			t.Errorf("ContentPolicyBlocks = %d, want 0", got)
		}
		if got := counters.RuleBlocks(); got != 0 {
			t.Errorf("RuleBlocks = %d, want 0", got)
		}
		want := []string{warningPrefix + ` rule="a"`, warningPrefix + ` rule="b"`}
		if got := warnings.seen(); !reflect.DeepEqual(got, want) {
			t.Fatalf("warnings = %q, want %q (deduped, sorted, once for the aggregate)", got, want)
		}
	})

	t.Run("aggregate Block moves both counters once and refuses", func(t *testing.T) {
		evaluator := &scriptedEvaluator{decision: ResponseDecision{Action: ResponseBlock, RuleIDs: []string{"r1", "r2"}}}
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: counters})
		stream := jsonOne + jsonTwo

		status, _, body := sseHandle(t, handler, http.StatusOK, "", []byte(stream))
		if status != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d", status, http.StatusBadGateway)
		}
		if got := counters.ContentPolicyBlocks(); got != 1 {
			t.Errorf("ContentPolicyBlocks = %d, want exactly 1 for the aggregate", got)
		}
		if got := counters.RuleBlocks(); got != 1 {
			t.Errorf("RuleBlocks = %d, want exactly 1 for the aggregate", got)
		}
		if got := counters.WalkSkips(); got != 0 {
			t.Errorf("WalkSkips = %d, want 0", got)
		}
		var ref refusal
		if err := json.Unmarshal(body, &ref); err != nil {
			t.Fatalf("block body is not the refusal document: %q", body)
		}
		if ref.Error != refusalRuleBlocked || ref.RuleID != "r1" {
			t.Fatalf("refusal = %+v, want %s naming r1", ref, refusalRuleBlocked)
		}
	})
}

// TestBufferedSSESplitPlaceholderRestoredOnce: a placeholder split across two
// SSE events is restored exactly once, in the completing event, and every
// emitted envelope stays valid JSON.
func TestBufferedSSESplitPlaceholderRestoredOnce(t *testing.T) {
	secret := []byte("alice@example.com")
	back, placeholder := sseMint(t, secret, "email")
	handler := NewResponseHandler(ResponseConfig{Evaluator: allowEvaluator(), Backfiller: back, Counters: NewCounters()})

	pre, suffix := "say ", " done"
	half := len(placeholder) / 2
	first := sseContentEvent(t, pre+placeholder[:half])
	second := sseContentEvent(t, placeholder[half:]+suffix)
	stream := first + second

	status, _, body := sseHandle(t, handler, http.StatusOK, "", []byte(stream))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if got := bytes.Count(body, secret); got != 1 {
		t.Fatalf("secret appears %d times, want exactly 1 in %q", got, body)
	}
	if bytes.Contains(body, []byte("__PII_")) {
		t.Fatalf("placeholder prefix survived in %q", body)
	}
	events := sseEvents(t, body)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
	}
	got0 := sseContentOf(t, events[0].Data)
	got1 := sseContentOf(t, events[1].Data)
	if got0 != pre {
		t.Fatalf("event 0 content = %q, want %q", got0, pre)
	}
	if want := string(secret) + suffix; got1 != want {
		t.Fatalf("event 1 content = %q, want %q", got1, want)
	}
	if joined := got0 + got1; joined != pre+string(secret)+suffix {
		t.Fatalf("concatenated content = %q, want %q", joined, pre+string(secret)+suffix)
	}
}

// TestBufferedSSEContentEncoding: a gzip-encoded buffered SSE response is
// decoded, its Content-Encoding is removed, and Content-Length is set to the
// restored body length.
func TestBufferedSSEContentEncoding(t *testing.T) {
	secret := []byte("alice@example.com")
	back, placeholder := sseMint(t, secret, "email")
	handler := NewResponseHandler(ResponseConfig{Evaluator: allowEvaluator(), Backfiller: back, Counters: NewCounters()})

	stream := sseContentEvent(t, placeholder)
	encoded := encodeGzip(t, []byte(stream))

	status, header, body := sseHandle(t, handler, http.StatusOK, "gzip", encoded)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if got := header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want it removed after decoding", got)
	}
	if got, want := header.Get("Content-Length"), strconv.Itoa(len(body)); got != want {
		t.Fatalf("Content-Length = %q, want %q (the restored body length)", got, want)
	}
	if got := bytes.Count(body, secret); got != 1 {
		t.Fatalf("secret appears %d times, want exactly 1 in %q", got, body)
	}
	if bytes.Contains(body, []byte("__PII_")) {
		t.Fatalf("placeholder prefix survived in %q", body)
	}
	events := sseEvents(t, body)
	if len(events) != 1 || !json.Valid(events[0].Data) {
		t.Fatalf("decoded body is not one valid JSON SSE event: %q", body)
	}
}

// TestBufferedSSEBlockAllOrNothing: a response-scoped Block on a buffered SSE
// response is a 502 with nothing committed -- no upstream event byte reaches
// the client, only the metadata-only refusal document.
func TestBufferedSSEBlockAllOrNothing(t *testing.T) {
	evaluator := &scriptedEvaluator{decision: ResponseDecision{Action: ResponseBlock, RuleIDs: []string{"pol-1"}}}
	counters := NewCounters()
	handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: counters})

	stream := sseContentEvent(t, "before") + sseContentEvent(t, "after")
	status, header, body := sseHandle(t, handler, http.StatusOK, "", []byte(stream))
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 before any byte is committed", status)
	}
	var ref refusal
	if err := json.Unmarshal(body, &ref); err != nil {
		t.Fatalf("block body is not the refusal document: %q", body)
	}
	if ref.Error != refusalRuleBlocked || ref.RuleID != "pol-1" {
		t.Fatalf("refusal = %+v, want %s naming pol-1", ref, refusalRuleBlocked)
	}
	if bytes.Contains(body, []byte("before")) || bytes.Contains(body, []byte("after")) {
		t.Fatalf("an upstream event byte was committed: %q", body)
	}
	if got := header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := counters.ContentPolicyBlocks(); got != 1 {
		t.Errorf("ContentPolicyBlocks = %d, want 1", got)
	}
	if got := counters.RuleBlocks(); got != 1 {
		t.Errorf("RuleBlocks = %d, want 1", got)
	}
	if got := counters.WalkSkips(); got != 0 {
		t.Errorf("WalkSkips = %d, want 0", got)
	}
}
