package proxy

// W1.4 regressions: an unparseable client-bound body used to be skipped
// silently. These tests pin the observability that replaces the silence — the
// Pipeline.ResponseWalkFailures counter and the metadata-only RedactionEvents —
// while proving the response and SSE paths keep their frozen behaviour: no
// fail-closed, byte-identical output, and `data: [DONE]`/ping passthrough.
// See transformResponse and noteResponseWalkFailure for the rationale.

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
)

// w14UnparseableBody is a non-empty body no leaf walk can parse. Plain text is
// enough: the walker rejects anything that is not a single JSON document.
var w14UnparseableBody = []byte("plain-text upstream error: not JSON")

// w14Reporter returns a reporter that records every event it receives.
func w14Reporter() (RedactionReporter, *[]RedactionEvent) {
	events := &[]RedactionEvent{}
	return func(ev RedactionEvent) { *events = append(*events, ev) }, events
}

// w14SSEWriter returns a response writer switched into SSE streaming mode, so
// w.backfill is the backfiller the pipeline itself created and wired.
func w14SSEWriter(t *testing.T, pipe *Pipeline) (*pipelineResponseWriter, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	w := &pipelineResponseWriter{pipeline: pipe, dst: rec, status: http.StatusOK}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if w.backfill == nil {
		t.Fatal("SSE WriteHeader did not install a backfiller")
	}
	return w, rec
}

// w14DesyncEvent builds a held JSON event whose payload cannot be walked. It
// models the only way the emit-time desync guard can fire: the payload was
// walked when it was fed, so a later disagreement between the held edits and
// the raw bytes is a bug-shaped state, not a provider response.
func w14DesyncEvent() *heldEvent {
	const payload = "plain-text-desync"
	return &heldEvent{
		raw:       []byte("data: " + payload + "\n\n"),
		dataOff:   len("data: "),
		dataLen:   len(payload),
		kind:      kindJSON,
		jsonEdits: map[string]string{"/delta/content": "rewritten"},
	}
}

// TestPipelineResponseWalkFailureObservable pins the buffered response path: an
// unparseable body is skipped (never fail-closed) but the skip is counted and
// reported exactly once as a metadata-only event, and the output is
// byte-identical to the plain backfill.
func TestPipelineResponseWalkFailureObservable(t *testing.T) {
	t.Run("counts_reports_and_stays_byte_identical", func(t *testing.T) {
		engine := w45Engine(t)
		pipe := w45Pipeline(t, PipelineConfig{Engine: engine, Tool: "w1.4-response"})
		reporter, events := w14Reporter()
		pipe.SetRedactionReporter(reporter)

		// The body is not JSON but still carries a placeholder, so the test
		// proves the skip kept running backfill on the way to the client.
		body := append([]byte("prefix "), []byte(engine.Placeholder(w45Secret(), "api_key"))...)
		body = append(body, []byte(" suffix")...)

		before := pipe.ResponseWalkFailures()
		got, err := pipe.transformResponse(body, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse(unparseable) = %v, want nil error (the response path is not fail-closed)", err)
		}
		if want := pipe.backfill(body); !bytes.Equal(got, want) {
			t.Fatalf("output = %q, want the backfilled body %q", got, want)
		}
		if !bytes.Contains(got, []byte(w45Secret())) {
			t.Fatalf("output did not backfill the placeholder: %q", got)
		}
		if after := pipe.ResponseWalkFailures(); after != before+1 {
			t.Fatalf("ResponseWalkFailures = %d, want %d", after, before+1)
		}
		if len(*events) != 1 {
			t.Fatalf("reporter events = %d (%+v), want exactly 1", len(*events), *events)
		}
		wantEvent := RedactionEvent{
			Action:    RedactionActionResponseWalkFailed,
			Direction: RedactionDirectionResponse,
			Phase:     extension.ResponseContent.String(),
		}
		if gotEvent := (*events)[0]; gotEvent != wantEvent {
			t.Fatalf("event = %+v, want %+v (no content, type, length or masked fields)", gotEvent, wantEvent)
		}
	})

	t.Run("parseable_body_is_not_counted", func(t *testing.T) {
		// Control: the counter is tied to walk failures, never to every
		// response that passes through the inbound path.
		engine := w45Engine(t)
		pipe := w45Pipeline(t, PipelineConfig{Engine: engine, Tool: "w1.4-control"})
		reporter, events := w14Reporter()
		pipe.SetRedactionReporter(reporter)

		if _, err := pipe.transformResponse([]byte(`{"ok":true}`), pipe.tool); err != nil {
			t.Fatalf("transformResponse(valid JSON) = %v", err)
		}
		if got := pipe.ResponseWalkFailures(); got != 0 {
			t.Fatalf("ResponseWalkFailures = %d for a parseable body, want 0", got)
		}
		if len(*events) != 0 {
			t.Fatalf("reporter events = %d for a parseable body, want 0", len(*events))
		}
	})

	t.Run("counts_without_a_reporter", func(t *testing.T) {
		// The pre-existing contract holds: with no reporter installed there is
		// no event and no panic, yet the counter still increments.
		engine := w45Engine(t)
		pipe := w45Pipeline(t, PipelineConfig{Engine: engine, Tool: "w1.4-nil-reporter"})
		for i := 0; i < 3; i++ {
			if _, err := pipe.transformResponse(w14UnparseableBody, pipe.tool); err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
		}
		if got := pipe.ResponseWalkFailures(); got != 3 {
			t.Fatalf("ResponseWalkFailures = %d after 3 skips, want 3", got)
		}
	})

	t.Run("nil_receiver_accessor_returns_zero", func(t *testing.T) {
		var pipe *Pipeline
		if got := pipe.ResponseWalkFailures(); got != 0 {
			t.Fatalf("(*Pipeline)(nil).ResponseWalkFailures() = %d, want 0", got)
		}
	})
}

// TestPipelineSSEWalkFailureObservable pins the SSE emit-time desync guard: a
// held JSON event whose payload can no longer be walked is counted and
// reported, and its original bytes are written verbatim so a desync can never
// produce a half-spliced record.
func TestPipelineSSEWalkFailureObservable(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Engine: engine, Tool: "w1.4-sse"})
	reporter, events := w14Reporter()
	pipe.SetRedactionReporter(reporter)

	w, rec := w14SSEWriter(t, pipe)
	he := w14DesyncEvent()

	before := pipe.ResponseWalkFailures()
	if err := w.backfill.emit(he); err != nil {
		t.Fatalf("emit(desync event) = %v, want nil", err)
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, he.raw) {
		t.Fatalf("fallback output = %q, want the original event bytes %q", got, he.raw)
	}
	if got := pipe.ResponseWalkFailures(); got != before+1 {
		t.Fatalf("ResponseWalkFailures = %d, want %d", got, before+1)
	}
	if len(*events) != 1 {
		t.Fatalf("reporter events = %d (%+v), want exactly 1", len(*events), *events)
	}
	wantEvent := RedactionEvent{
		Action:    RedactionActionSSEWalkFailed,
		Direction: RedactionDirectionResponse,
		Phase:     extension.ResponseContent.String(),
	}
	if gotEvent := (*events)[0]; gotEvent != wantEvent {
		t.Fatalf("event = %+v, want %+v", gotEvent, wantEvent)
	}
}

// TestPipelineSSEPassthroughStaysUncounted proves the streams the plan
// explicitly protects: comment/ping lines, `data: [DONE]` and ordinary JSON
// deltas flow through byte-identical and do NOT count as walk failures. A
// non-JSON payload takes the documented kindRaw passthrough, not the desync
// guard, so it must not be reported either.
func TestPipelineSSEPassthroughStaysUncounted(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Engine: engine, Tool: "w1.4-sse-passthrough"})
	reporter, events := w14Reporter()
	pipe.SetRedactionReporter(reporter)

	w, rec := w14SSEWriter(t, pipe)

	input := []byte(": ping\n\ndata: [DONE]\n\ndata: {\"delta\":{\"content\":\"plain\"}}\n\n")
	if _, err := w.backfill.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.backfill.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, input) {
		t.Fatalf("passthrough output = %q, want %q", got, input)
	}
	if got := pipe.ResponseWalkFailures(); got != 0 {
		t.Fatalf("ResponseWalkFailures = %d for pure passthrough, want 0", got)
	}
	if len(*events) != 0 {
		t.Fatalf("reporter events = %d for pure passthrough, want 0", len(*events))
	}
}

// TestSSEBackfillerWalkFailureObserver pins the optional observer on a
// directly-constructed backfiller (the eight test call-sites keep the
// three-argument constructor): the setter is nil-safe, the observer receives
// the walker error (never payload bytes), and a nil observer stays a safe
// no-op.
func TestSSEBackfillerWalkFailureObserver(t *testing.T) {
	t.Run("observer_receives_walk_error", func(t *testing.T) {
		var dst bytes.Buffer
		b := newSSEBackfiller(&dst, 128, t4Replace)
		var observed []error
		b.setWalkFailureObserver(func(err error) { observed = append(observed, err) })
		if err := b.emit(w14DesyncEvent()); err != nil {
			t.Fatalf("emit: %v", err)
		}
		if len(observed) != 1 || !errors.Is(observed[0], protocol.ErrMalformedJSON) {
			t.Fatalf("observed = %v, want exactly one protocol.ErrMalformedJSON", observed)
		}
		if got := dst.String(); got != "data: plain-text-desync\n\n" {
			t.Fatalf("output = %q, want the original bytes", got)
		}
	})

	t.Run("nil_observer_is_a_noop", func(t *testing.T) {
		var dst bytes.Buffer
		b := newSSEBackfiller(&dst, 128, t4Replace)
		if err := b.emit(w14DesyncEvent()); err != nil {
			t.Fatalf("emit: %v", err)
		}
		if got := dst.String(); got != "data: plain-text-desync\n\n" {
			t.Fatalf("output = %q, want the original bytes", got)
		}
	})

	t.Run("setter_is_nil_safe_and_clearable", func(t *testing.T) {
		var nilB *sseBackfiller
		nilB.setWalkFailureObserver(func(error) { t.Fatal("unreachable") }) // must not panic

		var dst bytes.Buffer
		b := newSSEBackfiller(&dst, 128, t4Replace)
		calls := 0
		b.setWalkFailureObserver(func(error) { calls++ })
		b.setWalkFailureObserver(nil)
		if err := b.emit(w14DesyncEvent()); err != nil {
			t.Fatalf("emit: %v", err)
		}
		if calls != 0 {
			t.Fatalf("cleared observer was called %d times", calls)
		}
	})

	t.Run("edit_free_event_does_not_walk", func(t *testing.T) {
		// No jsonEdits -> emit copies the raw event without walking, so a
		// non-JSON payload held this way is not a walk failure.
		var dst bytes.Buffer
		b := newSSEBackfiller(&dst, 128, t4Replace)
		calls := 0
		b.setWalkFailureObserver(func(error) { calls++ })
		he := w14DesyncEvent()
		he.jsonEdits = nil
		if err := b.emit(he); err != nil {
			t.Fatalf("emit: %v", err)
		}
		if calls != 0 {
			t.Fatalf("observer called %d times for an edit-free event, want 0", calls)
		}
	})
}

// TestPipelineResponsePathIsNotFailClosed pins the frozen asymmetry with the
// request path (W1.3): an unparseable request body reports ErrUnwalkableBody
// at the pipeline seam (pinned by TestPipelineMalformedInputPassthrough;
// deliberately not re-tested here), while the response path returns the body
// unchanged and a nil error. Do not "unify" them: response and SSE are
// client-bound directions, and failing closed would break legitimate
// plain-text responses.
func TestPipelineResponsePathIsNotFailClosed(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Engine: engine, Tool: "w1.4-asymmetry"})
	out, err := pipe.transformResponse(w14UnparseableBody, pipe.tool)
	if err != nil {
		t.Fatalf("transformResponse(unparseable) error = %v, want nil (not fail-closed)", err)
	}
	if !bytes.Equal(out, w14UnparseableBody) {
		t.Fatalf("output = %q, want the unchanged body %q", out, w14UnparseableBody)
	}
}
