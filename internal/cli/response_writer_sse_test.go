package cli

// response_writer_sse_test.go is the F2-1 regression suite: finish() must
// classify an event stream by Content-Type alone, so a gzip/deflate
// text/event-stream reaches ResponseHandler.HandleBufferedSSE instead of the
// ordinary buffered path. Before the fix an encoded stream was sent to
// commitBuffered, which decoded it but evaluated the whole body as one JSON
// document and restored placeholders with a plain byte scan: a response Block
// never fired and a split placeholder was never reassembled.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
)

// encodedSSEBlockingGateway installs a response-scoped keyword Block on top of
// the gateway built over cfg, so a response Block can be driven through route.
func encodedSSEBlockingGateway(t *testing.T, cfg config.Config) *gateway {
	t.Helper()
	gw := redGateway(t, cfg)
	doc := &filter.Document{Rules: []filter.RuleDoc{{
		ID: "resp-block", Type: filter.TypeKeyword, Category: filter.CategoryCustom,
		Scope: filter.ScopeResponse, Action: filter.ActionBlock, Keywords: []string{"BLOCKME"},
	}}}
	compiled, err := filter.Compile(doc)
	if err != nil {
		t.Fatalf("compile blocking rule: %v", err)
	}
	registry := filter.NewRegistry()
	if err := registry.RegisterCompiled(compiled); err != nil {
		t.Fatalf("register blocking rule: %v", err)
	}
	gw.policy = filter.NewPolicy(registry, filter.PolicyConfig{})
	return gw
}

// encodedGzip compresses body into one gzip stream.
func encodedGzip(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// encodedSSEEvent renders one SSE record whose JSON envelope carries a single
// "content" string member.
func encodedSSEEvent(t *testing.T, content string) string {
	t.Helper()
	value, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}
	return "data: {\"content\":" + string(value) + "}\n\n"
}

// encodedUpstream serves one gzip-encoded text/event-stream whose body is
// published through payload before the request is made.
func encodedUpstream(t *testing.T, payload *atomic.Pointer[[]byte]) string {
	t.Helper()
	srv := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		if body := payload.Load(); body != nil {
			_, _ = w.Write(*body)
		}
	})
	return srv.URL
}

// encodedSSEData returns each record's data payload, so a caller can assert the
// emitted envelopes are valid JSON.
func encodedSSEData(t *testing.T, body []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for _, record := range bytes.Split(body, []byte("\n\n")) {
		record = bytes.TrimSpace(record)
		if len(record) == 0 {
			continue
		}
		if !bytes.HasPrefix(record, []byte("data: ")) {
			t.Fatalf("unexpected SSE record %q", record)
		}
		out = append(out, bytes.TrimPrefix(record, []byte("data: ")))
	}
	return out
}

// TestResponseWriterEncodedSSEUsesBufferedSSEPath pins F2-1: a
// Content-Encoding: gzip text/event-stream is classified as an event stream by
// Content-Type, so the buffered SSE path evaluates it event by event and
// restores a placeholder split across events. Both subtests fail while
// streamingSSE still requires an identity encoding.
func TestResponseWriterEncodedSSEUsesBufferedSSEPath(t *testing.T) {
	t.Run("a response Block fires on a gzip-encoded event stream", func(t *testing.T) {
		var payload atomic.Pointer[[]byte]
		target := encodedUpstream(t, &payload)
		compressed := encodedGzip(t, []byte(encodedSSEEvent(t, "BLOCKME")))
		payload.Store(&compressed)

		gw := encodedSSEBlockingGateway(t, redConfig(target))
		rec := redRoute(t, gw, "/v1/chat/completions")
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502: an encoded event stream must run the buffered SSE path", rec.Code)
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("rule_blocked")) {
			t.Errorf("the 502 body does not name the block: %s", rec.Body.Bytes())
		}
		if got := gw.counters.WalkSkips(); got != 0 {
			t.Errorf("walk_skips = %d, want 0: the SSE path evaluated the event, not the whole stream", got)
		}
	})

	t.Run("a split placeholder is restored on a gzip-encoded event stream", func(t *testing.T) {
		var payload atomic.Pointer[[]byte]
		target := encodedUpstream(t, &payload)
		gw := redGateway(t, redConfig(target))

		secret := []byte("hunter2")
		placeholder, err := gw.backfiller.Mint(gw.writer, secret, "custom")
		if err != nil {
			t.Fatalf("mint placeholder: %v", err)
		}
		half := len(placeholder) / 2
		stream := encodedSSEEvent(t, placeholder[:half]) + encodedSSEEvent(t, placeholder[half:])
		compressed := encodedGzip(t, []byte(stream))
		payload.Store(&compressed)

		rec := redRoute(t, gw, "/v1/chat/completions")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.Bytes())
		}
		body := rec.Body.Bytes()
		if got := bytes.Count(body, secret); got != 1 {
			t.Fatalf("the restored secret appears %d times, want exactly 1 in %q", got, body)
		}
		if bytes.Contains(body, []byte("__PII_")) {
			t.Fatalf("a placeholder fragment survived in %q", body)
		}
		events := encodedSSEData(t, body)
		if len(events) != 2 {
			t.Fatalf("event count = %d, want 2: %q", len(events), body)
		}
		for i, data := range events {
			if !json.Valid(data) {
				t.Fatalf("event %d data is not valid JSON: %q", i, data)
			}
		}
	})
}
