package proxy

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// sseRecord renders one SSE record carrying a single data line.
func sseRecord(event, data string) string {
	return "event: " + event + "\ndata: " + data + "\n\n"
}

// sseMint mints a placeholder for secret and records its reverse mapping on a
// fresh session backfiller.
func sseMint(t *testing.T, secret []byte, kind string) (*redact.Backfiller, string) {
	t.Helper()
	back := redact.NewBackfiller()
	p, err := back.Mint(redact.NewForwardWriter(redact.NewEngine()), secret, kind)
	if err != nil {
		t.Fatalf("Mint(%q, %q): %v", secret, kind, err)
	}
	return back, p
}

// sseChunks splits stream into consecutive chunks of at most n bytes.
func sseChunks(stream string, n int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(stream); i += n {
		chunks = append(chunks, []byte(stream[i:min(i+n, len(stream))]))
	}
	return chunks
}

// sseDrive writes every chunk through h and returns the concatenated output of
// every Write plus the Flush.
func sseDrive(t *testing.T, h *SSEHandler, chunks [][]byte) []byte {
	t.Helper()
	var out []byte
	for i, chunk := range chunks {
		part, err := h.Write(chunk)
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
		out = append(out, part...)
	}
	tail, err := h.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	return append(out, tail...)
}

// sseEvents decodes every record of stream, including the Close flush.
func sseEvents(t *testing.T, stream []byte) []protocol.Event {
	t.Helper()
	dec := protocol.NewDecoder()
	events, err := dec.Feed(stream)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	tail, err := dec.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	return append(events, tail...)
}

// TestSSEBackfillRestoresSplitAcrossDeltaEvents: one placeholder split across
// three data deltas is restored exactly once, in the completing event, while
// the earlier contributing events are emptied and the framing survives.
func TestSSEBackfillRestoresSplitAcrossDeltaEvents(t *testing.T) {
	secret := []byte("alice@example.com")
	back, p := sseMint(t, secret, "email")
	if len(p) < 21 {
		t.Fatalf("placeholder %q is too short to split across three deltas", p)
	}
	first, second, third := sseRecord("delta", p[:8]), sseRecord("delta", p[8:20]), sseRecord("delta", p[20:]+" tail")
	in := first + second + third
	want := sseRecord("delta", "") + sseRecord("delta", "") + sseRecord("delta", string(secret)+" tail")

	cases := []struct {
		name   string
		chunks [][]byte
	}{
		{"separate-writes", [][]byte{[]byte(first), []byte(second), []byte(third)}},
		{"mid-event-5", sseChunks(in, 5)},
		{"mid-event-1", sseChunks(in, 1)},
		{"whole-stream", [][]byte{[]byte(in)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := sseDrive(t, NewSSEHandler(SSEResponseConfig{Backfiller: back}), tc.chunks)
			if string(out) != want {
				t.Fatalf("stream:\n got %q\nwant %q", out, want)
			}
			if got := bytes.Count(out, secret); got != 1 {
				t.Fatalf("secret appears %d times, want exactly 1 in %q", got, out)
			}
			if bytes.Contains(out, []byte("__PII_")) {
				t.Fatalf("placeholder prefix survived in %q", out)
			}
			events := sseEvents(t, out)
			if len(events) != 3 {
				t.Fatalf("event count = %d, want 3", len(events))
			}
			for i := 0; i < 2; i++ {
				if got := string(events[i].Data); got != "" {
					t.Fatalf("event %d data = %q, want empty (its bytes moved to the completing event)", i, got)
				}
			}
			if got := string(events[2].Data); got != string(secret)+" tail" {
				t.Fatalf("event 2 data = %q, want %q", got, string(secret)+" tail")
			}
		})
	}
}

// TestSSEStreamNoMatchIsByteIdentical: a plain stream round-trips byte-for-byte
// however the transport chunks it.
func TestSSEStreamNoMatchIsByteIdentical(t *testing.T) {
	back, _ := sseMint(t, []byte("alice@example.com"), "email")
	in := sseRecord("delta", `{"choices":[{"delta":{"content":"hello"}}]}`) +
		sseRecord("delta", `{"choices":[{"delta":{"content":" world"}}]}`) +
		sseRecord("message", "plain trailer")
	for _, n := range []int{1, 3, 7, 64, len(in)} {
		out := sseDrive(t, NewSSEHandler(SSEResponseConfig{Backfiller: back}), sseChunks(in, n))
		if !bytes.Equal(out, []byte(in)) {
			t.Fatalf("chunk size %d changed a no-match stream:\n got %q\nwant %q", n, out, in)
		}
	}
}

// TestSSEStreamHeldBytesBounded: feeding far more than
// protocol.SSEBackfillHoldbackBytes of prefix-like data keeps the single
// accumulator under the bound and the stream progressing.
func TestSSEStreamHeldBytesBounded(t *testing.T) {
	back, _ := sseMint(t, []byte("alice@example.com"), "email")
	// Every event's data ends in an unfinished placeholder prefix (a capped
	// type segment followed by 60 digest digits), so the writer holds a tail
	// at every event boundary.
	run := "__PII_" + strings.Repeat("a", 16) + "_" + strings.Repeat("a", 60)
	const events, filler = 40, 8192
	var in strings.Builder
	for i := 0; i < events; i++ {
		in.WriteString(sseRecord("delta", strings.Repeat("x", filler)+run))
	}
	if in.Len() <= protocol.SSEBackfillHoldbackBytes {
		t.Fatalf("test stream is %d bytes; must exceed the %d-byte bound", in.Len(), protocol.SSEBackfillHoldbackBytes)
	}

	h := NewSSEHandler(SSEResponseConfig{Backfiller: back})
	var streamed int
	for i, chunk := range sseChunks(in.String(), 1024) {
		out, err := h.Write(chunk)
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
		streamed += len(out)
		if held := h.Held(); held > protocol.SSEBackfillHoldbackBytes {
			t.Fatalf("after Write %d: held %d bytes, above the bound %d", i, held, protocol.SSEBackfillHoldbackBytes)
		}
	}
	if streamed <= protocol.SSEBackfillHoldbackBytes {
		t.Fatalf("streamed only %d of %d bytes before Flush: no progress", streamed, in.Len())
	}
	tail, err := h.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := streamed + len(tail); got != in.Len() {
		t.Fatalf("emitted %d bytes, want %d: a byte was dropped", got, in.Len())
	}
	if held := h.Held(); held != 0 {
		t.Fatalf("Held() = %d after Flush, want 0", held)
	}
}

// TestSSEStreamNonDeltaFieldsPreserved: id, retry and comment lines are not
// touched while a delta is rewritten.
func TestSSEStreamNonDeltaFieldsPreserved(t *testing.T) {
	secret := "alice@example.com"
	back, p := sseMint(t, []byte(secret), "email")
	in := "id: 42\nretry: 1000\n: keepalive\nevent: delta\ndata: " + p + "\n\n"
	want := "id: 42\nretry: 1000\n: keepalive\nevent: delta\ndata: " + secret + "\n\n"
	for _, n := range []int{len(in), 4} {
		out := sseDrive(t, NewSSEHandler(SSEResponseConfig{Backfiller: back}), sseChunks(in, n))
		if string(out) != want {
			t.Fatalf("chunk size %d:\n got %q\nwant %q", n, out, want)
		}
		for _, kept := range []string{"id: 42\n", "retry: 1000\n", ": keepalive\n"} {
			if !strings.Contains(string(out), kept) {
				t.Fatalf("stream dropped %q: %q", kept, out)
			}
		}
	}
}

// TestSSEStreamDoneAndPingPassThrough: sentinel, ping, comment-only and
// data-less streams are byte-identical passthrough.
func TestSSEStreamDoneAndPingPassThrough(t *testing.T) {
	back, _ := sseMint(t, []byte("alice@example.com"), "email")
	for _, in := range []string{
		"data: [DONE]\n\n",
		"event: ping\ndata: alive\n\n",
		": keepalive\n\n",
		"data: [DONE]\n\n: keepalive\n\n",
		"retry: 250\n\n",
	} {
		out := sseDrive(t, NewSSEHandler(SSEResponseConfig{Backfiller: back}), sseChunks(in, 3))
		if !bytes.Equal(out, []byte(in)) {
			t.Fatalf("stream %q came back as %q, want byte-identical", in, out)
		}
	}
}

// TestSSEStreamOpenWindowFlushesCleanly: a stream that ends with a writer
// window still open flushes its held bytes back into the pending data span and
// terminates cleanly.
func TestSSEStreamOpenWindowFlushesCleanly(t *testing.T) {
	back, _ := sseMint(t, []byte("alice@example.com"), "email")
	for _, in := range []string{
		"data: hello __PII_",
		"data: a\n\ndata: partial __PII_em",
	} {
		h := NewSSEHandler(SSEResponseConfig{Backfiller: back})
		out := sseDrive(t, h, sseChunks(in, 3))
		if !bytes.Equal(out, []byte(in)) {
			t.Fatalf("stream %q came back as %q, want the literal window flushed back", in, out)
		}
		if !h.Closed() {
			t.Fatalf("stream %q is not closed after Flush", in)
		}
		if held := h.Held(); held != 0 {
			t.Fatalf("Held() = %d after Flush, want 0", held)
		}
		if extra, err := h.Flush(); err != nil || len(extra) != 0 {
			t.Fatalf("second Flush = (%q, %v), want (empty, nil)", extra, err)
		}
	}
}

// TestSSEResponseBlockEmitsErrorRecordAndCloses: the first whole-event
// evaluation decides; a Block emits exactly one error record naming the rule
// id and closes the stream, and both counters move.
func TestSSEResponseBlockEmitsErrorRecordAndCloses(t *testing.T) {
	stream := sseRecord("delta", `{"hi":1}`) + sseRecord("delta", `{"hi":2}`)

	t.Run("block", func(t *testing.T) {
		evaluator := &scriptedEvaluator{decision: ResponseDecision{Action: ResponseBlock, RuleIDs: []string{"rule-7"}}}
		counters := NewCounters()
		h := NewSSEHandler(SSEResponseConfig{Evaluator: evaluator, Counters: counters})

		out, err := h.Write([]byte(stream))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		want := "event: error\ndata: {\"error\":\"rule_blocked\",\"rule_id\":\"rule-7\"}\n\n"
		if string(out) != want {
			t.Fatalf("block record:\n got %q\nwant %q", out, want)
		}
		if seen := evaluator.seen(); len(seen) != 1 || string(seen[0]) != `{"hi":1}` {
			t.Errorf("evaluator saw %q, want the first whole event exactly once", seen)
		}
		if !h.Closed() {
			t.Error("stream is not closed after a Block")
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
		if _, err := h.Write([]byte(sseRecord("delta", `{"hi":3}`))); !errors.Is(err, ErrSSEClosed) {
			t.Errorf("Write after Block error = %v, want ErrSSEClosed", err)
		}
		if extra, err := h.Flush(); err != nil || len(extra) != 0 {
			t.Errorf("Flush after Block = (%q, %v), want (empty, nil)", extra, err)
		}
	})

	t.Run("warn", func(t *testing.T) {
		evaluator := &scriptedEvaluator{decision: ResponseDecision{Action: ResponseWarn, RuleIDs: []string{"warn-1"}}}
		counters := NewCounters()
		warnings := &recordingWarnings{}
		h := NewSSEHandler(SSEResponseConfig{Evaluator: evaluator, Counters: counters, Warnings: warnings})

		out := sseDrive(t, h, sseChunks(stream, 6))
		if !bytes.Equal(out, []byte(stream)) {
			t.Fatalf("a Warn must forward the stream unchanged:\n got %q\nwant %q", out, stream)
		}
		if got := warnings.seen(); len(got) != 1 {
			t.Fatalf("warnings = %q, want exactly one", got)
		}
		if counters.ContentPolicyBlocks() != 0 || counters.RuleBlocks() != 0 || counters.WalkSkips() != 0 {
			t.Errorf("counters moved on a Warn: content=%d rule=%d walk=%d",
				counters.ContentPolicyBlocks(), counters.RuleBlocks(), counters.WalkSkips())
		}
		if !h.Closed() {
			t.Error("stream is not closed after Flush")
		}
	})
}

// TestSSEStreamExactlyOneAccumulator: the handler holds exactly one
// *protocol.BackfillWriter and no second accumulator surface with its own cap.
func TestSSEStreamExactlyOneAccumulator(t *testing.T) {
	writerType := reflect.TypeOf(&protocol.BackfillWriter{})
	typ := reflect.TypeOf(SSEHandler{})
	accumulators := 0
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Type == writerType {
			accumulators++
			continue
		}
		if isBoundedAccumulator(field.Type) {
			t.Errorf("field %s exposes a second bounded accumulator", field.Name)
		}
	}
	if accumulators != 1 {
		t.Fatalf("SSEHandler holds %d *protocol.BackfillWriter fields, want exactly 1", accumulators)
	}
	if got := NewSSEHandler(SSEResponseConfig{}).Held(); got != 0 {
		t.Errorf("Held() = %d on a fresh handler, want 0", got)
	}
}

// isBoundedAccumulator reports whether typ (or *typ) exposes the bounded
// accumulator surface: both Feed([]byte) []byte and Held() int.
func isBoundedAccumulator(typ reflect.Type) bool {
	probe := typ
	if typ.Kind() != reflect.Pointer {
		probe = reflect.PointerTo(typ)
	}
	_, feed := probe.MethodByName("Feed")
	_, held := probe.MethodByName("Held")
	return feed && held
}

// TestSSEStreamNeverUsesForwardWriter: no seam of the handler can reach the
// forward-only placeholder writer, and the Backfiller seam exposes exactly the
// restore method.
func TestSSEStreamNeverUsesForwardWriter(t *testing.T) {
	typ := reflect.TypeOf(SSEHandler{})
	for i := 0; i < typ.NumField(); i++ {
		if mentionsForwardWriter(typ.Field(i).Type, 4) {
			t.Errorf("field %s exposes a forward-only writer", typ.Field(i).Name)
		}
	}
	seam := reflect.TypeOf((*Backfiller)(nil)).Elem()
	if seam.NumMethod() != 1 {
		t.Fatalf("Backfiller has %d methods, want exactly the restore method", seam.NumMethod())
	}
	method := seam.Method(0)
	bytesType := reflect.TypeOf([]byte(nil))
	sig := method.Type
	if method.Name != "Backfill" || sig.NumIn() != 1 || sig.NumOut() != 1 ||
		sig.In(0) != bytesType || sig.Out(0) != bytesType {
		t.Errorf("Backfiller method = %s%s, want Backfill([]byte) []byte", method.Name, method.Type)
	}
}

// mentionsForwardWriter reports whether typ names or reaches a ForwardWriter
// type, following pointers, slices, struct fields, interfaces and functions.
func mentionsForwardWriter(typ reflect.Type, depth int) bool {
	if strings.Contains(typ.String(), "ForwardWriter") {
		return true
	}
	if depth == 0 {
		return false
	}
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return mentionsForwardWriter(typ.Elem(), depth-1)
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			if mentionsForwardWriter(typ.Field(i).Type, depth-1) {
				return true
			}
		}
	case reflect.Interface:
		for i := 0; i < typ.NumMethod(); i++ {
			if mentionsForwardWriter(typ.Method(i).Type, depth-1) {
				return true
			}
		}
	case reflect.Func:
		for i := 0; i < typ.NumIn(); i++ {
			if mentionsForwardWriter(typ.In(i), depth-1) {
				return true
			}
		}
		for i := 0; i < typ.NumOut(); i++ {
			if mentionsForwardWriter(typ.Out(i), depth-1) {
				return true
			}
		}
	}
	return false
}
