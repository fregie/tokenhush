package protocol

import (
	"bytes"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// TestSSESplit drives a stream containing two W4.4-shaped placeholders through
// BackfillWriter with a split at every byte boundary, byte-at-a-time, and
// randomised chunkings. In every case the destination must contain the
// replacements and no placeholder bytes.
func TestSSESplit(t *testing.T) {
	const (
		phEmail = "__PII_email_0123456789ab__"
		phKey   = "__PII_apikey_89abcdef0123__"
		maxLen  = 64
	)
	replacements := map[string]string{phEmail: "[EMAIL]", phKey: "[KEY]"}
	replace := func(tok string) string {
		r, ok := replacements[tok]
		if !ok {
			t.Fatalf("replace called with unexpected token %q", tok)
		}
		return r
	}
	stream := []byte("Hi " + phEmail + " and " + phKey + " bye")
	const want = "Hi [EMAIL] and [KEY] bye"
	runs := 0

	run := func(t *testing.T, chunks [][]byte) {
		t.Helper()
		runs++
		var dst bytes.Buffer
		w := NewBackfillWriter(&dst, maxLen, replace)
		for i, c := range chunks {
			if _, err := w.Write(c); err != nil {
				t.Fatalf("chunk %d: Write: %v", i, err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got := dst.String(); got != want {
			t.Fatalf("backfilled = %q, want %q", got, want)
		}
		if bytes.Contains(dst.Bytes(), []byte(PlaceholderPrefix)) {
			t.Fatalf("destination leaked a placeholder prefix: %q", dst.String())
		}
	}

	// Two chunks, split at every possible byte boundary (including empty
	// leading/trailing chunks).
	for k := 0; k <= len(stream); k++ {
		run(t, [][]byte{stream[:k], stream[k:]})
	}

	// One byte per chunk: every prefix boundary inside every placeholder.
	oneByte := make([][]byte, len(stream))
	for i := range stream {
		oneByte[i] = stream[i : i+1]
	}
	run(t, oneByte)

	// Deterministic pseudo-random chunkings up to 8 bytes wide.
	rng := rand.New(rand.NewSource(0x35))
	for trial := 0; trial < 300; trial++ {
		var chunks [][]byte
		for i := 0; i < len(stream); {
			n := 1 + rng.Intn(8)
			if i+n > len(stream) {
				n = len(stream) - i
			}
			chunks = append(chunks, stream[i:i+n])
			i += n
		}
		run(t, chunks)
	}
	t.Logf("verified %d chunk sequences over %d stream bytes", runs, len(stream))
}

// TestSSEPartialNeverEmitted proves that no chunk sequence can expose an
// incomplete placeholder to the destination. After every Write, the emitted
// bytes must (a) be a prefix of the final expected output and (b) contain no
// placeholder opening or any proper fragment of the known placeholder. The
// output byte stream is captured from under the writer, not reconstructed
// after Flush, so a leak in any intermediate state fails the test.
func TestSSEPartialNeverEmitted(t *testing.T) {
	const (
		ph     = "__PII_email_deadbeefcafe__"
		maxLen = 64
	)
	stream := []byte("P " + ph + " Q")
	const want = "P [EMAIL] Q"
	verifies := 0

	// Every proper fragment of the placeholder long enough to be recognisable
	// as a placeholder opening; none may appear raw in the destination.
	fragments := make([][]byte, 0, len(ph)-len(PlaceholderPrefix))
	for n := len(PlaceholderPrefix); n < len(ph); n++ {
		fragments = append(fragments, []byte(ph[:n]))
	}

	verify := func(t *testing.T, chunks [][]byte) {
		t.Helper()
		verifies++
		var dst bytes.Buffer
		w := NewBackfillWriter(&dst, maxLen, func(string) string { return "[EMAIL]" })
		for i, c := range chunks {
			if _, err := w.Write(c); err != nil {
				t.Fatalf("chunk %d: Write: %v", i, err)
			}
			snap := append([]byte(nil), dst.Bytes()...)
			if !bytes.HasPrefix([]byte(want), snap) {
				t.Fatalf("after chunk %d: emitted %q is not a prefix of %q; a partial placeholder escaped",
					i, snap, want)
			}
			if bytes.Contains(snap, []byte(PlaceholderPrefix)) {
				t.Fatalf("after chunk %d: placeholder opening emitted raw: %q", i, snap)
			}
			for _, frag := range fragments {
				if bytes.Contains(snap, frag) {
					t.Fatalf("after chunk %d: placeholder fragment %q emitted raw", i, frag)
				}
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got := dst.String(); got != want {
			t.Fatalf("backfilled = %q, want %q", got, want)
		}
	}

	// All two-way splits.
	for k := 0; k <= len(stream); k++ {
		verify(t, [][]byte{stream[:k], stream[k:]})
	}
	// All three-way splits.
	for k := 0; k <= len(stream); k++ {
		for j := k; j <= len(stream); j++ {
			verify(t, [][]byte{stream[:k], stream[k:j], stream[j:]})
		}
	}
	// Byte at a time.
	oneByte := make([][]byte, len(stream))
	for i := range stream {
		oneByte[i] = stream[i : i+1]
	}
	verify(t, oneByte)
	// Deterministic random chunkings.
	rng := rand.New(rand.NewSource(0x5E))
	for trial := 0; trial < 200; trial++ {
		var chunks [][]byte
		for i := 0; i < len(stream); {
			n := 1 + rng.Intn(6)
			if i+n > len(stream) {
				n = len(stream) - i
			}
			chunks = append(chunks, stream[i:i+n])
			i += n
		}
		verify(t, chunks)
	}
	t.Logf("verified %d chunk sequences, every intermediate destination state leak-checked", verifies)
}

func TestBackfillLiteralCases(t *testing.T) {
	t.Run("incomplete_at_flush_kept_raw", func(t *testing.T) {
		const in = "text __PII_email_part"
		var dst bytes.Buffer
		w := NewBackfillWriter(&dst, 64, func(string) string { return "[TOO SOON]" })
		if _, err := w.Write([]byte(in)); err != nil {
			t.Fatal(err)
		}
		if got := dst.String(); got != "text " {
			t.Fatalf("before Flush: emitted %q, want only the safe prefix %q", got, "text ")
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if got := dst.String(); got != in {
			t.Fatalf("flush = %q, want raw %q", got, in)
		}
	})

	t.Run("overlong_candidate_then_valid_token", func(t *testing.T) {
		overlong := PlaceholderPrefix + strings.Repeat("x", 30) + placeholderSuffix
		valid := "__PII_email_0123456789ab__"
		in := overlong + " then " + valid + " end"
		want := overlong + " then [EMAIL] end"
		var dst bytes.Buffer
		w := NewBackfillWriter(&dst, 30, func(tok string) string {
			if tok != valid {
				t.Fatalf("replace called with %q, want only %q", tok, valid)
			}
			return "[EMAIL]"
		})
		if _, err := w.Write([]byte(in)); err != nil {
			t.Fatal(err)
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if got := dst.String(); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("nil_replace_is_identity", func(t *testing.T) {
		const in = "keep __PII_email_0123456789ab__ as is"
		var dst bytes.Buffer
		w := NewBackfillWriter(&dst, 64, nil)
		if _, err := w.Write([]byte(in)); err != nil {
			t.Fatal(err)
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if got := dst.String(); got != in {
			t.Fatalf("identity backfill = %q, want %q", got, in)
		}
	})

	t.Run("maxlen_clamped_up", func(t *testing.T) {
		var dst bytes.Buffer
		w := NewBackfillWriter(&dst, 1, nil)
		if w.maxPlaceholderLen != len(PlaceholderPrefix) {
			t.Fatalf("maxPlaceholderLen = %d, want clamp to %d", w.maxPlaceholderLen, len(PlaceholderPrefix))
		}
		in := "__P"
		if _, err := w.Write([]byte(in)); err != nil {
			t.Fatal(err)
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if got := dst.String(); got != in {
			t.Fatalf("got %q, want %q", got, in)
		}
	})

	t.Run("writer_poisoned_after_dst_error", func(t *testing.T) {
		w := NewBackfillWriter(errWriter{}, 64, nil)
		if _, err := w.Write([]byte("x")); err == nil {
			t.Fatal("Write to failing dst returned nil error")
		}
		if _, err := w.Write([]byte("y")); err == nil {
			t.Fatal("Write after failure returned nil error")
		}
		if err := w.Flush(); err == nil {
			t.Fatal("Flush after failure returned nil error")
		}
	})
}

// TestBackfillMemoryBound asserts the writer never retains more than
// maxPlaceholderLen bytes between Write calls, including adversarial inputs
// whose prefix never completes.
func TestBackfillMemoryBound(t *testing.T) {
	const maxLen = 24
	var dst bytes.Buffer
	w := NewBackfillWriter(&dst, maxLen, func(string) string { return "<x>" })

	writes := []string{
		strings.Repeat("a", 100000),                                     // no prefix at all
		strings.Repeat("b", 1000) + "__PI",                              // partial opening at the tail
		PlaceholderPrefix + strings.Repeat("x", 100000),                 // opening, suffix never completes
		strings.Repeat("__PII_", 50000),                                 // dense openings
		PlaceholderPrefix + strings.Repeat("y", 16) + placeholderSuffix, // exactly maxLen
		PlaceholderPrefix + strings.Repeat("z", 17) + placeholderSuffix, // one over: literal
		strings.Repeat("tail", 1000) + "__PII___PI",                     // literal tail + partial
	}
	for i, s := range writes {
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if len(w.buf) > w.maxPlaceholderLen {
			t.Fatalf("after write %d: retained %d bytes, max %d", i, len(w.buf), w.maxPlaceholderLen)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(w.buf) != 0 {
		t.Fatalf("after Flush: retained %d bytes, want 0", len(w.buf))
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errWriterErr{} }

type errWriterErr struct{}

func (errWriterErr) Error() string { return "destination failed" }

// sseFixture is a single SSE stream exercising comments before an event,
// multi-line data, CRLF and lone-CR line endings, id and retry fields, and a
// final event with no trailing blank line.
func sseFixture() string {
	return ": ping\n" +
		":pong\n" +
		"event: update\n" +
		"data: first line\n" +
		"data: second line\n" +
		"\n" +
		"id: 7\n" +
		"data: crlf\r\n" +
		"data: bare\rdata: cr\n" +
		"\n" +
		"retry: 1500\n" +
		"data: tail no blank"
}

func decodeChunks(chunks [][]byte) []SSEEvent {
	d := NewSSEDecoder()
	var out []SSEEvent
	for _, c := range chunks {
		out = append(out, d.Feed(c)...)
	}
	return append(out, d.Close()...)
}

func joinRaw(evs []SSEEvent) []byte {
	var b []byte
	for _, ev := range evs {
		b = append(b, ev.Raw...)
	}
	return b
}

// TestSSEDecoderRoundTrip locks both the parsed record semantics and the raw
// coverage invariant: concatenating every event's Raw reproduces the input
// byte for byte, for every chunking.
func TestSSEDecoderRoundTrip(t *testing.T) {
	input := []byte(sseFixture())

	whole := NewSSEDecoder()
	want := whole.Feed(input)
	want = append(want, whole.Close()...)

	if len(want) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(want), want)
	}
	if got := string(want[0].Data); got != "first line\nsecond line" {
		t.Fatalf("event 0 Data = %q", got)
	}
	if want[0].Event != "update" {
		t.Fatalf("event 0 Event = %q, want update", want[0].Event)
	}
	if !reflect.DeepEqual(want[0].Comments, []string{"ping", "pong"}) {
		t.Fatalf("event 0 Comments = %q, want [ping pong]", want[0].Comments)
	}
	if want[0].ID != "" || want[0].Retry != 0 {
		t.Fatalf("event 0 ID/Retry = %q/%d, want empty/0", want[0].ID, want[0].Retry)
	}
	if got := string(want[1].Data); got != "crlf\nbare\ncr" {
		t.Fatalf("event 1 Data = %q", got)
	}
	if want[1].Event != "message" {
		t.Fatalf("event 1 Event = %q, want message", want[1].Event)
	}
	if want[1].ID != "7" {
		t.Fatalf("event 1 ID = %q, want 7", want[1].ID)
	}
	if got := string(want[2].Data); got != "tail no blank" {
		t.Fatalf("event 2 Data = %q", got)
	}
	if want[2].ID != "7" {
		t.Fatalf("event 2 ID = %q, want persisted 7", want[2].ID)
	}
	if want[2].Retry != 1500 {
		t.Fatalf("event 2 Retry = %d, want 1500", want[2].Retry)
	}
	if got := string(joinRaw(want)); got != string(input) {
		t.Fatalf("Raw join = %q, want input", got)
	}

	check := func(t *testing.T, chunks [][]byte) {
		t.Helper()
		got := decodeChunks(chunks)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("chunked decode differs from whole decode:\n got %+v\nwant %+v", got, want)
		}
		if raw := joinRaw(got); !bytes.Equal(raw, input) {
			t.Fatalf("Raw join = %q, want %q", raw, input)
		}
	}

	// Every two-way split.
	for k := 0; k <= len(input); k++ {
		check(t, [][]byte{input[:k], input[k:]})
	}
	// Byte at a time.
	oneByte := make([][]byte, len(input))
	for i := range input {
		oneByte[i] = input[i : i+1]
	}
	check(t, oneByte)
	// Deterministic random chunkings.
	rng := rand.New(rand.NewSource(0x5D))
	for trial := 0; trial < 300; trial++ {
		var chunks [][]byte
		for i := 0; i < len(input); {
			n := 1 + rng.Intn(5)
			if i+n > len(input) {
				n = len(input) - i
			}
			chunks = append(chunks, input[i:i+n])
			i += n
		}
		check(t, chunks)
	}
}

// TestSSEDecoderFieldForms covers line-level parsing details: spacing,
// valueless data lines, duplicate/NUL id values, digit-only retry, unknown
// fields, and blank lines that must not dispatch.
func TestSSEDecoderFieldForms(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		data     string
		event    string
		id       string
		retry    int
		comments []string
		events   int
	}{
		{name: "no_space_after_colon", input: "data:x\n\n", data: "x", event: "message", events: 1},
		{name: "single_space_stripped", input: "data:  x\n\n", data: " x", event: "message", events: 1},
		{name: "valueless_data_dispatches", input: "data\n\n", data: "", event: "message", events: 1},
		{name: "multiline_join", input: "data: a\ndata: b\ndata: c\n\n", data: "a\nb\nc", event: "message", events: 1},
		{name: "comments_before_event", input: ": c1\n:c2 x\n:  c3\ndata: y\n\n", data: "y", event: "message", comments: []string{"c1", "c2 x", " c3"}, events: 1},
		{name: "named_event", input: "event: ping\ndata: x\n\n", data: "x", event: "ping", events: 1},
		{name: "last_id_wins", input: "id: 42\nid: 43\ndata: x\n\n", data: "x", event: "message", id: "43", events: 1},
		{name: "nul_id_ignored", input: "id: a\x00b\ndata: x\n\n", data: "x", event: "message", id: "", events: 1},
		{name: "retry_digits", input: "retry: 1500\ndata: x\n\n", data: "x", event: "message", retry: 1500, events: 1},
		{name: "retry_nondigits_ignored", input: "retry: 15x0\ndata: x\n\n", data: "x", event: "message", retry: 0, events: 1},
		{name: "retry_negative_ignored", input: "retry: -5\ndata: x\n\n", data: "x", event: "message", retry: 0, events: 1},
		{name: "fieldless_blank_no_dispatch", input: "event: ignored\n\ndata: x\n\n", data: "x", event: "message", events: 1},
		{name: "unknown_field_ignored", input: "foo: bar\ndata: x\n\n", data: "x", event: "message", events: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evs := decodeChunks([][]byte{[]byte(tc.input)})
			if len(evs) != tc.events {
				t.Fatalf("got %d events (%+v), want %d", len(evs), evs, tc.events)
			}
			if len(evs) == 0 {
				return
			}
			ev := evs[0]
			if ev.Data != tc.data {
				t.Fatalf("Data = %q, want %q", ev.Data, tc.data)
			}
			if ev.Event != tc.event {
				t.Fatalf("Event = %q, want %q", ev.Event, tc.event)
			}
			if ev.ID != tc.id {
				t.Fatalf("ID = %q, want %q", ev.ID, tc.id)
			}
			if ev.Retry != tc.retry {
				t.Fatalf("Retry = %d, want %d", ev.Retry, tc.retry)
			}
			if !reflect.DeepEqual(ev.Comments, tc.comments) {
				t.Fatalf("Comments = %q, want %q", ev.Comments, tc.comments)
			}
		})
	}
}

// TestSSEDecoderCommentOnlyTail locks the raw-coverage behaviour for streams
// that never dispatch: trailing comment bytes still surface in a final,
// data-less record so concatenated Raw stays byte-exact.
func TestSSEDecoderCommentOnlyTail(t *testing.T) {
	for _, input := range []string{": a\n: b\n", ": a\n\n", ":a\r\n\r\n"} {
		d := NewSSEDecoder()
		evs := d.Feed([]byte(input))
		evs = append(evs, d.Close()...)
		if len(evs) != 1 {
			t.Fatalf("input %q: got %d events, want 1", input, len(evs))
		}
		if evs[0].Data != "" || evs[0].Event != "" {
			t.Fatalf("input %q: data-less record = %+v", input, evs[0])
		}
		if got := string(joinRaw(evs)); got != input {
			t.Fatalf("input %q: Raw join = %q", input, got)
		}
	}
}

// TestSSEDecoderAdversarialInputs probes malformed and oversized input: binary
// bytes inside fields, terminators split across chunks, and a single very long
// line delivered in many small chunks.
func TestSSEDecoderAdversarialInputs(t *testing.T) {
	t.Run("binary_bytes_preserved", func(t *testing.T) {
		input := []byte("data: \x00\xff\xfe\x01 tail\n\n")
		evs := decodeChunks([][]byte{input[:9], input[9:]})
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1", len(evs))
		}
		if got, want := evs[0].Data, "\x00\xff\xfe\x01 tail"; got != want {
			t.Fatalf("Data = %q, want %q", got, want)
		}
		if raw := joinRaw(evs); !bytes.Equal(raw, input) {
			t.Fatalf("Raw join = %q, want %q", raw, input)
		}
	})

	t.Run("crlf_split_across_chunks", func(t *testing.T) {
		input := []byte("data: cr\r\ndata: lf\n\n")
		evs := decodeChunks([][]byte{[]byte("data: cr\r"), []byte("\ndata: lf\n\n")})
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1", len(evs))
		}
		if got, want := evs[0].Data, "cr\nlf"; got != want {
			t.Fatalf("Data = %q, want %q", got, want)
		}
		if raw := joinRaw(evs); !bytes.Equal(raw, input) {
			t.Fatalf("Raw join = %q, want %q", raw, input)
		}
	})

	t.Run("huge_single_line", func(t *testing.T) {
		payload := strings.Repeat("z", 1<<20)
		input := []byte("data: " + payload + "\n\n")
		var chunks [][]byte
		for i := 0; i < len(input); i += 4093 { // odd size to split tokens too
			end := min(i+4093, len(input))
			chunks = append(chunks, input[i:end])
		}
		evs := decodeChunks(chunks)
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1", len(evs))
		}
		if got := evs[0].Data; len(got) != len(payload) || got[:5] != "zzzzz" {
			t.Fatalf("Data length = %d, want %d", len(got), len(payload))
		}
		if raw := joinRaw(evs); !bytes.Equal(raw, input) {
			t.Fatalf("Raw join mismatch: got %d bytes, want %d", len(raw), len(input))
		}
	})

	t.Run("unterminated_huge_line_at_close", func(t *testing.T) {
		payload := strings.Repeat("q", 1<<20)
		input := []byte("data: " + payload)
		evs := decodeChunks([][]byte{input[:100], input[100:]})
		if len(evs) != 1 {
			t.Fatalf("got %d events, want 1", len(evs))
		}
		if got := evs[0].Data; len(got) != len(payload) {
			t.Fatalf("Data length = %d, want %d", len(got), len(payload))
		}
		if raw := joinRaw(evs); !bytes.Equal(raw, input) {
			t.Fatalf("Raw join mismatch: got %d bytes, want %d", len(raw), len(input))
		}
	})
}

// TestSSEDecoderLifecycle covers Close idempotence and Feed after Close.
func TestSSEDecoderLifecycle(t *testing.T) {
	d := NewSSEDecoder()
	if evs := d.Feed([]byte("data: x\n\n")); len(evs) != 1 {
		t.Fatalf("Feed returned %d events, want 1", len(evs))
	}
	if evs := d.Close(); evs != nil {
		t.Fatalf("first Close returned %+v, want nil", evs)
	}
	if evs := d.Close(); evs != nil {
		t.Fatalf("second Close returned %+v, want nil", evs)
	}
	if evs := d.Feed([]byte("data: y\n\n")); evs != nil {
		t.Fatalf("Feed after Close returned %+v, want nil", evs)
	}
}
