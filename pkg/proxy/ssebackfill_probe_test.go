package proxy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// TestSSEBackfillerPreservesFraming locks byte-for-byte framing: comments,
// event:, id:, retry:, CRLF, multi-line data, a colon-less data line, [DONE]
// and a final record with no trailing blank line (the Close path) all survive
// untouched, and only the JSON placeholder span changes.
func TestSSEBackfillerPreservesFraming(t *testing.T) {
	input := []byte(
		": lead comment\n" +
			"event: ping\n" +
			"id: 42\n" +
			"retry: 1000\n" +
			"data: {\"delta\":{\"content\":\"" + t4Placeholder + "\"}}\n" +
			": fold comment\n" +
			"\n" +
			"data: multi\r\n" +
			"data: line\r\n" +
			"\n" +
			"data\n" +
			"\n" +
			"data: [DONE]", // no trailing blank line: surfaced by Close
	)
	want := []byte(strings.Replace(string(input), t4Placeholder, t4Secret, 1))
	got := t4Run(t, input)
	if !bytes.Equal(got, want) {
		t.Fatalf("framing was not preserved:\n got %q\nwant %q", got, want)
	}
	if bytes.Contains(got, []byte(protocol.PlaceholderPrefix)) {
		t.Fatalf("output still contains a placeholder: %q", got)
	}
}

// TestSSEBackfillerMalformedPassthrough proves a malformed or invalid-UTF-8
// data payload (here a multibyte rune split across two events) is never half
// rewritten: it is fed as a raw path, no edit is produced without a complete
// placeholder, and the bytes pass through unchanged. A colon-less data line and
// a multi-line payload are likewise byte-identical.
func TestSSEBackfillerMalformedPassthrough(t *testing.T) {
	cases := map[string][]byte{
		"multibyte_split_mid_rune": []byte(
			"data: {\"delta\":{\"content\":\"caf\xc3\n\n" +
				"data: \xa9\"}}\n\n",
		),
		"multi_line_data": []byte("data: alpha\ndata: beta\n\n"),
		"colon_less_data": []byte("data\n\n"),
		"done_sentinel":   []byte("data: [DONE]\n\n"),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			got := t4Run(t, input)
			if !bytes.Equal(got, input) {
				t.Fatalf("malformed payload was modified:\n got %q\nwant %q", got, input)
			}
			if bytes.Contains(got, []byte(t4Secret)) {
				t.Fatalf("malformed payload leaked the secret: %q", got)
			}
		})
	}
}

// TestSSEBackfillerNoCrossPathOrStreamContamination proves paths and streams do
// not share state: within one stream an untouched sibling path keeps its bytes
// while a split placeholder path is restored, and repeated runs are byte-equal.
func TestSSEBackfillerNoCrossPathOrStreamContamination(t *testing.T) {
	input := []byte(
		t4DeltaEvent(t4Placeholder[:10]) +
			`data: {"other":"keep-me"}` + "\n\n" +
			t4DeltaEvent(t4Placeholder[10:]),
	)
	want := []byte(
		t4DeltaEvent("") +
			`data: {"other":"keep-me"}` + "\n\n" +
			t4DeltaEvent(t4Secret),
	)
	for run := 0; run < 3; run++ {
		got := t4Run(t, input)
		if !bytes.Equal(got, want) {
			t.Fatalf("run %d:\n got %q\nwant %q", run, got, want)
		}
	}
}

// TestSSEBackfillerSecondStreamSameObject proves a Flush ends one stream but
// not the object: a second independent stream written and flushed through the
// same backfiller is decoded from a fresh framing state and is byte-correct.
func TestSSEBackfillerSecondStreamSameObject(t *testing.T) {
	streamA := []byte(t4DeltaEvent(t4Placeholder) + "data: [DONE]\n\n")
	wantA := []byte(t4DeltaEvent(t4Secret) + "data: [DONE]\n\n")
	streamB := []byte(t4DeltaEvent("plain") + t4DeltaEvent(t4Placeholder))

	var dst bytes.Buffer
	b := newSSEBackfiller(&dst, 128, t4Replace)
	if _, err := b.Write(streamA); err != nil {
		t.Fatalf("stream A Write: %v", err)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("stream A Flush: %v", err)
	}
	if got := dst.Bytes(); !bytes.Equal(got, wantA) {
		t.Fatalf("stream A:\n got %q\nwant %q", got, wantA)
	}

	dst.Reset()
	if _, err := b.Write(streamB); err != nil {
		t.Fatalf("stream B Write: %v", err)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("stream B Flush: %v", err)
	}
	wantB := []byte(t4DeltaEvent("plain") + t4DeltaEvent(t4Secret))
	if got := dst.Bytes(); !bytes.Equal(got, wantB) {
		t.Fatalf("stream B after stream A on the same object:\n got %q\nwant %q", got, wantB)
	}
}

// TestSSEBackfillerForceFlushBoundsHoldback proves the holdback bound: a path
// whose window never closes across many events is force-flushed (its buffered
// tail becomes literal) so the held events are emitted mid-stream instead of
// being retained until Flush. With no complete placeholder present the output
// stays byte-identical.
func TestSSEBackfillerForceFlushBoundsHoldback(t *testing.T) {
	const events = 20000 // ~340 KiB of held raw events, past the 256 KiB bound
	var in strings.Builder
	for i := 0; i < events; i++ {
		in.WriteString(`data: {"x":"_"}` + "\n\n")
	}
	input := []byte(in.String())

	var dst bytes.Buffer
	b := newSSEBackfiller(&dst, 128, t4Replace)
	if _, err := b.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if dst.Len() == 0 {
		t.Fatalf("holdback bound did not force-flush anything during Write; output still empty")
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := dst.Bytes(); !bytes.Equal(got, input) {
		t.Fatalf("force-flushed output differs from input (len got %d, want %d)", len(got), len(input))
	}
}
