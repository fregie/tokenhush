package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// decodeSSE feeds every chunk and then Close, returning all events in order.
func decodeSSE(t *testing.T, chunks ...string) []Event {
	t.Helper()
	d := NewDecoder()
	var events []Event
	for _, chunk := range chunks {
		got, err := d.Feed([]byte(chunk))
		if err != nil {
			t.Fatalf("Feed(%q) error = %v, want nil", chunk, err)
		}
		events = append(events, got...)
	}
	tail, err := d.Close()
	if err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	return append(events, tail...)
}

// singleEvent decodes chunks and requires exactly one event.
func singleEvent(t *testing.T, chunks ...string) Event {
	t.Helper()
	events := decodeSSE(t, chunks...)
	if len(events) != 1 {
		t.Fatalf("decode returned %d events, want 1: %+v", len(events), events)
	}
	return events[0]
}

func TestSSELineTerminators(t *testing.T) {
	tests := []struct {
		name string
		in   string
		data string
	}{
		{"lf", "data: a\n\n", "a"},
		{"crlf", "data: a\r\n\r\n", "a"},
		{"lone cr", "data: a\r\r", "a"},
		{"mixed terminators", "data: a\r\ndata: b\rdata: c\n\n", "a\nb\nc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := singleEvent(t, tc.in)
			if string(ev.Data) != tc.data {
				t.Fatalf("Data = %q, want %q", ev.Data, tc.data)
			}
			if string(ev.Raw) != tc.in {
				t.Fatalf("Raw = %q, want byte-exact %q", ev.Raw, tc.in)
			}
		})
	}
}

// TestSSESplitMidDataAcrossThreeChunks is the invariant-8 anchor: one record
// is fed as exactly three chunks that cut through the data field name and
// value, and must decode to the exact concatenated value plus exact offsets.
func TestSSESplitMidDataAcrossThreeChunks(t *testing.T) {
	const in = "event: x\ndata: hello, world\nid: 9\n\n"
	events := decodeSSE(t, "event: x\nda", "ta: hel", "lo, world\nid: 9\n\n")
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if string(ev.Data) != "hello, world" {
		t.Fatalf("Data = %q, want %q", ev.Data, "hello, world")
	}
	if ev.Event != "x" || ev.ID != "9" || !ev.HasID {
		t.Fatalf("Event/ID/HasID = %q/%q/%v, want x/9/true", ev.Event, ev.ID, ev.HasID)
	}
	if string(ev.Raw) != in {
		t.Fatalf("Raw = %q, want byte-exact %q", ev.Raw, in)
	}
	if len(ev.DataSpans) != 1 {
		t.Fatalf("DataSpans = %+v, want exactly one span", ev.DataSpans)
	}
	sp := ev.DataSpans[0]
	if sp.Start != 15 || sp.End != 27 {
		t.Fatalf("DataSpans = %+v, want [{15 27}]", ev.DataSpans)
	}
	if got := string(ev.Raw[sp.Start:sp.End]); got != "hello, world" {
		t.Fatalf("Raw span = %q, want %q", got, "hello, world")
	}
}

func TestSSECommentFolding(t *testing.T) {
	in := ": lead one\n:lead two\ndata: v\n\n"
	ev := singleEvent(t, in)
	if string(ev.Data) != "v" {
		t.Fatalf("Data = %q, want v (comments never contribute)", ev.Data)
	}
	if string(ev.Raw) != in {
		t.Fatalf("Raw = %q, want the comment lines folded in: %q", ev.Raw, in)
	}
	if events := decodeSSE(t, ": only\n: comments\n"); len(events) != 0 {
		t.Fatalf("comment-only stream decoded %d events, want 0: %+v", len(events), events)
	}
	ev = singleEvent(t, "data: a\n: note\ndata: b\n\n")
	if string(ev.Data) != "a\nb" {
		t.Fatalf("Data = %q, want %q", ev.Data, "a\nb")
	}
}

func TestSSEIDPersistsRetryDoesNot(t *testing.T) {
	events := decodeSSE(t, "id: 42\nretry: 500\ndata: a\n\ndata: b\n\n")
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(events), events)
	}
	first, second := events[0], events[1]
	if first.ID != "42" || !first.HasID || first.Retry != "500" {
		t.Fatalf("first = {ID:%q HasID:%v Retry:%q}, want 42/true/500", first.ID, first.HasID, first.Retry)
	}
	if second.ID != "42" || second.HasID {
		t.Fatalf("second = {ID:%q HasID:%v}, want persisted 42 with HasID false", second.ID, second.HasID)
	}
	if second.Retry != "" {
		t.Fatalf("second Retry = %q, want empty (retry never persists)", second.Retry)
	}
}

func TestSSEBlankLineSemantics(t *testing.T) {
	// A blank line without any data since the previous dispatch does not
	// dispatch, drops the pending event/retry fields, and the id persists.
	events := decodeSSE(t, "id: 7\nevent: boot\nretry: 9\n\ndata: x\n\n")
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Event != "message" {
		t.Fatalf("Event = %q, want message (pending event field was cleared)", ev.Event)
	}
	if ev.Retry != "" {
		t.Fatalf("Retry = %q, want empty (cleared with the blank line)", ev.Retry)
	}
	// The id: line is in the record's byte range (fields fold forward past
	// the non-dispatching blank), so HasID is true; the value also persists.
	if ev.ID != "7" || !ev.HasID {
		t.Fatalf("ID/HasID = %q/%v, want 7/true", ev.ID, ev.HasID)
	}

	// Extra blank lines never dispatch on their own and never duplicate.
	events = decodeSSE(t, "data: a\n\n\n\ndata: b\n\n")
	if len(events) != 2 || string(events[0].Data) != "a" || string(events[1].Data) != "b" {
		t.Fatalf("got %+v, want exactly data a then data b", events)
	}
}

func TestSSEIncrementalDispatch(t *testing.T) {
	d := NewDecoder()
	got, err := d.Feed([]byte("data: a\n"))
	if err != nil || len(got) != 0 {
		t.Fatalf("Feed(partial) = (%+v, %v), want no events", got, err)
	}
	got, err = d.Feed([]byte("\n"))
	if err != nil || len(got) != 1 || string(got[0].Data) != "a" {
		t.Fatalf("Feed(blank) = (%+v, %v), want the completed record a", got, err)
	}
	got, err = d.Feed([]byte("\n"))
	if err != nil || len(got) != 0 {
		t.Fatalf("Feed(extra blank) = (%+v, %v), want nothing", got, err)
	}
	if _, err := d.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestSSECRFAcrossChunkBoundary(t *testing.T) {
	events := decodeSSE(t, "data: a\r", "\n\r", "\n")
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if got := string(events[0].Raw); got != "data: a\r\n\r\n" {
		t.Fatalf("Raw = %q, want %q", got, "data: a\r\n\r\n")
	}
}

func TestSSEColonlessAndMultilineData(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		data  string
		spans int
	}{
		{"colon-less data is empty", "data\n\n", "", 0},
		{"colon-less then valued", "data\ndata: x\n\n", "\nx", 0},
		{"multi-line joined", "data: a\ndata: b\n\n", "a\nb", 0},
		{"two spaces keep one", "data:  x\n\n", " x", 1},
		{"no space", "data:x\n\n", "x", 1},
		{"empty colon form", "data:\n\n", "", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := singleEvent(t, tc.in)
			if string(ev.Data) != tc.data {
				t.Fatalf("Data = %q, want %q", ev.Data, tc.data)
			}
			if len(ev.DataSpans) != tc.spans {
				t.Fatalf("DataSpans = %+v, want %d spans", ev.DataSpans, tc.spans)
			}
			if tc.spans == 1 {
				sp := ev.DataSpans[0]
				if got := string(ev.Raw[sp.Start:sp.End]); got != tc.data {
					t.Fatalf("Raw span = %q, want %q", got, tc.data)
				}
			}
		})
	}
}

func TestSSEDataSpanOffsets(t *testing.T) {
	const in = "id: 9\ndata: hello\n\n"
	ev := singleEvent(t, in)
	if len(ev.DataSpans) != 1 {
		t.Fatalf("DataSpans = %+v, want one span", ev.DataSpans)
	}
	sp := ev.DataSpans[0]
	if sp.Start != 12 || sp.End != 17 {
		t.Fatalf("span = %+v, want {12 17}", sp)
	}
	if got := string(ev.Raw[sp.Start:sp.End]); got != "hello" {
		t.Fatalf("Raw span = %q, want hello", got)
	}
}

func TestSSECloseFlushesAndIsIdempotent(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"unterminated value", "data: tail"},
		{"terminated line no blank", "data: x\n"},
		{"lone cr terminator", "data: y\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDecoder()
			got, err := d.Feed([]byte(tc.in))
			if err != nil || len(got) != 0 {
				t.Fatalf("Feed(%q) = (%+v, %v), want no events before Close", tc.in, got, err)
			}
			events, err := d.Close()
			if err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("Close() = %+v, want exactly one flushed event", events)
			}
			if string(events[0].Raw) != tc.in {
				t.Fatalf("flushed Raw = %q, want %q", events[0].Raw, tc.in)
			}
			again, err := d.Close()
			if err != nil || len(again) != 0 {
				t.Fatalf("second Close() = (%+v, %v), want empty and nil", again, err)
			}
		})
	}

	d := NewDecoder()
	events, err := d.Close()
	if err != nil || len(events) != 0 {
		t.Fatalf("Close on empty decoder = (%+v, %v), want empty", events, err)
	}
	if _, err := d.Feed([]byte("data: x\n\n")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Feed after Close error = %v, want ErrClosed", err)
	}
}

func TestSSEUnknownFieldsIgnored(t *testing.T) {
	ev := singleEvent(t, "unknown: field\nbaz\ndata: v\n\n")
	if string(ev.Data) != "v" {
		t.Fatalf("Data = %q, want v", ev.Data)
	}
	if ev.Event != "message" {
		t.Fatalf("Event = %q, want message", ev.Event)
	}
}

// sseFixture mixes every terminator, comments, unknown fields, multi-line
// and colon-less data, and a record flushed by Close with no blank line.
func sseFixture() string {
	return ": header\r\n" +
		"event: delta\r\n" +
		"id: 12\r\n" +
		"retry: 300\r\n" +
		"data: one\r\n" +
		"data: two\r\n" +
		"\r\n" +
		": mid\n" +
		"data: solo\r\n" +
		"\n" +
		"unknown: field\n" +
		"data\r\n" +
		"\r" +
		"data: last"
}

func TestSSERawByteExactAcrossEverySplit(t *testing.T) {
	in := []byte(sseFixture())
	whole := decodeSSE(t, sseFixture())
	if len(whole) != 4 {
		t.Fatalf("whole decode returned %d events, want 4: %+v", len(whole), whole)
	}
	var joined []byte
	for _, ev := range whole {
		joined = append(joined, ev.Raw...)
	}
	if !bytes.Equal(joined, in) {
		t.Fatalf("concatenated Raw = %q, want fixture %q", joined, in)
	}
	for split := 0; split <= len(in); split++ {
		got := decodeSSE(t, string(in[:split]), string(in[split:]))
		if !reflect.DeepEqual(got, whole) {
			t.Fatalf("split at %d: events differ\n got: %+v\nwant: %+v", split, got, whole)
		}
	}
}

// TestSSEMalformedInputNeverPanics replays byte soup that is not valid SSE:
// the decoder must never panic, never error, and every emitted Raw must be a
// byte-exact prefix of the input.
func TestSSEMalformedInputNeverPanics(t *testing.T) {
	inputs := [][]byte{
		{0xff, 0xfe, '\r', 0x00, '\n', '\r', ':', 0x80},
		[]byte(": \xff\xfe\ndata: ok\n\n\x00\x00"),
		[]byte("\r\r\r\r"),
		[]byte("\x80:\x80\r\x80"),
	}
	for _, in := range inputs {
		d := NewDecoder()
		var joined []byte
		for pos := 0; pos < len(in); {
			n := int(in[pos]%7) + 1
			if pos+n > len(in) {
				n = len(in) - pos
			}
			events, err := d.Feed(in[pos : pos+n])
			if err != nil {
				t.Fatalf("Feed(%q) error = %v, want nil (SSE has no malformed input)", in, err)
			}
			for _, ev := range events {
				joined = append(joined, ev.Raw...)
				for _, sp := range ev.DataSpans {
					if sp.Start < 0 || sp.End < sp.Start || sp.End > len(ev.Raw) {
						t.Fatalf("input %q: span %+v outside Raw %q", in, sp, ev.Raw)
					}
				}
			}
			pos += n
		}
		tail, err := d.Close()
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		for _, ev := range tail {
			joined = append(joined, ev.Raw...)
		}
		if !bytes.HasPrefix(in, joined) {
			t.Fatalf("input %q: concatenated Raw %q is not a byte-exact prefix", in, joined)
		}
	}
}
