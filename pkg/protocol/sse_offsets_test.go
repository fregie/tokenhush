package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

// TestSSEEventDataOffsets locks the byte-range accounting behind DataSingle:
// for a single canonical data: line, the value must be exactly
// Raw[DataOffset:DataOffset+DataLen]; for zero, multiple, or colon-less data:
// lines DataSingle must be false; and HasID must report an id: line without
// touching the persistent ID.
func TestSSEEventDataOffsets(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		dataSingle bool
		wantValue  string
		hasID      bool
	}{
		{name: "single_space", input: "data: hello\n\n", dataSingle: true, wantValue: "hello"},
		{name: "single_no_space", input: "data:hello\n\n", dataSingle: true, wantValue: "hello"},
		{name: "single_double_space", input: "data:  x\n\n", dataSingle: true, wantValue: " x"},
		{name: "single_empty_value", input: "data:\n\n", dataSingle: true, wantValue: ""},
		{name: "after_fields_and_comment", input: ": c\nevent: e\nid: 9\ndata: payload\n\n", dataSingle: true, wantValue: "payload", hasID: true},
		{name: "multi_line", input: "data: a\ndata: b\n\n", dataSingle: false},
		{name: "colon_less", input: "data\n\n", dataSingle: false},
		{name: "multi_line_one_colon_less", input: "data: a\ndata\n\n", dataSingle: false},
		{name: "no_data", input: ": only comment\n\n", dataSingle: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evs := decodeChunks([][]byte{[]byte(tc.input)})
			if len(evs) != 1 {
				t.Fatalf("got %d events (%+v), want 1", len(evs), evs)
			}
			ev := evs[0]
			if ev.DataSingle != tc.dataSingle {
				t.Fatalf("DataSingle = %v, want %v", ev.DataSingle, tc.dataSingle)
			}
			if ev.HasID != tc.hasID {
				t.Fatalf("HasID = %v, want %v", ev.HasID, tc.hasID)
			}
			if got := string(joinRaw(evs)); got != tc.input {
				t.Fatalf("Raw join = %q, want input %q", got, tc.input)
			}
			if !tc.dataSingle {
				return
			}
			if ev.DataOffset < 0 || ev.DataOffset+ev.DataLen > len(ev.Raw) {
				t.Fatalf("data range [%d,%d) outside Raw (%d bytes)", ev.DataOffset, ev.DataOffset+ev.DataLen, len(ev.Raw))
			}
			if got := string(ev.Raw[ev.DataOffset : ev.DataOffset+ev.DataLen]); got != tc.wantValue {
				t.Fatalf("Raw data range = %q, want %q", got, tc.wantValue)
			}
		})
	}
}

// TestSSEEventDataOffsetChunkingInvariant proves the offset accounting is
// independent of how the stream is chunked and that Raw still reproduces the
// input byte-for-byte: for every two-way split, the decoded events (including
// DataSingle, DataOffset, DataLen and HasID) must be identical to the whole
// decode.
func TestSSEEventDataOffsetChunkingInvariant(t *testing.T) {
	input := []byte(sseFixture())
	whole := decodeChunks([][]byte{input})
	if raw := joinRaw(whole); !bytes.Equal(raw, input) {
		t.Fatalf("whole Raw join = %q, want input", raw)
	}
	for k := 0; k <= len(input); k++ {
		got := decodeChunks([][]byte{input[:k], input[k:]})
		if !reflect.DeepEqual(got, whole) {
			t.Fatalf("split at %d: events differ from whole decode:\n got %+v\nwant %+v", k, got, whole)
		}
		if raw := joinRaw(got); !bytes.Equal(raw, input) {
			t.Fatalf("split at %d: Raw join = %q, want input", k, raw)
		}
	}
}
