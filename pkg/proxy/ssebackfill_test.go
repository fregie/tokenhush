package proxy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// t4Placeholder is a syntactically valid placeholder token long enough to be
// split across several events; t4Secret is its client-visible replacement.
const (
	t4Placeholder = "__PII_api_key_deadbeefcafe__"
	t4Secret      = "sk-REAL-SECRET-9931"
)

// t4Replace mirrors the engine's BackfillFunc: the known token maps to the
// secret and every unknown token is returned unchanged.
func t4Replace(tok string) string {
	if tok == t4Placeholder {
		return t4Secret
	}
	return tok
}

// t4DeltaEvent renders one SSE record whose data payload is a delta.content
// JSON object carrying fragment.
func t4DeltaEvent(fragment string) string {
	return `data: {"delta":{"content":"` + fragment + `"}}` + "\n\n"
}

// t4Run drives chunks through a fresh backfiller and returns the output.
func t4Run(t *testing.T, chunks ...[]byte) []byte {
	t.Helper()
	var dst bytes.Buffer
	b := newSSEBackfiller(&dst, 128, t4Replace)
	for i, c := range chunks {
		n, err := b.Write(c)
		if err != nil {
			t.Fatalf("chunk %d: Write: %v", i, err)
		}
		if n != len(c) {
			t.Fatalf("chunk %d: Write returned %d, want %d", i, n, len(c))
		}
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	return dst.Bytes()
}

// TestSSEBackfillerRestoresSecretAcrossEvents is the R1 regression: a
// placeholder split across four JSON delta events has no contiguous `__PII_` in
// the raw stream, yet an SSE-aware backfiller restores the secret exactly once
// while preserving every framing byte. The single-write case additionally
// proves a complete event with an idle window is emitted within the same Write,
// not buffered until Flush.
func TestSSEBackfillerRestoresSecretAcrossEvents(t *testing.T) {
	fragments := []string{
		t4Placeholder[:4],
		t4Placeholder[4:12],
		t4Placeholder[12:20],
		t4Placeholder[20:],
	}
	var in strings.Builder
	for _, f := range fragments {
		in.WriteString(t4DeltaEvent(f))
	}
	in.WriteString("data: [DONE]\n\n")
	input := []byte(in.String())

	var want strings.Builder
	for range fragments[:len(fragments)-1] {
		want.WriteString(t4DeltaEvent(""))
	}
	want.WriteString(t4DeltaEvent(t4Secret))
	want.WriteString("data: [DONE]\n\n")
	wantBytes := []byte(want.String())

	t.Run("single_write_emits_without_flush", func(t *testing.T) {
		var dst bytes.Buffer
		b := newSSEBackfiller(&dst, 128, t4Replace)
		if _, err := b.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got := dst.Bytes(); !bytes.Equal(got, wantBytes) {
			t.Fatalf("before Flush:\n got %q\nwant %q", got, wantBytes)
		}
		if err := b.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got := dst.Bytes(); !bytes.Equal(got, wantBytes) {
			t.Fatalf("after Flush:\n got %q\nwant %q", got, wantBytes)
		}
	})

	t.Run("byte_at_a_time", func(t *testing.T) {
		var dst bytes.Buffer
		b := newSSEBackfiller(&dst, 128, t4Replace)
		for i := range input {
			if _, err := b.Write(input[i : i+1]); err != nil {
				t.Fatalf("byte %d: Write: %v", i, err)
			}
		}
		if err := b.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got := dst.Bytes(); !bytes.Equal(got, wantBytes) {
			t.Fatalf("byte-at-a-time:\n got %q\nwant %q", got, wantBytes)
		}
	})

	t.Run("chunk_sizes", func(t *testing.T) {
		for _, size := range []int{2, 3, 5, 7, 11} {
			var dst bytes.Buffer
			b := newSSEBackfiller(&dst, 128, t4Replace)
			for i := 0; i < len(input); i += size {
				end := min(i+size, len(input))
				if _, err := b.Write(input[i:end]); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
			if err := b.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if got := dst.Bytes(); !bytes.Equal(got, wantBytes) {
				t.Fatalf("chunk size %d:\n got %q\nwant %q", size, got, wantBytes)
			}
		}
	})

	got := t4Run(t, input)
	if !bytes.Contains(got, []byte(t4Secret)) {
		t.Errorf("restored output does not contain the secret: %q", got)
	}
	if bytes.Contains(got, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("output still contains a placeholder: %q", got)
	}
	if n := strings.Count(string(got), "\n\n"); n != len(fragments)+1 {
		t.Errorf("event count = %d, want %d: %q", n, len(fragments)+1, got)
	}
}

// TestSSEBackfillerDoesNotMergeUnchangedFields is the M3 negative regression:
// `changed` must mean "the replacement differs from the token", never "replace
// was called". A non-delta field (`/model`) whose first value ends in a byte
// that can start a placeholder opening (`gpt-4_` ends in '_') keeps the path's
// window open across events. If the path were released as changed anyway, the
// two values would be merged into `gpt-4_gpt-4o` and the events redistributed,
// corrupting a field the backfiller must never touch.
func TestSSEBackfillerDoesNotMergeUnchangedFields(t *testing.T) {
	input := []byte(
		`data: {"model":"gpt-4_","delta":{"content":"hi"}}` + "\n\n" +
			`data: {"model":"gpt-4o","delta":{"content":"there"}}` + "\n\n",
	)
	got := t4Run(t, input)
	if !bytes.Equal(got, input) {
		t.Fatalf("unchanged events were rewritten:\n got %q\nwant %q", got, input)
	}
	if bytes.Contains(got, []byte("gpt-4_gpt-4o")) {
		t.Fatalf("non-delta field was merged across events: %q", got)
	}
}

// TestSSEBackfillerRawData covers a non-JSON data payload: a single raw record
// is backfilled (no JSON quoting) and a placeholder split across two raw
// records is restored with the same run semantics as a JSON path.
func TestSSEBackfillerRawData(t *testing.T) {
	t.Run("single_record", func(t *testing.T) {
		input := []byte("data: " + t4Placeholder + "\n\n")
		want := []byte("data: " + t4Secret + "\n\n")
		if got := t4Run(t, input); !bytes.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("split_across_records", func(t *testing.T) {
		input := []byte("data: " + t4Placeholder[:8] + "\n\n" + "data: " + t4Placeholder[8:] + "\n\n")
		want := []byte("data: \n\n" + "data: " + t4Secret + "\n\n")
		if got := t4Run(t, input); !bytes.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}
