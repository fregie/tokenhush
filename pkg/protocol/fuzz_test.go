package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzWalk(f *testing.F) {
	f.Add([]byte(`{"messages":[{"role":"user","content":{"text":"hello"}}],"token":"eyJhIjoxfQ=="}`))
	f.Add([]byte(`{"messages":[{"content":"truncated`))
	f.Add([]byte(strings.Repeat("[", MaxNestingDepth+1)))
	f.Add([]byte{0xff, 0xfe, 0x80, 0x00})
	f.Add([]byte(`{"leaf":"c2VjcmV0"}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		leaves, err := Walk(in)
		if err != nil && leaves != nil {
			t.Fatalf("Walk returned %d leaves together with error %v; errors must carry no leaves", len(leaves), err)
		}
	})
}

func FuzzSSE(f *testing.F) {
	f.Add([]byte("event: delta\nid: 7\ndata: {\"a\":1}\ndata: tail\n\n"))
	f.Add([]byte("data: split-me-across-chunks\nretry: 250\n\n"))
	f.Add([]byte("data: cr\rid: 3\rdata: lf\n\n"))
	f.Add([]byte(": comment\n: another\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		dec := NewDecoder()
		var events []Event
		for pos := 0; pos < len(in); {
			// Derive the chunk boundary from the input byte itself so the
			// corpus explores every split point rather than a fixed stride.
			n := int(in[pos]%9) + 1
			if pos+n > len(in) {
				n = len(in) - pos
			}
			got, err := dec.Feed(in[pos : pos+n])
			if err != nil {
				t.Fatalf("Feed(%d bytes at %d) error = %v", n, pos, err)
			}
			events = append(events, got...)
			pos += n
		}
		tail, err := dec.Close()
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		events = append(events, tail...)
		again, err := dec.Close()
		if err != nil || len(again) != 0 {
			t.Fatalf("second Close() = (%+v, %v), want empty and nil", again, err)
		}

		var joined []byte
		for i, ev := range events {
			joined = append(joined, ev.Raw...)
			if n := len(ev.DataSpans); n > 1 {
				t.Fatalf("event %d: %d data spans, want 0 or 1", i, n)
			}
			if len(ev.DataSpans) == 1 {
				sp := ev.DataSpans[0]
				if sp.Start < 0 || sp.End < sp.Start || sp.End > len(ev.Raw) {
					t.Fatalf("event %d: span %+v outside Raw of %d bytes", i, sp, len(ev.Raw))
				}
				if !bytes.Equal(ev.Raw[sp.Start:sp.End], ev.Data) {
					t.Fatalf("event %d: Raw span %q != Data %q", i, ev.Raw[sp.Start:sp.End], ev.Data)
				}
			}
		}
		if !bytes.HasPrefix(in, joined) {
			t.Fatalf("concatenated Raw %q is not a byte-exact prefix of input %q", joined, in)
		}
	})
}
