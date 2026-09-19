package protocol

import (
	"bytes"
	"encoding/json"
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
		// D1 identity invariants: the cap is a predicate and never a
		// truncation, the canonical identity always begins with the leaf's
		// RFC 6901 pointer, and same-path leaves stay distinguishable by their
		// occurrence discriminator (the property F7 relies on).
		seen := make(map[string]map[string]bool, len(leaves))
		for _, l := range leaves {
			if l.Identifiable != (len(l.Identity) <= maxIdentityBytes) {
				t.Fatalf("leaf {Path:%q Identity:%q Identifiable:%v}: Identifiable must equal len(Identity) <= %d",
					l.Path, l.Identity, l.Identifiable, maxIdentityBytes)
			}
			if !strings.HasPrefix(l.Identity, l.Path) {
				t.Fatalf("leaf {Path:%q Identity:%q Identifiable:%v}: identity must begin with the leaf's path",
					l.Path, l.Identity, l.Identifiable)
			}
			ids := seen[l.Path]
			if ids == nil {
				ids = make(map[string]bool)
				seen[l.Path] = ids
			}
			if ids[l.Identity] {
				t.Fatalf("leaf {Path:%q Identity:%q Identifiable:%v}: same-path leaves share one identity",
					l.Path, l.Identity, l.Identifiable)
			}
			ids[l.Identity] = true
		}
	})
}

// FuzzApplyOnlyTouchesTheSpan pins the splice invariant: for any Walk-accepted
// input, replacing a leaf's whole decoded value may change bytes only inside
// the raw span RawSpan returned, and the result must stay valid JSON.
func FuzzApplyOnlyTouchesTheSpan(f *testing.F) {
	f.Add([]byte(`{"messages":[{"role":"user","content":"hello"}]}`))
	f.Add([]byte(`{"a":"x\ny","b":[1,true,null]}`))
	f.Add([]byte(`"top-level string"`))
	f.Add([]byte(`{"wrap":"{\"s\":\"x\"}"}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		leaves, err := Walk(in)
		if err != nil || len(leaves) == 0 {
			return
		}
		leaf := leaves[0]
		rs, re, ok := leaf.RawSpan(0, len(leaf.Value))
		if !ok {
			t.Fatalf("Walk leaf %+v is not locatable", leaf)
		}
		out, idx := Apply(in, []Edit{{Leaf: leaf, Start: 0, End: len(leaf.Value), Replacement: []byte("X")}})
		if !json.Valid(out) {
			t.Fatalf("output for %q is not valid JSON: %q", in, out)
		}
		if len(idx) == 0 {
			if !bytes.Equal(out, in) {
				t.Fatalf("no indices returned but body changed: %q -> %q", in, out)
			}
			return
		}
		if !bytes.Equal(out[:rs], in[:rs]) || !bytes.Equal(out[rs+1:], in[re:]) {
			t.Fatalf("output changed outside raw span %d..%d: %q -> %q", rs, re, in, out)
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
