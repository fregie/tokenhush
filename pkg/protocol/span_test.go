package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

// unescapeOnce decodes raw as the interior of one JSON string literal.
func unescapeOnce(t *testing.T, raw []byte) []byte {
	t.Helper()
	var s string
	if err := json.Unmarshal(append(append([]byte{'"'}, raw...), '"'), &s); err != nil {
		t.Fatalf("unescape %q: %v", raw, err)
	}
	return []byte(s)
}

// unescapeLayers peels n JSON string encodings off raw.
func unescapeLayers(t *testing.T, raw []byte, n int) []byte {
	t.Helper()
	for i := 0; i < n; i++ {
		raw = unescapeOnce(t, raw)
	}
	return raw
}

func TestMapSpanEscapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string // exact raw interior as it must appear in the body
		want string // decoded value
	}{
		{"escaped quote", `\"`, `"`},
		{"escaped backslash", `\\`, `\`},
		{"escaped slash", `\/`, `/`},
		{"backspace", `\b`, "\b"},
		{"formfeed", `\f`, "\f"},
		{"newline", `\n`, "\n"},
		{"carriage return", `\r`, "\r"},
		{"tab", `\t`, "\t"},
		{"u0001", `\u0001`, "\x01"},
		{"u003c", `\u003c`, "<"},
		{"literal non-ASCII", "é", "é"},
		{"surrogate pair emoji", `\ud83d\ude00`, "😀"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"k":"` + tc.raw + `"}`)
			leaves, err := Walk(body)
			if err != nil {
				t.Fatalf("Walk(%q) error = %v", body, err)
			}
			if len(leaves) != 1 {
				t.Fatalf("Walk(%q) = %+v, want exactly one leaf", body, leaves)
			}
			leaf := leaves[0]
			if string(leaf.Value) != tc.want {
				t.Fatalf("Value = %q, want decoded %q", leaf.Value, tc.want)
			}
			rs, re, ok := leaf.RawSpan(0, len(leaf.Value))
			if !ok {
				t.Fatalf("RawSpan(0,%d) not locatable", len(leaf.Value))
			}
			if got := string(body[rs:re]); got != tc.raw {
				t.Fatalf("raw span = %q, want exact spelling %q", got, tc.raw)
			}
			if body[rs-1] != '"' || body[re] != '"' {
				t.Fatalf("raw span %d..%d is not the string interior (quotes must be excluded)", rs, re)
			}
			replacement := []byte("REPL")
			out, idx := Apply(body, []Edit{{Leaf: leaf, Start: 0, End: len(leaf.Value), Replacement: replacement}})
			if len(idx) != 1 || idx[0] != 0 {
				t.Fatalf("Apply indices = %v, want [0]", idx)
			}
			if want := `{"k":"REPL"}`; string(out) != want {
				t.Fatalf("Apply output = %q, want %q", out, want)
			}
			if !bytes.Equal(out[:rs], body[:rs]) || !bytes.Equal(out[rs+len(replacement):], body[re:]) {
				t.Fatalf("Apply changed bytes outside raw span %d..%d", rs, re)
			}
		})
	}
}

// wrapDocument embeds doc as a JSON string value inside an object, so every
// byte of the original document gets escaped one real layer deeper.
func wrapDocument(t *testing.T, doc []byte) []byte {
	t.Helper()
	quoted, err := json.Marshal(string(doc))
	if err != nil {
		t.Fatalf("marshal wrapper: %v", err)
	}
	return []byte(`{"wrap":` + string(quoted) + `}`)
}

func TestRawSpanComposesThroughEncodedWrappers(t *testing.T) {
	secret := []byte("line1\n\"quoted\"\\end")
	quoted, err := json.Marshal(string(secret))
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	inner := []byte(`{"s":` + string(quoted) + `}`)
	placeholder := []byte("__PII_test_deadbeef__")
	for _, wraps := range []int{1, 2} {
		body := inner
		for i := 0; i < wraps; i++ {
			body = wrapDocument(t, body)
		}
		leaves, err := Walk(body)
		if err != nil {
			t.Fatalf("wraps=%d: Walk(%q) error = %v", wraps, body, err)
		}
		var leaf Leaf
		found := false
		for _, l := range leaves {
			if bytes.Equal(l.Value, secret) {
				leaf, found = l, true
				break
			}
		}
		if !found {
			t.Fatalf("wraps=%d: secret leaf not found among %+v", wraps, leaves)
		}
		if !leaf.Encoded {
			t.Fatalf("wraps=%d: secret leaf not marked Encoded", wraps)
		}
		rs, re, ok := leaf.RawSpan(0, len(secret))
		if !ok {
			t.Fatalf("wraps=%d: RawSpan(0,%d) not locatable", wraps, len(secret))
		}
		if !bytes.Contains(body[rs:re], []byte(`\`)) {
			t.Fatalf("wraps=%d: raw span %q is not the escaped spelling", wraps, body[rs:re])
		}
		if got := unescapeLayers(t, body[rs:re], wraps+1); !bytes.Equal(got, secret) {
			t.Fatalf("wraps=%d: decoding raw span gives %q, want secret %q", wraps, got, secret)
		}
		out, idx := Apply(body, []Edit{{Leaf: leaf, Start: 0, End: len(secret), Replacement: placeholder}})
		if len(idx) != 1 || idx[0] != 0 {
			t.Fatalf("wraps=%d: Apply indices = %v, want [0]", wraps, idx)
		}
		if bytes.Contains(out, secret) {
			t.Fatalf("wraps=%d: secret still present in output %q", wraps, out)
		}
		if !bytes.Contains(out, placeholder) {
			t.Fatalf("wraps=%d: placeholder missing from output %q", wraps, out)
		}
		if !json.Valid(out) {
			t.Fatalf("wraps=%d: output is not valid JSON: %q", wraps, out)
		}
		if !bytes.Equal(out[:rs], body[:rs]) {
			t.Fatalf("wraps=%d: bytes before span changed", wraps)
		}
		if !bytes.Equal(out[rs+len(placeholder):], body[re:]) {
			t.Fatalf("wraps=%d: bytes after span changed", wraps)
		}
	}
}

func TestApplyOverlapFirstWins(t *testing.T) {
	body := []byte(`{"k":"abcdef"}`)
	leaves, err := Walk(body)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("Walk(%q) = (%+v, %v), want one leaf", body, leaves, err)
	}
	leaf := leaves[0]
	edits := []Edit{
		{Leaf: leaf, Start: 0, End: 4, Replacement: []byte("XXXX")},
		{Leaf: leaf, Start: 2, End: 6, Replacement: []byte("YYYY")},
	}
	out, idx := Apply(body, edits)
	if len(idx) != 1 || idx[0] != 0 {
		t.Fatalf("Apply indices = %v, want exactly [0] (first in raw-start order wins)", idx)
	}
	if want := `{"k":"XXXXef"}`; string(out) != want {
		t.Fatalf("Apply output = %q, want %q", out, want)
	}
}

func TestApplyNoLocatorAndNoOp(t *testing.T) {
	body := []byte(`{"k":"abcdef"}`)
	leaves, err := Walk(body)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("Walk(%q) = (%+v, %v), want one leaf", body, leaves, err)
	}
	leaf := leaves[0]

	if _, _, ok := (Leaf{}).RawSpan(0, 0); ok {
		t.Fatal("hand-built Leaf must have no raw location")
	}
	out, idx := Apply(body, []Edit{{Leaf: Leaf{}, Start: 0, End: 3, Replacement: []byte("X")}})
	if len(idx) != 0 || !bytes.Equal(out, body) {
		t.Fatalf("unlocatable edit: out = %q, idx = %v; want unchanged body and no indices", out, idx)
	}

	out, idx = Apply(body, []Edit{{Leaf: leaf, Start: 0, End: 3, Replacement: []byte("abc")}})
	if len(idx) != 0 || !bytes.Equal(out, body) {
		t.Fatalf("no-op edit: out = %q, idx = %v; want unchanged body and no indices", out, idx)
	}
}

func TestApplyOutputStaysValidJSON(t *testing.T) {
	body := []byte(`{"k":"a\nb\"c","n":1}`)
	leaves, err := Walk(body)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("Walk(%q) = (%+v, %v), want one leaf", body, leaves, err)
	}
	leaf := leaves[0]
	placeholder := []byte("__PII_test_1__")
	out, idx := Apply(body, []Edit{{Leaf: leaf, Start: 0, End: len(leaf.Value), Replacement: placeholder}})
	if len(idx) != 1 {
		t.Fatalf("Apply indices = %v, want one", idx)
	}
	if !json.Valid(out) {
		t.Fatalf("output is not valid JSON: %q", out)
	}
	var decoded struct {
		K string `json:"k"`
		N int    `json:"n"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("Unmarshal(%q) error = %v", out, err)
	}
	if decoded.K != string(placeholder) || decoded.N != 1 {
		t.Fatalf("round-trip = %+v, want k=%q n=1", decoded, placeholder)
	}
}
