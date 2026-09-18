package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

// spellingBody builds a real JSON body whose innermost string value is secret
// and whose leaf sits behind depth JSON-in-JSON string wrappers.
func spellingBody(t *testing.T, secret string, depth int) []byte {
	t.Helper()
	quoted, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	body := []byte(`{"s":` + string(quoted) + `}`)
	for range depth {
		body = wrapDocument(t, body)
	}
	return body
}

// spellingLeaf returns the single leaf of body whose Value equals want.
func spellingLeaf(t *testing.T, body, want []byte) Leaf {
	t.Helper()
	leaves, err := Walk(body)
	if err != nil {
		t.Fatalf("Walk(%q) error = %v", body, err)
	}
	for _, l := range leaves {
		if bytes.Equal(l.Value, want) {
			return l
		}
	}
	t.Fatalf("Walk(%q) = %d leaves, none equal %q", body, len(leaves), want)
	return Leaf{}
}

// spellingSplice replaces the leaf's raw span with RawSpelling(decoded).
func spellingSplice(t *testing.T, body []byte, leaf Leaf, decoded []byte) []byte {
	t.Helper()
	rs, re, ok := leaf.RawSpan(0, len(decoded))
	if !ok {
		t.Fatalf("RawSpan(0,%d) not locatable", len(decoded))
	}
	out := make([]byte, 0, len(body)-(re-rs)+len(decoded)*2)
	out = append(out, body[:rs]...)
	out = append(out, leaf.RawSpelling(decoded)...)
	out = append(out, body[re:]...)
	return out
}

func TestEscapeJSONString(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"quote", `"`, `\"`},
		{"backslash", `\`, `\\`},
		{"newline", "\n", `\n`},
		{"carriage return", "\r", `\r`},
		{"tab", "\t", `\t`},
		{"backspace", "\b", `\b`},
		{"formfeed", "\f", `\f`},
		{"nul", "\x00", `\u0000`},
		{"soh", "\x01", `\u0001`},
		{"unit separator", "\x1f", `\u001f`},
		{"html and slash untouched", "a<b>c&d/e", "a<b>c&d/e"},
		{"latin-1 rune", "é", "é"},
		{"emoji", "😀", "😀"},
		{"mixed", "a\"b\\c\nd", `a\"b\\c\nd`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(tc.in)
			orig := append([]byte(nil), in...)
			got := escapeJSONString(in)
			if string(got) != tc.want {
				t.Fatalf("escapeJSONString(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if !bytes.Equal(in, orig) {
				t.Fatalf("input mutated: %q -> %q", orig, in)
			}
			assertNoRawByte(t, got)
		})
	}
}

// isHex4 reports whether b is exactly four hexadecimal digits.
func isHex4(b []byte) bool {
	if len(b) != 4 {
		return false
	}
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// assertNoRawByte checks that escaped contains no bare quote or control byte
// and that every backslash opens a complete JSON escape sequence.
func assertNoRawByte(t *testing.T, escaped []byte) {
	t.Helper()
	for i := 0; i < len(escaped); {
		c := escaped[i]
		if c == '"' {
			t.Fatalf("escaped output contains a raw quote at %d: %q", i, escaped)
		}
		if c < 0x20 {
			t.Fatalf("escaped output contains raw control byte 0x%02x at %d: %q", c, i, escaped)
		}
		if c != '\\' {
			i++
			continue
		}
		if i+1 >= len(escaped) {
			t.Fatalf("escaped output ends in a bare backslash: %q", escaped)
		}
		switch escaped[i+1] {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			i += 2
		case 'u':
			if i+6 > len(escaped) || !isHex4(escaped[i+2:i+6]) {
				t.Fatalf("malformed \\u escape at %d: %q", i, escaped)
			}
			i += 6
		default:
			t.Fatalf("backslash not opening an escape at %d: %q", i, escaped)
		}
	}
}

func TestEscapeJSONStringMatchesJSONSemantics(t *testing.T) {
	table := []string{
		"",
		"plain",
		`"`,
		`\`,
		"a\nb",
		"\x00\x01\x1f",
		"é😀",
		"a\"b\\c\nd",
		"<>&/",
	}
	for _, want := range table {
		escaped := escapeJSONString([]byte(want))
		var got string
		if err := json.Unmarshal([]byte(`"`+string(escaped)+`"`), &got); err != nil {
			t.Fatalf("escapeJSONString(%q) = %q, not a valid JSON string: %v", want, escaped, err)
		}
		if got != want {
			t.Fatalf("json round trip = %q, want %q (escaped %q)", got, want, escaped)
		}
	}
}

func TestRawSpellingDepth(t *testing.T) {
	secret := "line1\n\"quoted\"\\end"
	for d := 0; d <= 2; d++ {
		body := spellingBody(t, secret, d)
		leaf := spellingLeaf(t, body, []byte(secret))
		layers := 0
		for n := leaf.tok; n != nil; n = n.parent {
			layers++
		}
		if layers != d+1 {
			t.Errorf("depth %d: tok chain has %d layers, want %d", d, layers, d+1)
		}
		got := spellingSplice(t, body, leaf, []byte(secret))
		if !bytes.Equal(got, body) {
			t.Errorf("depth %d: splice mismatch\n got: %q\nwant: %q", d, got, body)
		}
		t.Logf("depth=%d observed wrapper layers=%d", d, layers)
	}
}

func TestRawSpellingHandBuiltLeaf(t *testing.T) {
	in := []byte("a\n\"b\\")
	if got := (Leaf{}).RawSpelling(in); !bytes.Equal(got, in) {
		t.Fatalf("hand-built leaf RawSpelling(%q) = %q, want unchanged", in, got)
	}
	if got := (Leaf{}).RawSpelling(nil); len(got) != 0 {
		t.Fatalf("hand-built leaf RawSpelling(nil) = %q, want empty", got)
	}
}

func TestRawSpellingKeepsOutputValidJSON(t *testing.T) {
	secret := "line1\n\"quoted\"\\end"
	for d := 0; d <= 2; d++ {
		body := spellingBody(t, secret, d)
		leaf := spellingLeaf(t, body, []byte(secret))
		got := spellingSplice(t, body, leaf, []byte(secret))
		if !json.Valid(got) {
			t.Fatalf("depth %d: spliced output is not valid JSON: %q", d, got)
		}
	}
}
