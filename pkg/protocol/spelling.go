package protocol

// escapeJSONString returns the content bytes of a JSON string literal that
// spells decoded: `"` and `\` are backslash-escaped, the control bytes below
// 0x20 use their short escapes where JSON defines one (\b \f \n \r \t) and
// \u00XX otherwise, and every other byte — including UTF-8 continuation bytes,
// `<`, `>`, `&` and `/` — is copied unchanged.
//
// It deliberately does NOT use encoding/json, which HTML-escapes `<`, `>`, `&`
// and replaces invalid UTF-8 with U+FFFD; both would change bytes the wire
// format did not require changing.
//
// Contract: decoded is never mutated. When no byte needs escaping the input
// slice is returned as-is; otherwise the result is a fresh allocation. Callers
// treat both the input and the result as read-only (RawSpelling passes its
// result straight into Apply as a replacement, which never writes it).
func escapeJSONString(decoded []byte) []byte {
	needs := false
	for _, c := range decoded {
		if c == '"' || c == '\\' || c < 0x20 {
			needs = true
			break
		}
	}
	if !needs {
		return decoded
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(decoded)+8)
	for _, c := range decoded {
		switch c {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hex[c>>4], hex[c&0x0f])
				continue
			}
			out = append(out, c)
		}
	}
	return out
}

// EscapeJSONString returns the JSON string interior spelling of decoded (one
// escaping level). Use RawSpelling on a Leaf when the enclosing depth is known.
func EscapeJSONString(decoded []byte) []byte { return escapeJSONString(decoded) }

// RawSpelling returns the raw bytes that spell decoded at this leaf's position
// in the Walk input: escapeJSONString applied once per enclosing JSON string
// wrapper (the tok chain). A hand-built leaf (nil tok) returns decoded
// unchanged. Use it to restore a placeholder into a client-bound body without
// corrupting the surrounding JSON.
func (l Leaf) RawSpelling(decoded []byte) []byte {
	out := decoded
	for n := l.tok; n != nil; n = n.parent {
		out = escapeJSONString(out)
	}
	return out
}
