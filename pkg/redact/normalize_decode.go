package redact

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"unicode/utf8"
)

// zeroWidthSequences are the UTF-8 encodings of the zero-width characters an
// interleaving attack can insert between secret bytes. They are the only
// separators that span more than one byte.
var zeroWidthSequences = [][]byte{
	{0xe2, 0x80, 0x8b}, // U+200B zero width space
	{0xe2, 0x80, 0x8c}, // U+200C zero width non-joiner
	{0xe2, 0x80, 0x8d}, // U+200D zero width joiner
	{0xe2, 0x81, 0xa0}, // U+2060 word joiner
	{0xef, 0xbb, 0xbf}, // U+FEFF zero width no-break space
}

// separatorStripSets are the byte sets the separator decoder removes, one per
// separator convention. Form (1) interleaves spaces, dots or dashes; form (6)
// chunks in fours; form (10) is fold -w1 output whose separators are newlines,
// commas, colons, quotes and slashes. Emitting one candidate per set (and a
// union) is what lets a secret that itself contains one of these bytes survive
// a *different* separator, which a single global strip would corrupt.
var separatorStripSets = [][]byte{
	{' '},
	{'\t'},
	{'\r', '\n'},
	{'.'},
	{'-'},
	{','},
	{':'},
	{';'},
	{'"'},
	{'\''},
	{'/', '\\'},
	{'|'},
	{' ', '.', '-'},
	{'\n', '\r', ',', ':', '"', '\'', '/', '\\'},
	{' ', '\t', '\r', '\n', '.', '-', ',', ':', ';', '"', '\'', '/', '\\', '|'},
}

// unionSeparators is the widest strip set, used on the large-input path where
// only one candidate per window is afforded.
var unionSeparators = separatorStripSets[len(separatorStripSets)-1]

// decodeSeparators removes separator bytes and zero-width characters, including
// the JSON-escaped whitespace a fold -w1 payload gains when it is carried in a
// JSON string.
func decodeSeparators(in []byte) [][]byte {
	if len(in) > NormalizeMaxCandidateBytes {
		var out [][]byte
		for _, w := range windows(in) {
			out = append(out, removeSequences(removeBytes(w, unionSeparators), zeroWidthSequences))
			out = append(out, removeBytes(removeSequences(w, zeroWidthSequences), unionSeparators))
		}
		return out
	}
	variants := [][]byte{in}
	if u := unescapeOnce(in); u != nil && !bytes.Equal(u, in) {
		variants = append(variants, u)
	}
	var out [][]byte
	for _, v := range variants {
		if zw := removeSequences(v, zeroWidthSequences); !bytes.Equal(zw, v) {
			out = append(out, zw)
			for _, set := range separatorStripSets {
				out = append(out, removeBytes(zw, set))
			}
		}
		for _, set := range separatorStripSets {
			out = append(out, removeBytes(v, set))
		}
	}
	return out
}

// decodeEscapes reverses C / printf / JSON escapes: \xHH, \NNN (octal), \uHHHH,
// \UHHHHHHHH and the single-character escapes. It returns nothing when the
// input has no backslash, so the common case is a single index scan.
func decodeEscapes(in []byte) [][]byte {
	if bytes.IndexByte(in, '\\') < 0 {
		return nil
	}
	var out [][]byte
	if u := unescapeOnce(in); u != nil && !bytes.Equal(u, in) {
		out = append(out, u)
		// A second pass handles a doubly escaped payload without spending a
		// whole decode round on it.
		if u2 := unescapeOnce(u); !bytes.Equal(u2, u) {
			out = append(out, u2)
		}
	}
	// $'...' / "..." shell quoting: decode only the quoted payload so the
	// surrounding syntax does not end up in the candidate.
	if payload := dollarQuotedPayload(in); payload != nil {
		if u := unescapeOnce(payload); u != nil && !bytes.Equal(u, payload) {
			out = append(out, u)
		}
	}
	return out
}

// unescapeOnce expands backslash escapes in one left-to-right pass. An unknown
// escape keeps its backslash and lets the following byte be re-examined, which
// is what makes \\xHH decode correctly in two steps.
func unescapeOnce(in []byte) []byte {
	if bytes.IndexByte(in, '\\') < 0 {
		return nil
	}
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != '\\' || i+1 >= len(in) {
			out = append(out, c)
			continue
		}
		switch n := in[i+1]; n {
		case 'n':
			out = append(out, '\n')
			i++
		case 'r':
			out = append(out, '\r')
			i++
		case 't':
			out = append(out, '\t')
			i++
		case 'b':
			out = append(out, '\b')
			i++
		case 'f':
			out = append(out, '\f')
			i++
		case 'v':
			out = append(out, '\v')
			i++
		case '0':
			out = append(out, 0)
			i++
		case '\\', '\'', '"', '/':
			out = append(out, n)
			i++
		case 'x':
			if h, ok := hexByteAt(in[i+2:], 2); ok {
				out = append(out, h)
				i += 3
			} else {
				out = append(out, c)
			}
		case 'u':
			if r, ok := hexRuneAt(in[i+2:], 4); ok {
				out = append(out, r...)
				i += 5
			} else {
				out = append(out, c)
			}
		case 'U':
			if r, ok := hexRuneAt(in[i+2:], 8); ok {
				out = append(out, r...)
				i += 9
			} else {
				out = append(out, c)
			}
		default:
			if n >= '0' && n <= '7' {
				j, v := i+1, 0
				for ; j < len(in) && j < i+4 && in[j] >= '0' && in[j] <= '7'; j++ {
					v = v*8 + int(in[j]-'0')
				}
				out = append(out, byte(v))
				i = j - 1
			} else {
				out = append(out, c)
			}
		}
	}
	return out
}

// dollarQuotedPayload returns the bytes between a leading $' and the closing ',
// or nil when the input is not dollar-quoted. It is a best-effort slice: an
// escaped quote inside the payload ends it early, which leaves the outer
// unescape pass to finish the job.
func dollarQuotedPayload(in []byte) []byte {
	_, rest, found := bytes.Cut(in, []byte("$'"))
	if !found {
		return nil
	}
	if payload, _, ok := bytes.Cut(rest, []byte{'\''}); ok {
		return payload
	}
	return rest
}

// decodeHex decodes maximal hex runs, tolerating a trailing odd nibble.
func decodeHex(in []byte) [][]byte {
	var out [][]byte
	for _, run := range findRuns(in, isHexDigit, 4) {
		for _, w := range boundedWindows(run, maxRunBytes) {
			dec, err := hex.DecodeString(string(w))
			if err != nil && len(w) > 4 && len(w)%2 == 1 {
				dec, err = hex.DecodeString(string(w[:len(w)-1]))
			}
			if err == nil && len(dec) > 0 {
				out = append(out, dec)
			}
		}
	}
	return out
}

// base64Encodings covers the two alphabets with and without padding. -w0 output
// is a single unwrapped line, which is exactly what Raw* models for a short
// payload.
var base64Encodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

// decodeBase64 decodes maximal base64 runs under both alphabets and both
// padding conventions, and gunzips a result that carries the gzip magic.
func decodeBase64(in []byte) [][]byte {
	var out [][]byte
	for _, run := range findRuns(in, isBase64Byte, 8) {
		for _, w := range boundedWindows(run, maxRunBytes) {
			out = append(out, decodeBase64With(w)...)
		}
	}
	return out
}

func decodeBase64With(w []byte) [][]byte {
	var out [][]byte
	s := string(w)
	for _, enc := range base64Encodings {
		dec, err := enc.DecodeString(s)
		if err != nil || len(dec) == 0 {
			continue
		}
		out = append(out, dec)
		if gz := gunzipBounded(dec); gz != nil {
			out = append(out, gz)
		}
	}
	return out
}

// base32Encodings decodes upper-case base32 with and without padding.
var base32Encodings = []*base32.Encoding{
	base32.StdEncoding,
	base32.StdEncoding.WithPadding(base32.NoPadding),
}

// decodeBase32 decodes maximal base32 runs (case folded to upper, since the Go
// alphabet is upper-case) and gunzips a result that carries the gzip magic.
func decodeBase32(in []byte) [][]byte {
	var out [][]byte
	for _, run := range findRuns(in, isBase32Byte, 8) {
		for _, w := range boundedWindows(run, maxRunBytes) {
			s := string(bytes.ToUpper(w))
			for _, enc := range base32Encodings {
				dec, err := enc.DecodeString(s)
				if err != nil || len(dec) == 0 {
					continue
				}
				out = append(out, dec)
				if gz := gunzipBounded(dec); gz != nil {
					out = append(out, gz)
				}
			}
		}
	}
	return out
}

// decodePercent reverses percent/URL escapes over every %HH in the input.
func decodePercent(in []byte) [][]byte {
	if bytes.IndexByte(in, '%') < 0 {
		return nil
	}
	out := make([]byte, 0, len(in))
	changed := false
	for i := 0; i < len(in); i++ {
		if in[i] == '%' && i+2 < len(in) {
			hi, ok1 := hexVal(in[i+1])
			lo, ok2 := hexVal(in[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				changed = true
				continue
			}
		}
		out = append(out, in[i])
	}
	if !changed {
		return nil
	}
	return [][]byte{out}
}

func decodeRot13(in []byte) [][]byte  { return transformCandidates(in, rot13Byte) }
func decodeAtbash(in []byte) [][]byte { return transformCandidates(in, atbashByte) }
func decodeRot47(in []byte) [][]byte  { return transformCandidates(in, rot47Byte) }

func rot13Byte(c byte) byte {
	switch {
	case c >= 'a' && c <= 'z':
		return 'a' + (c-'a'+13)%26
	case c >= 'A' && c <= 'Z':
		return 'A' + (c-'A'+13)%26
	}
	return c
}

func atbashByte(c byte) byte {
	switch {
	case c >= 'a' && c <= 'z':
		return 'z' - (c - 'a')
	case c >= 'A' && c <= 'Z':
		return 'Z' - (c - 'A')
	}
	return c
}

// rot47Byte is the frozen ROT47 definition: only printable ASCII 33..126 is
// transformed and every other byte is left alone, which makes it self-inverse.
func rot47Byte(c byte) byte {
	if c >= 33 && c <= 126 {
		return 33 + (c-33+47)%94
	}
	return c
}

func isHexDigit(c byte) bool {
	_, ok := hexVal(c)
	return ok
}

func isBase64Byte(c byte) bool {
	return isASCIIAlnum(c) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

func isBase32Byte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') || c == '='
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// hexByteAt reads n hex digits into a single byte.
func hexByteAt(b []byte, n int) (byte, bool) {
	if len(b) < n || n > 2 {
		return 0, false
	}
	var v byte
	for i := range n {
		h, ok := hexVal(b[i])
		if !ok {
			return 0, false
		}
		v = v<<4 | h
	}
	return v, true
}

// hexRuneAt reads n hex digits into a UTF-8 rune, rejecting invalid runes.
func hexRuneAt(b []byte, n int) ([]byte, bool) {
	if len(b) < n {
		return nil, false
	}
	var v rune
	for i := range n {
		h, ok := hexVal(b[i])
		if !ok {
			return nil, false
		}
		v = v<<4 | rune(h)
	}
	if !utf8.ValidRune(v) {
		return nil, false
	}
	return []byte(string(v)), true
}

// removeBytes returns in with every byte in set removed. It returns in
// unchanged when no byte matches, so callers can skip a candidate.
func removeBytes(in, set []byte) []byte {
	var keep [256]bool
	for _, c := range set {
		keep[c] = true
	}
	removed := false
	for _, c := range in {
		if keep[c] {
			removed = true
			break
		}
	}
	if !removed {
		return in
	}
	out := make([]byte, 0, len(in))
	for _, c := range in {
		if !keep[c] {
			out = append(out, c)
		}
	}
	return out
}

// removeSequences deletes every occurrence of each multi-byte sequence.
func removeSequences(in []byte, seqs [][]byte) []byte {
	out := in
	for _, seq := range seqs {
		out = bytes.ReplaceAll(out, seq, nil)
	}
	return out
}
