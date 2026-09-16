package redact

import (
	"bytes"
	"compress/gzip"
	"io"
	"unicode/utf16"
)

// odOffsetDigits is the width of the octal byte-offset column od prints at the
// start of every line, for example "0000000". Byte values are at most three
// digits wide, so a seven-digit all-octal field can only be an offset.
const odOffsetDigits = 7

// decodeDecimalBytes decodes od -tu1 decimal byte code output. The fixture is
// frozen as od -tu1 -v; the -v-less layout collapses a run of sixteen identical
// bytes to "*" and is recorded in the known uncovered list instead.
func decodeDecimalBytes(in []byte) [][]byte {
	variants := [][]byte{in}
	if w := unescapeWhitespace(in); !bytes.Equal(w, in) {
		variants = append(variants, w)
	}
	var out [][]byte
	for _, v := range variants {
		for _, run := range odByteRuns(v) {
			out = append(out, byteRunCandidates(run)...)
		}
	}
	return out
}

// odByteRuns collects runs of decimal byte tokens. Per line it drops the
// leading octal offset column, so the bytes of consecutive lines stay in one
// run instead of being split by the offset values (which would corrupt the
// secret with the offset's own numeric value). Any non-byte field flushes the
// run, which keeps surrounding JSON text and numbers out of the decoded bytes.
func odByteRuns(in []byte) [][]byte {
	var runs [][]byte
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			runs = append(runs, cur)
			cur = nil
		}
	}
	for line := range bytes.SplitSeq(in, []byte{'\n'}) {
		if len(runs) >= maxRunsPerDecoder {
			break
		}
		fields := bytes.Fields(line)
		if len(fields) > 0 && isOctalOffset(fields[0]) {
			fields = fields[1:]
		}
		for _, f := range fields {
			if v, ok := parseDecimalByte(f); ok {
				cur = append(cur, v)
				continue
			}
			flush()
		}
	}
	flush()
	return runs
}

// byteRunCandidates returns a decoded byte run plus bounded suffixes of it. The
// suffix extraction is the sliding window od output needs when a run picks up
// extra numeric tokens; it is capped so a long run cannot cost quadratic time.
func byteRunCandidates(run []byte) [][]byte {
	out := boundedWindows(run, NormalizeMaxCandidateBytes)
	maxStart := min(len(run)-1, odSuffixStarts)
	for start := 1; start < maxStart; start++ {
		suffix := run[start:]
		if len(suffix) > NormalizeMaxCandidateBytes {
			suffix = suffix[:NormalizeMaxCandidateBytes]
		}
		out = append(out, suffix)
	}
	return out
}

// isOctalOffset reports whether f is a seven-digit octal od offset field.
func isOctalOffset(f []byte) bool {
	if len(f) != odOffsetDigits {
		return false
	}
	for _, c := range f {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}

// parseDecimalByte parses a one-to-three digit decimal byte value in 0..255.
func parseDecimalByte(f []byte) (byte, bool) {
	if len(f) == 0 || len(f) > 3 {
		return 0, false
	}
	v := 0
	for _, c := range f {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	if v > 255 {
		return 0, false
	}
	return byte(v), true
}

// unescapeWhitespace turns the two-character \n, \r and \t sequences into real
// whitespace, so od's line structure survives being carried in a JSON string.
func unescapeWhitespace(in []byte) []byte {
	if bytes.IndexByte(in, '\\') < 0 {
		return in
	}
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] == '\\' && i+1 < len(in) {
			switch in[i+1] {
			case 'n', 'r':
				out = append(out, '\n')
				i++
				continue
			case 't':
				out = append(out, '\t')
				i++
				continue
			}
		}
		out = append(out, in[i])
	}
	return out
}

// decodeUTF16 decodes UTF-16LE and UTF-16BE. The whole input is tried only when
// enough high bytes are zero to look like ASCII text in a UTF-16 encoding;
// otherwise the decoder pulls out the maximal ASCII-in-UTF-16 runs, which is
// what an iconv payload embedded in a larger body looks like.
func decodeUTF16(in []byte) [][]byte {
	var out [][]byte
	if s := utf16Whole(in, false); s != nil {
		out = append(out, s)
	}
	if s := utf16Whole(in, true); s != nil {
		out = append(out, s)
	}
	out = append(out, utf16Runs(in, false)...)
	out = append(out, utf16Runs(in, true)...)
	return out
}

// utf16Runs returns the decoded form of each maximal run of the ASCII-in-UTF-16
// pattern: a printable ASCII byte whose adjacent byte is 0x00.
func utf16Runs(in []byte, bigEndian bool) [][]byte {
	var out [][]byte
	i := 0
	for i+1 < len(in) && len(out) < maxRunsPerDecoder {
		if !isASCIIUTF16Pair(in, i, bigEndian) {
			i++
			continue
		}
		start := i
		for i+1 < len(in) && isASCIIUTF16Pair(in, i, bigEndian) {
			i += 2
		}
		if i-start >= 8 {
			if s := decodeUTF16Slice(in[start:i], bigEndian); s != nil {
				out = append(out, s)
			}
		}
	}
	return out
}

// utf16Whole decodes the entire input when at least a third of its high bytes
// are zero, which rejects ordinary text without a UTF-16 structure.
func utf16Whole(in []byte, bigEndian bool) []byte {
	if len(in) < 4 || len(in)%2 != 0 || len(in) > maxRunBytes {
		return nil
	}
	zeros := 0
	for i := 0; i+1 < len(in); i += 2 {
		hi := in[i+1]
		if bigEndian {
			hi = in[i]
		}
		if hi == 0 {
			zeros++
		}
	}
	if zeros*3 < len(in)/2 {
		return nil
	}
	return decodeUTF16Slice(in, bigEndian)
}

func isASCIIUTF16Pair(in []byte, i int, bigEndian bool) bool {
	lo, hi := in[i], in[i+1]
	if bigEndian {
		lo, hi = hi, lo
	}
	return hi == 0 && lo >= 0x20 && lo <= 0x7e
}

// decodeUTF16Slice decodes an even-length byte slice into UTF-8. Invalid
// surrogate pairs become U+FFFD rather than an error, which is fine for a
// membership scan.
func decodeUTF16Slice(b []byte, bigEndian bool) []byte {
	if len(b) < 2 || len(b)%2 != 0 {
		return nil
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			units = append(units, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			units = append(units, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	s := []byte(string(utf16.Decode(units)))
	if len(s) == 0 {
		return nil
	}
	return s
}

// decodeGzip gunzips an input that carries the gzip magic.
func decodeGzip(in []byte) [][]byte {
	if gz := gunzipBounded(in); gz != nil {
		return [][]byte{gz}
	}
	return nil
}

// gunzipBounded decompresses at most NormalizeMaxCandidateBytes+1 bytes and
// rejects anything larger. The limit is on the *decompressed* size, so a
// compression bomb is stopped after a bounded read instead of expanding fully.
func gunzipBounded(in []byte) []byte {
	if len(in) < 2 || in[0] != 0x1f || in[1] != 0x8b {
		return nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, NormalizeMaxCandidateBytes+1))
	if err != nil || len(data) == 0 || len(data) > NormalizeMaxCandidateBytes {
		return nil
	}
	return data
}
