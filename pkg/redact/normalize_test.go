package redact

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// normalizeTestSecret assembles the fixture credential from fragments so no
// long literal secret is committed. It is alphanumeric on purpose: every
// separator-strip variant then leaves the bytes intact, and no covered encoding
// collides with a separator byte.
func normalizeTestSecret() string {
	return strings.Join([]string{"sk", "live", "4f8a2c9e", "71b3d650", "aa19ff02"}, "")
}

// normalizeTestEngine registers the fixture secret so the membership check the
// outbound re-check uses can be exercised end to end.
func normalizeTestEngine(t *testing.T) (*PlaceholderEngine, string) {
	t.Helper()
	secret := normalizeTestSecret()
	e := mustEngine(t)
	e.Placeholder(secret, "api_key")
	return e, secret
}

// jsonBody embeds encoded inside a larger JSON request body, the shape the
// outbound re-check sees in production. escapeJSON controls whether the payload
// is JSON-string-escaped first (the realistic case for text payloads); binary
// payloads (raw UTF-16LE) are inserted verbatim.
func jsonBody(encoded []byte, escapeJSON bool) []byte {
	payload := encoded
	if escapeJSON {
		payload = jsonEscape(encoded)
	}
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"`)
	body = append(body, payload...)
	body = append(body, []byte(`"}]}`)...)
	return body
}

// jsonEscape applies the JSON string escapes a client would use for the bytes.
func jsonEscape(in []byte) []byte {
	var b bytes.Buffer
	for _, c := range in {
		switch c {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(c)
		}
	}
	return b.Bytes()
}

// assertNormalizeRecovers is the C2 evidence: an encoded secret embedded in a
// larger body must be recovered as a candidate and hit the membership test.
func assertNormalizeRecovers(t *testing.T, e *PlaceholderEngine, secret string, encoded []byte, escapeJSON bool) {
	t.Helper()
	body := jsonBody(encoded, escapeJSON)
	candidates := NormalizeCandidates(body)
	if len(candidates) == 0 {
		t.Fatalf("NormalizeCandidates(%q) returned no candidates", body)
	}
	recovered := false
	for _, c := range candidates {
		if len(c) > NormalizeMaxCandidateBytes {
			t.Fatalf("candidate of %d bytes exceeds NormalizeMaxCandidateBytes %d", len(c), NormalizeMaxCandidateBytes)
		}
		if bytes.Contains(c, []byte(secret)) {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Fatalf("no candidate contains the secret; body=%q candidates=%d", body, len(candidates))
	}
	hit := false
	for _, c := range candidates {
		if ok, _ := e.ContainsKnownSecret(c); ok {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("ContainsKnownSecret hit no candidate; body=%q candidates=%d", body, len(candidates))
	}
}

// TestNormalizeCandidates locks the multi-form decoder set: each covered
// encoding gets one named subtest that encodes the fixture secret, embeds it in
// a larger body, and proves a candidate recovers it. The set is deliberately
// not a single normal form: an attacker picks one encoding, so every form needs
// its own decoder.
func TestNormalizeCandidates(t *testing.T) {
	e, secret := normalizeTestEngine(t)

	// (1) characters interleaved with spaces / dots / dashes / zero-width.
	t.Run("separators_space_dot_dash_zerowidth", func(t *testing.T) {
		for _, sep := range []string{" ", ".", "-", "\u200b"} {
			assertNormalizeRecovers(t, e, secret, interleaveBytes([]byte(secret), sep), true)
		}
	})

	// (2) lowercase and uppercase hex.
	t.Run("hex_lower_and_upper", func(t *testing.T) {
		lower := []byte(hex.EncodeToString([]byte(secret)))
		assertNormalizeRecovers(t, e, secret, lower, true)
		assertNormalizeRecovers(t, e, secret, bytes.ToUpper(lower), true)
	})

	// (3) od -tu1 -v decimal byte codes, with the octal offset column.
	t.Run("od_tu1_decimal_bytes", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, odTu1V([]byte(secret)), true)
	})

	// (4) rot13.
	t.Run("rot13", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, rot13Bytes([]byte(secret)), true)
	})

	// (5) base64: std and URL-safe, padded and raw (-w0 is a single unwrapped
	// line, which Raw* already models).
	t.Run("base64_std_url_padding_and_w0", func(t *testing.T) {
		encoders := []struct {
			name string
			enc  *base64.Encoding
		}{
			{"std_padded", base64.StdEncoding},
			{"std_raw_w0", base64.RawStdEncoding},
			{"url_padded", base64.URLEncoding},
			{"url_raw", base64.RawURLEncoding},
		}
		for _, c := range encoders {
			assertNormalizeRecovers(t, e, secret, []byte(c.enc.EncodeToString([]byte(secret))), true)
		}
	})

	// (6) four-character chunks.
	t.Run("four_char_chunks", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, fourCharChunks([]byte(secret), "-"), true)
		assertNormalizeRecovers(t, e, secret, fourCharChunks([]byte(secret), " "), true)
	})

	// (7) gzip then base64.
	t.Run("gzip_base64", func(t *testing.T) {
		gz := gzipBytes(t, []byte(secret))
		assertNormalizeRecovers(t, e, secret, []byte(base64.StdEncoding.EncodeToString(gz)), true)
	})

	// (8) base32, and base32 of gzip.
	t.Run("base32_and_base32_gzip", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, []byte(base32.StdEncoding.EncodeToString([]byte(secret))), true)
		gz := gzipBytes(t, []byte(secret))
		assertNormalizeRecovers(t, e, secret, []byte(base32.StdEncoding.EncodeToString(gz)), true)
	})

	// (9) percent / URL escapes.
	t.Run("percent_url", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, percentEncodeBytes([]byte(secret)), true)
	})

	// (10) fold -w1 newline-separated output.
	t.Run("fold_w1_newline_separated", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, foldW1Bytes([]byte(secret)), true)
	})

	// (11) ROT47 and atbash.
	t.Run("rot47_and_atbash", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, rot47Bytes([]byte(secret)), true)
		assertNormalizeRecovers(t, e, secret, atbashBytes([]byte(secret)), true)
	})

	// (12) $'\x..' / printf escapes.
	t.Run("dollar_hex_printf_escapes", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, dollarHexBytes([]byte(secret)), false)
	})

	// (13) UTF-16LE (iconv).
	t.Run("utf16le", func(t *testing.T) {
		assertNormalizeRecovers(t, e, secret, utf16LEBytes(secret), false)
	})
}

// TestNormalizeBounded locks the cost ceiling: oversized input short-circuits,
// in-cap high-entropy input stays within every candidate bound, a deeply nested
// payload terminates inside the round cap, and a compression bomb cannot expand
// past the candidate cap.
func TestNormalizeBounded(t *testing.T) {
	t.Run("oversized_input_short_circuits", func(t *testing.T) {
		big := make([]byte, NormalizeMaxInputBytes+1)
		for i := range big {
			big[i] = byte(i*7 + 13)
		}
		start := time.Now()
		got := NormalizeCandidates(big)
		elapsed := time.Since(start)
		if len(got) != 0 {
			t.Fatalf("oversized input yielded %d candidates, want none", len(got))
		}
		if elapsed > 5*time.Second {
			t.Fatalf("oversized input took %v, want a short circuit", elapsed)
		}
		t.Logf("oversized input: %d bytes -> %d candidates in %v", len(big), len(got), elapsed)
	})

	t.Run("in_cap_high_entropy_stays_bounded", func(t *testing.T) {
		big := make([]byte, NormalizeMaxInputBytes/2)
		for i := range big {
			big[i] = byte(i*31 + 7)
		}
		start := time.Now()
		got := NormalizeCandidates(big)
		elapsed := time.Since(start)
		assertCandidateBounds(t, got)
		if elapsed > 10*time.Second {
			t.Fatalf("in-cap high-entropy input took %v", elapsed)
		}
		t.Logf("in-cap high entropy: %d bytes -> %d candidates, %d candidate bytes in %v",
			len(big), len(got), candidateBytes(got), elapsed)
	})

	t.Run("deep_nesting_beyond_round_cap_terminates", func(t *testing.T) {
		secret := normalizeTestSecret()
		layer := []byte(secret)
		for i := 0; i < 20; i++ {
			layer = []byte(base64.StdEncoding.EncodeToString(layer))
		}
		start := time.Now()
		got := NormalizeCandidates(jsonBody(layer, true))
		elapsed := time.Since(start)
		assertCandidateBounds(t, got)
		for _, c := range got {
			if bytes.Contains(c, []byte(secret)) {
				t.Fatalf("20 nested base64 layers reached the secret within %d rounds", NormalizeMaxRounds)
			}
		}
		t.Logf("20-layer base64: -> %d candidates in %v (round cap %d)", len(got), elapsed, NormalizeMaxRounds)
	})

	t.Run("gzip_bomb_decompressed_size_bounded", func(t *testing.T) {
		// 4 MiB of zeros compresses to a few KiB. The decompressed-size cap must
		// reject it instead of materialising the buffer.
		bomb := gzipBytes(t, make([]byte, 4<<20))
		bodies := [][]byte{bomb, []byte(base64.StdEncoding.EncodeToString(bomb))}
		for _, body := range bodies {
			got := NormalizeCandidates(body)
			assertCandidateBounds(t, got)
			for _, c := range got {
				if len(c) > NormalizeMaxCandidateBytes {
					t.Fatalf("gzip bomb produced a %d-byte candidate", len(c))
				}
			}
		}
		t.Logf("gzip bomb: compressed %d bytes, all candidates within %d bytes", len(bomb), NormalizeMaxCandidateBytes)
	})
}

// TestKnownUncoveredEncodings locks the honesty list to its documentation
// artifact: the accessor must be non-empty, must equal the file byte for byte
// (so the two cannot drift), and must explicitly record the od -tu1 (no -v)
// collapse and arbitrary multi-layer custom encodings.
func TestKnownUncoveredEncodings(t *testing.T) {
	list := KnownUncoveredEncodings()
	if len(list) == 0 {
		t.Fatal("KnownUncoveredEncodings() is empty")
	}

	path := filepath.Join("testdata", "known_uncovered_encodings.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		t.Fatalf("%s is empty", path)
	}
	parsed := parseUncoveredList(raw)
	if !equalStrings(list, parsed) {
		t.Fatalf("accessor and %s drifted:\n accessor=%q\n file=%q", path, list, parsed)
	}

	if !anyLineContains(list, "od -tu1") || !anyLineContains(list, "without -v") {
		t.Fatalf("the od -tu1 (no -v) '*' collapse is not recorded: %q", list)
	}
	if !anyLineContains(list, "custom") {
		t.Fatalf("arbitrary multi-layer custom/non-standard encodings are not recorded: %q", list)
	}
	t.Logf("known uncovered classes (%d): %q", len(list), list)
}

// parseUncoveredList parses one class per line, dropping blank lines and '#'.
func parseUncoveredList(raw []byte) []string {
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func anyLineContains(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func assertCandidateBounds(t *testing.T, got [][]byte) {
	t.Helper()
	if len(got) > NormalizeMaxCandidates {
		t.Fatalf("candidate count %d exceeds NormalizeMaxCandidates %d", len(got), NormalizeMaxCandidates)
	}
	for _, c := range got {
		if len(c) > NormalizeMaxCandidateBytes {
			t.Fatalf("candidate of %d bytes exceeds NormalizeMaxCandidateBytes %d", len(c), NormalizeMaxCandidateBytes)
		}
	}
	if total := candidateBytes(got); total > NormalizeMaxCandidates*NormalizeMaxCandidateBytes {
		t.Fatalf("total candidate bytes %d exceeds the cap", total)
	}
}

func candidateBytes(got [][]byte) int {
	total := 0
	for _, c := range got {
		total += len(c)
	}
	return total
}

// --- fixture encoders (test-only, hermetic: no shelling out) ---

// odTu1V reproduces `od -tu1 -v` byte for byte: a seven-digit octal offset then
// each byte right-aligned in four columns, sixteen bytes per line, with a
// trailing offset-only line.
func odTu1V(data []byte) []byte {
	var b strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(&b, "%07o", off)
		for _, c := range data[off:end] {
			fmt.Fprintf(&b, "%4d", c)
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%07o\n", len(data))
	return []byte(b.String())
}

func rot13Bytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + (c-'A'+13)%26
		default:
			out[i] = c
		}
	}
	return out
}

// rot47Bytes follows the frozen definition: only printable ASCII 33..126 is
// transformed, every other byte is unchanged, so the transform is self-inverse.
func rot47Bytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		if c >= 33 && c <= 126 {
			out[i] = 33 + (c-33+47)%94
		} else {
			out[i] = c
		}
	}
	return out
}

func atbashBytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'z' - (c - 'a')
		case c >= 'A' && c <= 'Z':
			out[i] = 'Z' - (c - 'A')
		default:
			out[i] = c
		}
	}
	return out
}

func interleaveBytes(in []byte, sep string) []byte {
	parts := make([]string, len(in))
	for i, c := range in {
		parts[i] = string(c)
	}
	return []byte(strings.Join(parts, sep))
}

func fourCharChunks(in []byte, sep string) []byte {
	var parts []string
	for i := 0; i < len(in); i += 4 {
		end := i + 4
		if end > len(in) {
			end = len(in)
		}
		parts = append(parts, string(in[i:end]))
	}
	return []byte(strings.Join(parts, sep))
}

func percentEncodeBytes(in []byte) []byte {
	var b strings.Builder
	for _, c := range in {
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return []byte(b.String())
}

func foldW1Bytes(in []byte) []byte {
	parts := make([]string, len(in))
	for i, c := range in {
		parts[i] = string(c)
	}
	return []byte(strings.Join(parts, "\n"))
}

func dollarHexBytes(in []byte) []byte {
	var b strings.Builder
	b.WriteString("$'")
	for _, c := range in {
		fmt.Fprintf(&b, "\\x%02x", c)
	}
	b.WriteString("'")
	return []byte(b.String())
}

func utf16LEBytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func gzipBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(in); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
