package protocol

import (
	"bytes"
	"math/rand"
	"testing"
)

// testTokenMax is a generous ceiling the test grammar honours: no test
// builds a token longer than this, so the hold-back bound under test is the
// named SSEBackfillHoldbackBytes constant rather than MaxTokenLen.
const testTokenMax = 1 << 20

// testMatcher recognises the made-up token grammar <<[a-z]+>>.
type testMatcher struct{}

func (testMatcher) MaxTokenLen() int { return testTokenMax }

func (testMatcher) TokenLen(p []byte) int {
	if len(p) < 4 || p[0] != '<' || p[1] != '<' {
		return 0
	}
	i := 2
	for i < len(p) && isLowerLetter(p[i]) {
		i++
	}
	if i == 2 || i+2 > len(p) || p[i] != '>' || p[i+1] != '>' {
		return 0
	}
	return i + 2
}

func (testMatcher) PrefixLen(p []byte) int {
	if len(p) == 0 || p[0] != '<' {
		return 0
	}
	if len(p) == 1 || p[1] != '<' {
		return 1
	}
	i := 2
	for i < len(p) && isLowerLetter(p[i]) {
		i++
	}
	if i == len(p) {
		return i
	}
	if p[i] != '>' || i == 2 {
		return i
	}
	if i+1 < len(p) && p[i+1] == '>' {
		return i + 2
	}
	return i + 1
}

func isLowerLetter(b byte) bool { return b >= 'a' && b <= 'z' }

// identityReplace mirrors every token through unchanged.
func identityReplace(token []byte) []byte { return token }

// feedChunked feeds in in chunks of exactly size bytes, then flushes.
// size must be positive.
func feedChunked(w *BackfillWriter, in []byte, size int) []byte {
	out := []byte{}
	for len(in) > 0 {
		n := size
		if n > len(in) {
			n = len(in)
		}
		out = append(out, w.Feed(in[:n])...)
		in = in[n:]
	}
	return append(out, w.Flush()...)
}

func TestBackfillWriterReplacesCompleteToken(t *testing.T) {
	w := NewBackfillWriter(testMatcher{}, func([]byte) []byte { return []byte("[redacted]") })
	got := feedChunked(w, []byte("hello <<secret>> world"), 3)
	if want := "hello [redacted] world"; string(got) != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestBackfillWriterReplacesSplitTokenOnce(t *testing.T) {
	calls := 0
	w := NewBackfillWriter(testMatcher{}, func(token []byte) []byte {
		calls++
		return []byte("[R:" + string(token) + "]")
	})
	var got []byte
	for _, chunk := range []string{"a<<sec", "re", "t>>", "b"} {
		got = append(got, w.Feed([]byte(chunk))...)
	}
	got = append(got, w.Flush()...)
	if want := "a[R:<<secret>>]b"; string(got) != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if calls != 1 {
		t.Fatalf("ReplaceFunc called %d times, want 1", calls)
	}
}

func TestBackfillWriterReleasesIncompletePrefixOnFlush(t *testing.T) {
	w := NewBackfillWriter(testMatcher{}, identityReplace)
	got := w.Feed([]byte("tail <<unfinished"))
	if want := "tail "; string(got) != want {
		t.Fatalf("Feed = %q, want %q (prefix must be held)", got, want)
	}
	if want := len("<<unfinished"); w.Held() != want {
		t.Fatalf("Held() = %d, want %d", w.Held(), want)
	}
	if rest := w.Flush(); string(rest) != "<<unfinished" {
		t.Fatalf("Flush() = %q, want %q", rest, "<<unfinished")
	}
}

func TestBackfillWriterHoldsBackBound(t *testing.T) {
	w := NewBackfillWriter(testMatcher{}, identityReplace)
	blob := append([]byte("<<"), bytes.Repeat([]byte("a"), SSEBackfillHoldbackBytes+64)...)
	out := w.Feed(blob)
	if want := len(blob) - SSEBackfillHoldbackBytes; len(out) != want {
		t.Fatalf("Feed released %d bytes, want %d (progress past the bound)", len(out), want)
	}
	if w.Held() != SSEBackfillHoldbackBytes {
		t.Fatalf("Held() = %d, want %d", w.Held(), SSEBackfillHoldbackBytes)
	}
	if w.Held() > SSEBackfillHoldbackBytes {
		t.Fatalf("Held() = %d exceeds SSEBackfillHoldbackBytes", w.Held())
	}
	rest := w.Flush()
	if len(out)+len(rest) != len(blob) {
		t.Fatalf("released %d bytes, want %d", len(out)+len(rest), len(blob))
	}

	// At exactly the bound nothing is released yet; one more byte pushes
	// the oldest held byte out first.
	exact := append([]byte("<<"), bytes.Repeat([]byte("a"), SSEBackfillHoldbackBytes-2)...)
	w2 := NewBackfillWriter(testMatcher{}, identityReplace)
	if extra := w2.Feed(exact); extra != nil {
		t.Fatalf("Feed of exactly the bound released %q, want nothing", extra)
	}
	if w2.Held() != SSEBackfillHoldbackBytes {
		t.Fatalf("Held() = %d, want %d", w2.Held(), SSEBackfillHoldbackBytes)
	}
	if extra := w2.Feed([]byte("a")); string(extra) != "<" {
		t.Fatalf("Feed past the bound released %q, want the oldest byte %q", extra, "<")
	}
	if w2.Held() != SSEBackfillHoldbackBytes {
		t.Fatalf("Held() after trim = %d, want %d", w2.Held(), SSEBackfillHoldbackBytes)
	}
}

func TestBackfillWriterNeverDropsBytes(t *testing.T) {
	inputs := []string{
		"",
		"a",
		"<",
		"<<",
		"<<a",
		"<<a>>",
		"<<a>><<b>>",
		"x<<a>>y<<b>z",
		"<<<<a>>>>",
		"<<unclosed",
		"a<<secret>>b<<sec",
	}
	for _, in := range inputs {
		for _, size := range []int{1, 2, 3, 5, 17, 1 << 10} {
			if size > len(in)+1 {
				continue
			}
			w := NewBackfillWriter(testMatcher{}, identityReplace)
			if got := feedChunked(w, []byte(in), size); !bytes.Equal(got, []byte(in)) {
				t.Fatalf("input %q with chunk size %d: output %q", in, size, got)
			}
		}
	}

	rng := rand.New(rand.NewSource(20260917))
	alphabet := []byte("<>abcd ")
	for i := 0; i < 300; i++ {
		in := make([]byte, rng.Intn(256))
		for j := range in {
			in[j] = alphabet[rng.Intn(len(alphabet))]
		}
		for _, size := range []int{1, 2, 5, 13, 64, len(in) + 1} {
			w := NewBackfillWriter(testMatcher{}, identityReplace)
			if got := feedChunked(w, in, size); !bytes.Equal(got, in) {
				t.Fatalf("input %q with chunk size %d: output %q", in, size, got)
			}
		}
	}
}

func TestBackfillWriterTokenSpanningBound(t *testing.T) {
	w := NewBackfillWriter(testMatcher{}, func([]byte) []byte { return []byte("REPLACED") })
	content := bytes.Repeat([]byte("a"), SSEBackfillHoldbackBytes+64)
	token := append([]byte("<<"), append(content, '>', '>')...)
	split := len(token) - 2 // keep the closing ">>" for the second Feed

	out := w.Feed(token[:split])
	if want := split - SSEBackfillHoldbackBytes; len(out) != want {
		t.Fatalf("Feed released %d bytes, want %d", len(out), want)
	}
	if w.Held() > SSEBackfillHoldbackBytes {
		t.Fatalf("Held() = %d exceeds SSEBackfillHoldbackBytes", w.Held())
	}
	out = append(out, w.Feed(token[split:])...)
	out = append(out, w.Flush()...)
	if !bytes.Equal(out, token) {
		t.Fatalf("token straddling the bound must pass through literally: got %d bytes, want %d", len(out), len(token))
	}
	if bytes.Contains(out, []byte("REPLACED")) {
		t.Fatal("a token broken by the bound must not be replaced")
	}
}

func TestBackfillWriterFlushIdempotent(t *testing.T) {
	w := NewBackfillWriter(testMatcher{}, identityReplace)
	if got := w.Flush(); got != nil {
		t.Fatalf("Flush() on an empty writer = %q, want nil", got)
	}
	if got := w.Feed([]byte("<<par")); got != nil {
		t.Fatalf("Feed = %q, want nil (prefix held)", got)
	}
	first := w.Flush()
	if string(first) != "<<par" {
		t.Fatalf("Flush() = %q, want %q", first, "<<par")
	}
	if w.Held() != 0 {
		t.Fatalf("Held() = %d, want 0 after Flush", w.Held())
	}
	if second := w.Flush(); second != nil {
		t.Fatalf("second Flush() = %q, want nil", second)
	}
}

func TestBackfillWriterEmptyAndSingleByte(t *testing.T) {
	w := NewBackfillWriter(testMatcher{}, identityReplace)
	if got := w.Feed(nil); got != nil {
		t.Fatalf("Feed(nil) = %q, want nil", got)
	}
	if got := w.Feed([]byte{}); got != nil {
		t.Fatalf("Feed(empty) = %q, want nil", got)
	}
	if got := w.Feed([]byte("<")); got != nil {
		t.Fatalf("Feed(<) = %q, want nil (held)", got)
	}
	if got := w.Flush(); string(got) != "<" {
		t.Fatalf("Flush() = %q, want %q", got, "<")
	}
	if got := w.Feed([]byte("x")); string(got) != "x" {
		t.Fatalf("Feed(x) = %q, want %q", got, "x")
	}
}
