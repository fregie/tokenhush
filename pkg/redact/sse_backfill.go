package redact

import (
	"bytes"
	"strings"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// placeholderLiteralPrefix is the immutable head of the frozen placeholder
// grammar (see placeholder.go).
const placeholderLiteralPrefix = "__PII_"

// placeholderMatcher teaches the protocol backfill writer the frozen
// placeholder grammar __PII_<type>_<digest>__: a 1..16 byte type over
// [a-z0-9_] and a 12..64 lowercase hex-digit digest. The grammar is ambiguous
// on paper (types may carry hex digits and underscores), so both matchers try
// every split instead of committing to a greedy one.
type placeholderMatcher struct{}

// MaxTokenLen reports the worst-case placeholder length.
func (placeholderMatcher) MaxTokenLen() int { return MaxPlaceholderLen }

// TokenLen returns the byte length of the complete placeholder at the start of
// p, or 0 when p starts with an incomplete or invalid one. Every type length is
// tried and the shortest complete token wins.
func (placeholderMatcher) TokenLen(p []byte) int {
	best := 0
	for t := 1; t <= maxTypeLen; t++ {
		sep := len(placeholderLiteralPrefix) + t
		if sep >= len(p) || p[sep] != placeholderSep[0] {
			continue
		}
		d := hexRun(p[sep+1:])
		for l := minDigestLen; l <= d && l <= maxDigestLen; l++ {
			end := sep + 1 + l + len(placeholderSuffix)
			if end > len(p) {
				break
			}
			if string(p[sep+1+l:end]) != placeholderSuffix {
				continue
			}
			if best == 0 || end < best {
				best = end
			}
			break
		}
	}
	return best
}

// PrefixLen returns the largest k <= len(p) whose first k bytes can still grow
// into a valid placeholder. "Is a placeholder prefix" is downward-closed, so
// the scan stops at the first byte that leaves the grammar.
func (placeholderMatcher) PrefixLen(p []byte) int {
	k := 0
	for k < len(p) && isPlaceholderPrefix(p[:k+1]) {
		k++
	}
	return k
}

// isPlaceholderPrefix reports whether s could be the head of a valid
// placeholder.
func isPlaceholderPrefix(s []byte) bool {
	if len(s) <= len(placeholderLiteralPrefix) {
		return strings.HasPrefix(placeholderLiteralPrefix, string(s))
	}
	if string(s[:len(placeholderLiteralPrefix)]) != placeholderLiteralPrefix {
		return false
	}
	rest := s[len(placeholderLiteralPrefix):]
	for t := 1; t <= maxTypeLen; t++ {
		if len(rest) <= t {
			return allTypeChars(rest)
		}
		if rest[t] != placeholderSep[0] {
			continue
		}
		d := hexRun(rest[t+1:])
		rem := rest[t+1+d:]
		if d == len(rest)-t-1 {
			return d <= maxDigestLen
		}
		if rem[0] != placeholderSep[0] || d < minDigestLen || d > maxDigestLen {
			continue
		}
		if len(rem) == 1 || (len(rem) == 2 && rem[1] == placeholderSep[0]) {
			return true
		}
	}
	return false
}

// hexRun returns the length of the leading run of lowercase hex digits in b.
func hexRun(b []byte) int {
	n := 0
	for n < len(b) && isHexDigit(b[n]) {
		n++
	}
	return n
}

// isHexDigit reports whether c is a lowercase hex digit, the only case the
// engine mints.
func isHexDigit(c byte) bool { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') }

// allTypeChars reports whether every byte of s is in the type alphabet.
func allTypeChars(s []byte) bool {
	for _, c := range s {
		if !isTypeChar(c) {
			return false
		}
	}
	return true
}

// isTypeChar reports whether c may appear in a sanitized <type> segment.
func isTypeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}

// SSEBackfiller restores placeholders a stream split across SSE data deltas.
// It reuses the session Backfiller's reverse map and exclusion set, so only a
// token this session minted is ever expanded: an unknown, foreign or excluded
// token comes back unchanged and is never fabricated into a secret.
type SSEBackfiller struct{ back *Backfiller }

// NewSSEBackfiller returns a backfiller driven by back's session map. A nil
// backfiller gets a fresh, empty one so no token can expand to a secret.
func NewSSEBackfiller(back *Backfiller) *SSEBackfiller {
	if back == nil {
		back = NewBackfiller()
	}
	return &SSEBackfiller{back: back}
}

// sseSpan is one data-value byte range of the input plus the bytes the writer
// released for it.
type sseSpan struct {
	start, end int
	out        []byte
}

// Process restores every placeholder a delta split and returns the rewritten
// stream. The splice-by-offset pass copies the input verbatim and rewrites only
// single "data:" value spans, so SSE framing, field lines, comments and byte
// counts are preserved and no byte is ever dropped. Held bytes always sit at
// the tail of the last-fed data, so the final Flush returns an unfinished
// prefix to that same span and a stream with nothing to restore comes back
// byte-identical.
func (s *SSEBackfiller) Process(stream []byte) []byte {
	dec := protocol.NewDecoder()
	events, _ := dec.Feed(stream)
	tail, _ := dec.Close()
	events = append(events, tail...)

	w := protocol.NewBackfillWriter(placeholderMatcher{}, func(tok []byte) []byte {
		return s.back.Backfill(tok)
	})

	spans := make([]sseSpan, 0, len(events))
	cursor := 0
	for _, ev := range events {
		idx := bytes.Index(stream[cursor:], ev.Raw)
		if idx < 0 {
			continue
		}
		abs := cursor + idx
		cursor = abs + len(ev.Raw)
		if len(ev.DataSpans) != 1 {
			continue
		}
		sp := ev.DataSpans[0]
		start, end := abs+sp.Start, abs+sp.End
		spans = append(spans, sseSpan{start: start, end: end, out: w.Feed(stream[start:end])})
	}
	if len(spans) == 0 {
		return stream
	}

	out := make([]byte, 0, len(stream))
	prev := 0
	for i, sp := range spans {
		out = append(out, stream[prev:sp.start]...)
		out = append(out, sp.out...)
		if i == len(spans)-1 {
			out = append(out, w.Flush()...)
		}
		prev = sp.end
	}
	return append(out, stream[prev:]...)
}
