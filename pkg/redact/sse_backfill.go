package redact

import (
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
func (placeholderMatcher) MaxTokenLen() int { return maxPlaceholderLen }

// TokenLen returns the byte length of the complete placeholder at the start of
// p, or 0 when p starts with an incomplete or invalid one. Every type length is
// tried and the shortest complete token wins.
func (placeholderMatcher) TokenLen(p []byte) int {
	if len(p) < len(placeholderLiteralPrefix) || string(p[:len(placeholderLiteralPrefix)]) != placeholderLiteralPrefix {
		return 0
	}
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

// TokenRestorer resolves one complete placeholder token to its secret.
// pkg/proxy's Backfiller seam and this package's Backfiller both satisfy it;
// the SSE reassembler holds the session's reverse map and exclusion set
// through this interface alone.
type TokenRestorer interface {
	Backfill([]byte) []byte
}

// SSEObserver sees each decoded event before its bytes become final. A
// non-nil return aborts the stream: every held byte is dropped and the
// returned bytes become the sole output of the Write or Flush that decoded
// the event. pkg/proxy injects the response-scoped Block decision here.
type SSEObserver func(ev protocol.Event) []byte

// SSEBackfiller restores placeholders a stream split across SSE data deltas.
// It owns the stream's single bounded accumulator -- one
// protocol.BackfillWriter over the frozen placeholder grammar -- and one
// protocol.Decoder, and pkg/proxy's SSE handler is its production driver. It
// reuses the session Backfiller's reverse map and exclusion set, so only a
// token this session minted is ever expanded: an unknown, foreign or excluded
// token comes back unchanged and is never fabricated into a secret.
//
// The writer lags the decoder by exactly one data event: a segment's
// replacement content is tentative while it is the newest data event fed and
// final once a later data event has been fed, because the writer's held tail
// can only ever belong to the last fed event. Released segments therefore
// exclude the newest data segment, so a placeholder split across deltas is
// restored exactly once, in the completing event, and never emitted in
// pieces. Non-data segments (comments, event:/id:/retry: lines, blank lines)
// are never modified, but they are released strictly in order behind any
// pending data segment. Flush appends the writer's held tail to the pending
// segment and releases everything, including bytes the decoder never
// dispatched, so a ping- or comment-only stream is byte-identical.
type SSEBackfiller struct {
	restorer TokenRestorer
	observer SSEObserver
	decoder  *protocol.Decoder
	writer   *protocol.BackfillWriter

	feed feedSpelling

	segments []sseSegment
	tail     []byte
	closed   bool
}

// sseSegment is one decoded event's exact bytes plus, for an event with exactly
// one canonical data: line, the replacement content its data value carries.
type sseSegment struct {
	raw     []byte
	span    protocol.Span
	content []byte
	hasSpan bool
}

// bytes renders the segment's client-bound bytes: the record verbatim, with its
// single data value replaced by content when the segment carries a span. A nil
// content empties the value; every framing byte is untouched.
func (seg sseSegment) bytes() []byte {
	if !seg.hasSpan {
		return seg.raw
	}
	return append(append(append([]byte(nil), seg.raw[:seg.span.Start]...), seg.content...), seg.raw[seg.span.End:]...)
}

// NewSSEBackfiller returns a streaming reassembler driven by restorer's
// session map. A nil restorer gets a fresh, empty backfiller so no token can
// expand to a secret. A nil observer is the identity: nothing ever aborts.
func NewSSEBackfiller(restorer TokenRestorer, observer SSEObserver) *SSEBackfiller {
	if restorer == nil {
		restorer = NewBackfiller()
	}
	s := &SSEBackfiller{
		restorer: restorer,
		observer: observer,
		decoder:  protocol.NewDecoder(),
	}
	s.writer = protocol.NewBackfillWriter(placeholderMatcher{}, s.replace)
	return s
}

// Write accepts the next upstream chunk and returns the bytes that are final
// now: the released prefix of the segment queue. A chunk may split records at
// any byte boundary. After Flush or an abort it returns nothing.
func (s *SSEBackfiller) Write(chunk []byte) []byte {
	if s.closed {
		return nil
	}
	s.tail = append(s.tail, chunk...)
	events, _ := s.decoder.Feed(chunk)
	return s.consume(events)
}

// Flush finalizes the stream: the decoder's trailing record is processed, the
// writer's held tail is appended to the pending data segment, and every
// remaining segment plus the never-dispatched tail is released in order. It is
// idempotent: a second call returns nothing.
func (s *SSEBackfiller) Flush() []byte {
	if s.closed {
		return nil
	}
	s.closed = true
	events, _ := s.decoder.Close()
	out := s.consume(events)
	if i := s.pendingIndex(); i >= 0 {
		s.segments[i].content = append(s.segments[i].content, s.writer.Flush()...)
	}
	out = append(out, s.release(len(s.segments))...)
	out = append(out, s.tail...)
	s.tail = nil
	return out
}

// Held reports how many bytes the single bounded accumulator is holding back,
// never more than protocol.SSEBackfillHoldbackBytes.
func (s *SSEBackfiller) Held() int { return s.writer.Held() }

// Closed reports whether Flush or an abort terminated the stream.
func (s *SSEBackfiller) Closed() bool { return s.closed }

func (s *SSEBackfiller) process(stream []byte) []byte {
	return append(s.Write(stream), s.Flush()...)
}

// consume processes decoded events in order: each event is offered to the
// observer, an abort returns that observer's bytes as the only output, and
// every segment that became final is released.
func (s *SSEBackfiller) consume(events []protocol.Event) []byte {
	var out []byte
	for _, ev := range events {
		s.drop(len(ev.Raw))
		if s.observer != nil {
			if aborted := s.observer(ev); aborted != nil {
				s.segments, s.tail = nil, nil
				s.closed = true
				return aborted
			}
		}
		out = append(out, s.accept(ev)...)
	}
	return out
}

// accept turns one decoded event into a segment and releases every segment that
// has become final. A new data segment makes every earlier segment final, so
// the released prefix is returned; a non-data segment is never modified and is
// released immediately unless a pending data segment still gates it.
func (s *SSEBackfiller) accept(ev protocol.Event) []byte {
	seg := sseSegment{raw: ev.Raw}
	if len(ev.DataSpans) == 1 {
		seg.hasSpan, seg.span = true, ev.DataSpans[0]
		value := seg.raw[seg.span.Start:seg.span.End]
		s.spellFeed(value)
		seg.content = s.writer.Feed(value)
	}
	s.segments = append(s.segments, seg)
	if seg.hasSpan {
		return s.release(len(s.segments) - 1)
	}
	if s.pendingIndex() >= 0 {
		return nil
	}
	return s.release(len(s.segments))
}

// release renders segments[:n], removes them from the queue and returns them.
func (s *SSEBackfiller) release(n int) []byte {
	if n <= 0 {
		return nil
	}
	var out []byte
	for _, seg := range s.segments[:n] {
		out = append(out, seg.bytes()...)
	}
	s.segments = s.segments[n:]
	return out
}

// pendingIndex returns the index of the queued data segment, or -1 when none is
// pending: no later data event has finalized it. At most one exists, because a
// new data segment releases everything before it.
func (s *SSEBackfiller) pendingIndex() int {
	for i := range s.segments {
		if s.segments[i].hasSpan {
			return i
		}
	}
	return -1
}

// drop consumes n bytes of dispatched events from the never-dispatched tail.
func (s *SSEBackfiller) drop(n int) {
	s.tail = append(s.tail[:0], s.tail[min(n, len(s.tail)):]...)
}
