package proxy

// response_sse.go is the streaming, client-bound half of invariant 8. An
// upstream SSE response is restored incrementally: the handler owns ONE
// bounded accumulator (a single protocol.BackfillWriter over the frozen
// placeholder grammar) and ONE persistent protocol.Decoder, and it lags the
// writer by exactly one data event.
//
// A data segment's replacement content is tentative while it is the last data
// event fed and final once a later data event has been fed, because the
// writer's held tail can only ever belong to the last fed event. Write
// therefore releases every segment BEFORE the newest data segment -- never the
// newest one -- so a placeholder split across deltas is restored exactly once,
// in the completing event, and never emitted in pieces. Non-data segments
// (comments, event:/id:/retry: lines, blank lines) are never modified, but they
// are released strictly in order behind any pending data segment. Flush
// appends the writer's held tail to the pending segment and releases
// everything, including bytes the decoder never dispatched, so a ping- or
// comment-only stream is byte-identical.
//
// The response path can hold no forward-only placeholder writer: the only
// substitution writer reachable from here is the injected Backfiller, and one
// complete token is routed through Backfill(token). The reverse map and the
// exclusion set stay in pkg/redact.
//
// A response-scoped Block cannot be a 502 here: once headers and earlier
// deltas are on the wire the status cannot change and emitted bytes cannot be
// recalled. The decision is therefore taken at the FIRST whole-event
// evaluation -- the stream is held until it decides -- and a Block emits
// exactly one SSE error record naming the rule id and closes the stream.
// Deltas already emitted before the decision point are unrecoverable, and
// docs/security.md states this.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// ErrSSEClosed reports a Write after Flush or a Block terminated the stream.
var ErrSSEClosed = errors.New("proxy: sse stream closed")

// SSEResponseConfig wires the SSE handler's injectable seams. A nil Evaluator
// means no evaluation, a nil Backfiller is the identity transform, a nil
// Counters reads as zero and ignores increments, a nil WarningWriter drops
// warnings and a nil Context means context.Background().
type SSEResponseConfig struct {
	Context    context.Context
	Evaluator  Evaluator
	Backfiller Backfiller
	Counters   *Counters
	Warnings   WarningWriter
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
	// head + replacement content + tail, in the record's own byte order.
	return append(append(append([]byte(nil), seg.raw[:seg.span.Start]...), seg.content...), seg.raw[seg.span.End:]...)
}

// SSEHandler incrementally restores placeholders in one client-bound SSE
// stream. It owns the stream's single bounded accumulator -- one
// protocol.BackfillWriter -- and one persistent protocol.Decoder.
//
// SSEHandler is stateful and not safe for concurrent use: it serves exactly one
// response. Write returns the bytes that are final now; Flush finalizes.
type SSEHandler struct {
	ctx        context.Context
	evaluator  Evaluator
	backfiller Backfiller
	counters   *Counters
	warnings   WarningWriter

	decoder *protocol.Decoder
	writer  *protocol.BackfillWriter

	segments []sseSegment
	tail     []byte
	decided  bool
	closed   bool
}

// NewSSEHandler returns a handler over the configured seams. Nil seams take
// their documented inert defaults, so a handler always exists.
func NewSSEHandler(cfg SSEResponseConfig) *SSEHandler {
	h := &SSEHandler{ctx: cfg.Context, evaluator: cfg.Evaluator, backfiller: cfg.Backfiller, counters: cfg.Counters, warnings: cfg.Warnings, decoder: protocol.NewDecoder()}
	if h.ctx == nil {
		h.ctx = context.Background()
	}
	h.writer = protocol.NewBackfillWriter(placeholderMatcher{}, h.replace)
	return h
}

// Write accepts the next upstream chunk and returns the bytes that are final
// now: the released prefix of the segment queue. A chunk may split records at
// any byte boundary. After Flush or a Block it returns ErrSSEClosed.
func (h *SSEHandler) Write(chunk []byte) ([]byte, error) {
	if h.closed {
		return nil, ErrSSEClosed
	}
	h.tail = append(h.tail, chunk...)
	events, _ := h.decoder.Feed(chunk) // Feed cannot fail: the decoder is open
	return h.consume(events), nil
}

// Flush finalizes the stream: the decoder's trailing record is processed, the
// writer's held tail is appended to the pending data segment, and every
// remaining segment plus the never-dispatched tail is released in order. It is
// idempotent: a second call returns nothing.
func (h *SSEHandler) Flush() ([]byte, error) {
	if h.closed {
		return nil, nil
	}
	h.closed = true
	events, _ := h.decoder.Close() // Close cannot fail: the decoder is open
	out := h.consume(events)
	if i := h.pendingIndex(); i >= 0 {
		h.segments[i].content = append(h.segments[i].content, h.writer.Flush()...)
	}
	out = append(out, h.release(len(h.segments))...)
	out = append(out, h.tail...)
	h.tail = nil
	return out, nil
}

// Held reports how many bytes the single bounded accumulator is holding back,
// never more than protocol.SSEBackfillHoldbackBytes.
func (h *SSEHandler) Held() int { return h.writer.Held() }

// Closed reports whether Flush or a Block terminated the stream.
func (h *SSEHandler) Closed() bool { return h.closed }

// consume processes decoded events in order: the first whole event is
// evaluated (a Block record is returned as the only output) and every segment
// that became final is released.
func (h *SSEHandler) consume(events []protocol.Event) []byte {
	var out []byte
	for _, ev := range events {
		h.drop(len(ev.Raw))
		if !h.decided {
			if block := h.evaluate(ev); block != nil {
				return block
			}
		}
		out = append(out, h.accept(ev)...)
	}
	return out
}

// evaluate runs the first whole-event evaluation and returns the single SSE
// error record on a Block; on Warn it writes one metadata-only warning line, on
// an evaluator error it counts a walk skip, and otherwise it returns nil. It is
// deliberately the only evaluation: the decision is taken once, when the first
// whole event exists. A Block can only close the very first event, so the
// segment queue and the accumulator are empty and already-emitted deltas are
// unrecoverable.
func (h *SSEHandler) evaluate(ev protocol.Event) []byte {
	h.decided = true
	if h.evaluator == nil {
		return nil
	}
	decision, err := h.evaluator.EvaluateResponse(h.ctx, ev.Data)
	switch {
	case err != nil:
		h.counters.countWalkSkip()
	case decision.Action == ResponseWarn:
		h.warn(decision.RuleIDs)
	case decision.Action == ResponseAllow:
	default:
		h.counters.countContentPolicyBlock()
		h.counters.countRuleBlock()
		h.closed = true
		h.tail = nil
		_, _ = h.decoder.Close()
		return blockedRecord(primaryRule(decision.RuleIDs))
	}
	return nil
}

// accept turns one decoded event into a segment and releases every segment that
// has become final. A new data segment makes every earlier segment final, so
// the released prefix is returned; a non-data segment is never modified and is
// released immediately unless a pending data segment still gates it.
func (h *SSEHandler) accept(ev protocol.Event) []byte {
	seg := sseSegment{raw: ev.Raw}
	if len(ev.DataSpans) == 1 {
		seg.hasSpan, seg.span = true, ev.DataSpans[0]
		seg.content = h.writer.Feed(seg.raw[seg.span.Start:seg.span.End])
	}
	h.segments = append(h.segments, seg)
	if seg.hasSpan {
		return h.release(len(h.segments) - 1)
	}
	if h.pendingIndex() >= 0 {
		return nil
	}
	return h.release(len(h.segments))
}

// release renders segments[:n], removes them from the queue and returns them.
func (h *SSEHandler) release(n int) []byte {
	if n <= 0 {
		return nil
	}
	var out []byte
	for _, seg := range h.segments[:n] {
		out = append(out, seg.bytes()...)
	}
	h.segments = h.segments[n:]
	return out
}

// pendingIndex returns the index of the queued data segment, or -1 when none is
// pending: no later data event has finalized it. At most one exists, because a
// new data segment releases everything before it.
func (h *SSEHandler) pendingIndex() int {
	for i := range h.segments {
		if h.segments[i].hasSpan {
			return i
		}
	}
	return -1
}

// drop consumes n bytes of dispatched events from the never-dispatched tail.
func (h *SSEHandler) drop(n int) {
	h.tail = append(h.tail[:0], h.tail[min(n, len(h.tail)):]...)
}

// replace routes one complete token through the injected Backfiller, the only
// substitution writer this path may hold: the forward-only writer is
// unreachable here. A nil backfiller forwards the token unchanged.
func (h *SSEHandler) replace(token []byte) []byte {
	if h.backfiller == nil {
		return nil
	}
	return h.backfiller.Backfill(token)
}

// warn writes one metadata-only warning line per rule that backed a Warn
// decision; the rule id is quoted, so a hostile id cannot inject a line.
func (h *SSEHandler) warn(ruleIDs []string) {
	if h.warnings == nil {
		return
	}
	if len(ruleIDs) == 0 {
		h.warnings.Warn(warningPrefix)
		return
	}
	for _, id := range ruleIDs {
		h.warnings.Warn(warningPrefix + " rule=" + strconv.Quote(id))
	}
}

// sseErrorHead opens the single SSE error record a response-scoped Block emits
// once the first whole-event evaluation decides.
const sseErrorHead = "event: error\ndata: "

// blockedRecord renders that record: one error event whose data is the
// metadata-only refusal document naming the rule id. It carries no content.
func blockedRecord(ruleID string) []byte {
	body, _ := json.Marshal(refusal{Error: refusalRuleBlocked, RuleID: ruleID})
	return append(append([]byte(sseErrorHead), body...), '\n', '\n')
}

// Geometry of the frozen placeholder grammar, mirrored from pkg/redact, the
// canonical owner: __PII_<type>_<digest>__ with a 1..16 byte [a-z0-9_] type
// and a 12..64 lowercase hex digest.
const (
	placeholderHead      = "__PII_"
	placeholderTail      = "__"
	placeholderTypeMax   = 16
	placeholderDigestMin = 12
	placeholderDigestMax = 64
)

// placeholderMatcher recognises the frozen placeholder grammar on the response
// stream. pkg/redact's matcher is the canonical one; this is the
// response-stream view of the same frozen grammar, so MaxTokenLen is exactly
// redact.MaxPlaceholderLen and the single accumulator can never hold back more
// than a placeholder could span.
type placeholderMatcher struct{}

// MaxTokenLen reports the worst-case placeholder length.
func (placeholderMatcher) MaxTokenLen() int { return redact.MaxPlaceholderLen }

// TokenLen mirrors pkg/redact's matcher: every type length is tried and the
// shortest complete placeholder wins, because the grammar is ambiguous (a type
// may carry hex digits and underscores). Only a digest of exactly the hex run's
// length can be followed by the suffix, so the run's own end is the only
// candidate.
func (placeholderMatcher) TokenLen(p []byte) int {
	best := 0
	for t := 1; t <= placeholderTypeMax; t++ {
		sep := len(placeholderHead) + t
		if sep >= len(p) || p[sep] != '_' {
			continue
		}
		d := hexRun(p[sep+1:])
		end := sep + 1 + d
		if d < placeholderDigestMin || d > placeholderDigestMax || end+len(placeholderTail) > len(p) {
			continue
		}
		if string(p[end:end+len(placeholderTail)]) != placeholderTail {
			continue
		}
		if best == 0 || end+len(placeholderTail) < best {
			best = end + len(placeholderTail)
		}
	}
	return best
}

// PrefixLen reports the longest prefix of p that could still grow into a valid
// placeholder. "Is a placeholder prefix" is downward-closed, so the scan stops
// at the first byte that leaves the grammar.
func (placeholderMatcher) PrefixLen(p []byte) int {
	k := 0
	for k < len(p) && isPlaceholderPrefix(p[:k+1]) {
		k++
	}
	return k
}

// isPlaceholderPrefix mirrors pkg/redact: s could be the head of a valid
// placeholder.
func isPlaceholderPrefix(s []byte) bool {
	if len(s) <= len(placeholderHead) {
		return bytes.HasPrefix([]byte(placeholderHead), s)
	}
	if string(s[:len(placeholderHead)]) != placeholderHead {
		return false
	}
	rest := s[len(placeholderHead):]
	for t := 1; t <= placeholderTypeMax; t++ {
		if len(rest) <= t {
			return !bytes.ContainsFunc(rest, func(r rune) bool { return !isTypeChar(byte(r)) })
		}
		if rest[t] != '_' {
			continue
		}
		d := hexRun(rest[t+1:])
		rem := rest[t+1+d:]
		if len(rem) == 0 {
			return d <= placeholderDigestMax
		}
		if rem[0] != '_' || d < placeholderDigestMin || d > placeholderDigestMax {
			continue
		}
		return len(rem) == 1 || (len(rem) == 2 && rem[1] == '_')
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

// isTypeChar reports whether c may appear in a sanitized <type> segment.
func isTypeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}
