package redact

import (
	"bytes"
	"encoding/json"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// carryPart is one held segment fragment that contributes to an unresolved
// placeholder carry: the segment queue index, the leaf it lives in, and the
// decoded span of that leaf's Value the fragment occupies. editHeld deletes or
// rewrites that span once the token completes.
type carryPart struct {
	seg                      int
	leaf                     protocol.Leaf
	decodedStart, decodedEnd int
}

// firstNonSpace returns the first non-whitespace byte of b, or 0.
func firstNonSpace(b []byte) byte {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return c
		}
	}
	return 0
}

// originTornInner reports whether l is a torn inner-JSON fragment: not reached
// by decoding a JSON-encoded string, not valid JSON itself, and opening an
// object or array (so restoring an escape-needing secret into it would corrupt
// the client's nested document).
func originTornInner(l protocol.Leaf) bool {
	if l.Encoded || json.Valid(l.Value) {
		return false
	}
	c := firstNonSpace(l.Value)
	return c == '{' || c == '['
}

// keepPlaceholder reports whether a completing secret must be left as the
// placeholder: the origin is a torn inner-JSON fragment AND the secret's JSON
// spelling differs from its raw bytes (it needs escaping).
func keepPlaceholder(origin protocol.Leaf, secret []byte) bool {
	return originTornInner(origin) && !bytes.Equal(protocol.EscapeJSONString(secret), secret)
}

// contentWith applies the leaf-token restores plus any accumulated extra edits
// to V. It returns V unchanged when no edit changes a byte.
func (s *SSEBackfiller) contentWith(V []byte, leaves []protocol.Leaf, extra []protocol.Edit) []byte {
	edits := append(withinLeafEdits(V, leaves, s.restorer.Backfill), extra...)
	if len(edits) == 0 {
		return V
	}
	out, _ := protocol.Apply(V, edits)
	return out
}

// withinLeafContent is contentWith with no extra edits.
func (s *SSEBackfiller) withinLeafContent(V []byte, leaves []protocol.Leaf) []byte {
	return s.contentWith(V, leaves, nil)
}

// renderHeld recomputes a held segment's content from its ORIGINAL data value
// and every accumulated edit, never from a previously rendered content.
func (s *SSEBackfiller) renderHeld(i int) {
	V := segmentValue(s.segments[i])
	leaves, err := protocol.Walk(V)
	if err != nil {
		return
	}
	s.segments[i].content = s.contentWith(V, leaves, s.segments[i].extraEdits)
}

// editHeld appends one edit to a held segment and re-renders it.
func (s *SSEBackfiller) editHeld(part carryPart, replacement []byte) {
	e := protocol.Edit{Leaf: part.leaf, Start: part.decodedStart, End: part.decodedEnd, Replacement: replacement}
	s.segments[part.seg].extraEdits = append(s.segments[part.seg].extraEdits, e)
	s.renderHeld(part.seg)
}

// holdSegment appends a leaf segment to the queue, counts its retained bytes
// against the joint budget, and returns its index.
func (s *SSEBackfiller) holdSegment(seg sseSegment, content []byte, extra []protocol.Edit) int {
	seg.leaf = true
	seg.content = content
	seg.extraEdits = extra
	s.heldBytes += len(seg.raw) + len(content)
	s.segments = append(s.segments, seg)
	return len(s.segments) - 1
}

// emitSegment appends a leaf segment that is not counted against the budget.
func (s *SSEBackfiller) emitSegment(seg sseSegment, content []byte, extra []protocol.Edit) int {
	seg.leaf = true
	seg.content = content
	seg.extraEdits = extra
	s.segments = append(s.segments, seg)
	return len(s.segments) - 1
}

// fitsBudget reports whether admitting add more retained bytes keeps the joint
// hold within the invariant cap.
func (s *SSEBackfiller) fitsBudget(add int) bool {
	return s.writer.Held()+len(s.carry)+s.heldBytes+add <= protocol.SSEBackfillHoldbackBytes
}

// clearCarry forgets the unresolved carry and its held-segment accounting.
func (s *SSEBackfiller) clearCarry() {
	s.carry, s.carryKey, s.carryParts, s.heldBytes = nil, "", nil, 0
}

// flushHeld releases every queued segment in order and drops the carry.
func (s *SSEBackfiller) flushHeld() []byte {
	out := s.release(len(s.segments))
	s.clearCarry()
	return out
}

// handoffWriter moves the raw-path writer's held tail onto the newest raw data
// segment before a JSON envelope is processed, so a partial prefix never leaks
// into a JSON data value.
func (s *SSEBackfiller) handoffWriter() {
	if s.writer.Held() == 0 {
		return
	}
	for i := len(s.segments) - 1; i >= 0; i-- {
		if !s.segments[i].leaf && s.segments[i].hasSpan {
			s.segments[i].content = append(s.segments[i].content, s.writer.Flush()...)
			return
		}
	}
}

// carryReferenced reports whether segment n is a held carry contributor.
func (s *SSEBackfiller) carryReferenced(n int) bool {
	for _, part := range s.carryParts {
		if part.seg == n {
			return true
		}
	}
	return false
}

// hasLaterRaw reports whether a raw data segment follows index n.
func (s *SSEBackfiller) hasLaterRaw(n int) bool {
	for j := n + 1; j < len(s.segments); j++ {
		if !s.segments[j].leaf && s.segments[j].hasSpan {
			return true
		}
	}
	return false
}

// drain releases the final front run: every segment that is neither a
// carry contributor nor a raw data segment still awaiting a later raw event.
func (s *SSEBackfiller) drain() []byte {
	n := 0
	for n < len(s.segments) {
		seg := s.segments[n]
		if seg.leaf && s.carryReferenced(n) {
			break
		}
		if !seg.leaf && seg.hasSpan && !s.hasLaterRaw(n) {
			break
		}
		n++
	}
	return s.release(n)
}

// acceptLeaf is the D3 state machine: it establishes a carry from a JSON
// envelope ending in a partial placeholder, continues one across consecutive
// envelopes whose identity matches the carry's channel, and completes a token
// by deleting each contributing fragment and re-spelling the secret into the
// completing leaf. handled is false when the event is not a usable JSON
// envelope, so accept falls back to the raw writer path.
func (s *SSEBackfiller) acceptLeaf(ev protocol.Event, seg sseSegment) (handled bool, out []byte) {
	value := segmentValue(seg)
	if !json.Valid(value) {
		return false, nil
	}
	s.handoffWriter()
	leaves, err := protocol.Walk(value)
	if err != nil || !hasIdentifiableLeaf(leaves) {
		return false, nil
	}

	if len(s.carry) == 0 {
		content := s.withinLeafContent(value, leaves)
		p, leaf, ok := trailingPrefix(leaves)
		if ok && s.fitsBudget(len(ev.Raw)+len(content)) {
			out = s.release(len(s.segments))
			cur := s.holdSegment(seg, content, nil)
			s.carry, s.carryKey = p, leaf.Identity
			s.carryParts = []carryPart{{seg: cur, leaf: leaf, decodedStart: len(leaf.Value) - len(p), decodedEnd: len(leaf.Value)}}
			return true, append(out, s.drain()...)
		}
		s.emitSegment(seg, content, nil)
		return true, s.drain()
	}

	match, ok := uniqueIdentityMatch(leaves, s.carryKey)
	if !ok {
		out = s.flushHeld()
		content := s.withinLeafContent(value, leaves)
		p, leaf, pok := trailingPrefix(leaves)
		if pok && s.fitsBudget(len(ev.Raw)+len(content)) {
			cur := s.holdSegment(seg, content, nil)
			s.carry, s.carryKey = p, leaf.Identity
			s.carryParts = []carryPart{{seg: cur, leaf: leaf, decodedStart: len(leaf.Value) - len(p), decodedEnd: len(leaf.Value)}}
		} else {
			s.emitSegment(seg, content, nil)
		}
		return true, append(out, s.drain()...)
	}

	combined := append(append([]byte(nil), s.carry...), match.Value...)
	t := (placeholderMatcher{}).TokenLen(combined)
	if t > len(s.carry) {
		secret := s.restorer.Backfill(combined[:t])
		origin := s.carryParts[0].leaf
		if bytes.Equal(secret, combined[:t]) || keepPlaceholder(origin, secret) {
			out = s.flushHeld()
			s.emitSegment(seg, s.withinLeafContent(value, leaves), nil)
			return true, append(out, s.drain()...)
		}
		k := t - len(s.carry)
		for _, part := range s.carryParts {
			s.editHeld(part, nil)
		}
		out = s.flushHeld()
		spelled := match.RawSpelling(secret)
		extra := []protocol.Edit{{Leaf: match, Start: 0, End: k, Replacement: spelled}}
		matchContent := s.contentWith(value, leaves, extra)
		p2, leaf2, pok := trailingPrefixAfter(leaves, match, k)
		if pok && s.fitsBudget(len(ev.Raw)+len(matchContent)) {
			cur := s.holdSegment(seg, matchContent, extra)
			s.carry, s.carryKey = p2, leaf2.Identity
			s.carryParts = []carryPart{{seg: cur, leaf: leaf2, decodedStart: len(leaf2.Value) - len(p2), decodedEnd: len(leaf2.Value)}}
		} else {
			s.emitSegment(seg, matchContent, nil)
		}
		return true, append(out, s.drain()...)
	}

	content := s.withinLeafContent(value, leaves)
	if (placeholderMatcher{}).PrefixLen(combined) != len(combined) ||
		len(combined) > maxPlaceholderLen || !s.fitsBudget(len(ev.Raw)+len(content)+len(match.Value)) {
		out = s.flushHeld()
		s.emitSegment(seg, content, nil)
		return true, append(out, s.drain()...)
	}
	cur := s.holdSegment(seg, content, nil)
	s.carry = combined
	s.carryParts = append(s.carryParts, carryPart{seg: cur, leaf: match, decodedStart: 0, decodedEnd: len(match.Value)})
	return true, s.drain()
}
