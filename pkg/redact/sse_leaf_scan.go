package redact

import (
	"bytes"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// segmentValue returns the raw bytes of the segment's single data value.
func segmentValue(seg sseSegment) []byte { return seg.raw[seg.span.Start:seg.span.End] }

// withinLeafEdits scans every leaf value for complete mapped placeholders and
// returns the replacement edits. A foreign or unmapped token is byte-identical
// after Backfill, so it produces no edit.
func withinLeafEdits(V []byte, leaves []protocol.Leaf, restore func([]byte) []byte) []protocol.Edit {
	var edits []protocol.Edit
	for _, leaf := range leaves {
		v := leaf.Value
		for i := 0; i < len(v); {
			j := bytes.Index(v[i:], []byte(placeholderPrefix))
			if j < 0 {
				break
			}
			start := i + j
			n := (placeholderMatcher{}).TokenLen(v[start:])
			if n == 0 {
				i = start + 1
				continue
			}
			token := v[start : start+n]
			secret := restore(token)
			if !bytes.Equal(secret, token) {
				edits = append(edits, protocol.Edit{
					Leaf:        leaf,
					Start:       start,
					End:         start + n,
					Replacement: leaf.RawSpelling(secret),
				})
			}
			i = start + n
		}
	}
	return edits
}

// hasIdentifiableLeaf reports whether any leaf carries a usable channel
// identity.
func hasIdentifiableLeaf(leaves []protocol.Leaf) bool {
	for _, leaf := range leaves {
		if leaf.Identifiable {
			return true
		}
	}
	return false
}

// uniqueIdentityMatch returns the single Identifiable leaf whose Identity equals
// key. ok is false when zero or more than one leaf matches, so an ambiguous
// channel never stitches.
func uniqueIdentityMatch(leaves []protocol.Leaf, key string) (protocol.Leaf, bool) {
	var match protocol.Leaf
	n := 0
	for _, leaf := range leaves {
		if leaf.Identifiable && leaf.Identity == key {
			match = leaf
			n++
		}
	}
	return match, n == 1
}

// smallestPrefixAt returns the smallest index s >= from where v[s:] is a
// non-empty proper suffix that is a placeholder prefix but not a complete
// token.
func smallestPrefixAt(v []byte, from int) (int, bool) {
	for i := from; i < len(v); i++ {
		if (placeholderMatcher{}).TokenLen(v[i:]) != 0 {
			continue
		}
		if isPlaceholderPrefix(v[i:]) {
			return i, true
		}
	}
	return 0, false
}

// trailingPrefix returns the last Identifiable leaf whose Value ends in a
// non-empty unresolved placeholder prefix, along with that suffix.
func trailingPrefix(leaves []protocol.Leaf) (p []byte, leaf protocol.Leaf, ok bool) {
	for _, l := range leaves {
		if !l.Identifiable {
			continue
		}
		if s, found := smallestPrefixAt(l.Value, 0); found && s < len(l.Value) {
			p, leaf, ok = l.Value[s:], l, true
		}
	}
	return
}

// trailingPrefixAfter returns the trailing unresolved prefix of match (only at
// or after decoded offset k) or of any leaf after match in document order.
func trailingPrefixAfter(leaves []protocol.Leaf, match protocol.Leaf, k int) (p []byte, leaf protocol.Leaf, ok bool) {
	seen := false
	for _, l := range leaves {
		if !seen {
			if l.Identifiable && l.Identity == match.Identity {
				seen = true
				if s, found := smallestPrefixAt(l.Value, k); found {
					p, leaf, ok = l.Value[s:], l, true
				}
			}
			continue
		}
		if !l.Identifiable {
			continue
		}
		if s, found := smallestPrefixAt(l.Value, 0); found {
			p, leaf, ok = l.Value[s:], l, true
		}
	}
	return
}
