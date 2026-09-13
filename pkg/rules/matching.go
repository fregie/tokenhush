package rules

// Compiled rule matching: regex (RE2) and keyword (byte-exact or
// ASCII-folded) finding, allowlist suppression, blocklist scanning and the
// deterministic finding order.

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"

	"github.com/fregie/tokenhush/pkg/extension"
)

// compiledRule is the immutable, validated form of one Rule. Exactly one of
// re (regex) or keywords (keyword) is set, selected by kind.
type compiledRule struct {
	id         string
	kind       string
	finding    string
	action     extension.Action
	confidence float64
	re         *regexp.Regexp
	keywords   [][]byte
	fold       bool
	allow      [][]byte
}

// find returns the rule's matches in content as half-open [start,end) byte
// spans. folded is the ASCII-folded copy of content, used only by
// case-insensitive keyword rules and built lazily by the Inspector. A match
// count reaching limit fails with ErrTooManyMatches instead of truncating.
func (r *compiledRule) find(content, folded []byte, limit int) ([][2]int, error) {
	if r.re != nil {
		idx := r.re.FindAllIndex(content, limit)
		if len(idx) >= limit {
			return nil, fmt.Errorf("%w: rule %q", ErrTooManyMatches, r.id)
		}
		spans := make([][2]int, 0, len(idx))
		for _, m := range idx {
			if m[1] > m[0] { // defensively skip empty matches; rejected at load
				spans = append(spans, [2]int{m[0], m[1]})
			}
		}
		return spans, nil
	}
	hay := content
	if r.fold {
		hay = folded
	}
	var spans [][2]int
	for _, kw := range r.keywords {
		for off := 0; off <= len(hay)-len(kw); {
			j := bytes.Index(hay[off:], kw)
			if j < 0 {
				break
			}
			s := off + j
			spans = append(spans, [2]int{s, s + len(kw)})
			if len(spans) >= limit {
				return nil, fmt.Errorf("%w: rule %q", ErrTooManyMatches, r.id)
			}
			off = s + len(kw)
		}
	}
	return spans, nil
}

// suppressed reports whether [start,end) lies inside an occurrence of an allow
// literal in any of the given lists.
func suppressed(content []byte, start, end int, lists ...[][]byte) bool {
	for _, list := range lists {
		for _, lit := range list {
			if insideOccurrence(content, lit, start, end) {
				return true
			}
		}
	}
	return false
}

// insideOccurrence reports whether [start,end) is contained in one byte-exact
// occurrence of lit in content. The scan window is bounded by the literal
// length, so the check is O(len(lit)) per candidate, independent of content.
func insideOccurrence(content, lit []byte, start, end int) bool {
	l := len(lit)
	if l == 0 || l < end-start {
		return false
	}
	lo := end - l
	if lo < 0 {
		lo = 0
	}
	hi := start + l
	if hi > len(content) {
		hi = len(content)
	}
	if lo >= hi {
		return false
	}
	window := content[lo:hi]
	for off := 0; off+l <= len(window); {
		j := bytes.Index(window[off:], lit)
		if j < 0 {
			return false
		}
		occurrence := lo + off + j
		if end <= occurrence+l {
			return true
		}
		off += j + 1
	}
	return false
}

// findLiterals returns every non-overlapping occurrence of the blocklist
// literals in content, capped at limit.
func findLiterals(content []byte, literals [][]byte, limit int) ([][2]int, error) {
	var spans [][2]int
	for _, lit := range literals {
		for off := 0; off <= len(content)-len(lit); {
			j := bytes.Index(content[off:], lit)
			if j < 0 {
				break
			}
			s := off + j
			spans = append(spans, [2]int{s, s + len(lit)})
			if len(spans) >= limit {
				return nil, fmt.Errorf("%w: blocklist", ErrTooManyMatches)
			}
			off = s + len(lit)
		}
	}
	return spans, nil
}

// asciiFold returns a copy of b with ASCII upper-case letters lower-cased.
// The copy has exactly the same length as b, so match offsets stay valid.
func asciiFold(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// sortFindings orders findings by (leaf, start, end, type), the same
// determinism contract as the core detectors.
func sortFindings(findings []extension.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.LeafIndex != b.LeafIndex {
			return a.LeafIndex < b.LeafIndex
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End < b.End
		}
		return a.Type < b.Type
	})
}

// dedupeFindings collapses findings with an identical (leaf, start, end,
// type) key. The input must already be sorted, so duplicates are adjacent.
func dedupeFindings(findings []extension.Finding) []extension.Finding {
	if len(findings) < 2 {
		return findings
	}
	out := findings[:1]
	for _, f := range findings[1:] {
		last := out[len(out)-1]
		if f.LeafIndex == last.LeafIndex && f.Start == last.Start && f.End == last.End && f.Type == last.Type {
			continue
		}
		out = append(out, f)
	}
	return out
}
