package filter

// evaluate.go is the evaluator over the leaf model. It reads value leaves as
// raw bytes, never decodes or normalises them, and reports findings as byte
// spans inside a leaf instead of content, so no matched secret can leak through
// a result. Ordering is deterministic — (leaf, start, end), with the rule
// invocation order (ascending priority, then id) breaking exact ties — and the
// output never depends on the order rules were declared in. The global
// allowlist and a rule's own allowlist suppress a match; a global blocklist hit
// always yields a Block finding and no allowlist can suppress it.

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// ErrMatchLimit is the hard MaxMatches bound: an evaluation that would exceed
// it fails with this typed error and no partial results instead of truncating.
var ErrMatchLimit = errors.New("filter: match limit exceeded")

// RuleIDBlocklist is the rule id carried by a global blocklist finding. Its
// category is CategoryCustom, so it is never mistaken for one of the six
// detector categories.
const RuleIDBlocklist = "blocklist"

// Finding is one detection result: which rule fired, the action and category it
// carries, and the half-open byte span [Start, End) inside the named leaf's
// value. It deliberately carries no content bytes beyond those offsets.
type Finding struct {
	RuleID     string
	Category   string
	Action     Action
	LeafIndex  int
	Start      int
	End        int
	Confidence float64
}

// Evaluate applies every compiled rule whose scope covers phase to every leaf
// and returns the findings ordered by (leaf index, start, end). A match
// contained in an occurrence of a global or per-rule allowlist literal is
// suppressed. A global blocklist occurrence yields a Block finding at
// confidence 1 in both content phases and is never suppressed. More than
// MaxMatches findings fails with ErrMatchLimit and no partial results.
func (c *Compiled) Evaluate(leaves []protocol.Leaf, phase Scope) ([]Finding, error) {
	if c == nil {
		return nil, fieldError(ErrInvalidValue, "compiled", "nil compiled rule set")
	}
	if phase != ScopeRequest && phase != ScopeResponse {
		return nil, fieldError(ErrInvalidValue, "phase", "unknown evaluation phase %q", phase)
	}
	var findings []Finding
	for index := range leaves {
		value := leaves[index].Value
		if len(value) == 0 {
			continue
		}
		for i := range c.rules {
			rule := &c.rules[i]
			if rule.scope != phase && rule.scope != ScopeBoth {
				continue
			}
			spans := rule.spans(value)
			if len(spans) > MaxMatches {
				return nil, matchLimitError()
			}
			for _, span := range spans {
				if allowlistSuppressed(value, span, c.allowlist, rule.allow) {
					continue
				}
				if len(findings) >= MaxMatches {
					return nil, matchLimitError()
				}
				findings = append(findings, Finding{
					RuleID:     rule.id,
					Category:   rule.category,
					Action:     rule.action,
					LeafIndex:  index,
					Start:      span.Start,
					End:        span.End,
					Confidence: rule.confidence,
				})
			}
		}
		spans := blocklistSpans(value, c.blocklist, MaxMatches)
		if len(spans) > MaxMatches {
			return nil, matchLimitError()
		}
		for _, span := range spans {
			if len(findings) >= MaxMatches {
				return nil, matchLimitError()
			}
			findings = append(findings, Finding{
				RuleID:     RuleIDBlocklist,
				Category:   CategoryCustom,
				Action:     ActionBlock,
				LeafIndex:  index,
				Start:      span.Start,
				End:        span.End,
				Confidence: 1,
			})
		}
	}
	sortFindings(findings)
	return findings, nil
}

// spans returns one rule's raw matches in value. A regex rule scans with RE2, a
// keyword rule scans byte-exact (case-folded unless case_sensitive), and a
// primitive-typed rule delegates to its bundled algorithm, which keeps its own
// documented per-call byte budget. No branch decodes or normalises anything.
func (r *compiledRule) spans(value []byte) []Span {
	switch {
	case r.re != nil:
		return regexSpans(r.re, value, MaxMatches)
	case r.keywords != nil:
		return keywordSpans(value, r.keywords, r.fold, MaxMatches)
	default:
		return primitiveInspect[r.typ](value)
	}
}

// regexSpans returns non-empty regex matches, capped at max+1 so a caller can
// prove an overflow instead of silently truncating.
func regexSpans(re *regexp.Regexp, value []byte, max int) []Span {
	matches := re.FindAllIndex(value, max+1)
	spans := make([]Span, 0, len(matches))
	for _, match := range matches {
		if match[1] > match[0] {
			spans = append(spans, Span{Start: match[0], End: match[1]})
		}
	}
	return spans
}

// keywordSpans returns non-overlapping occurrences of every keyword, capped at
// max+1. hay is the value, ASCII-folded when the rule is case-insensitive (the
// fold preserves length, so offsets stay valid).
func keywordSpans(value []byte, keywords [][]byte, fold bool, max int) []Span {
	hay := value
	if fold {
		hay = foldASCII(value)
	}
	var spans []Span
	for _, keyword := range keywords {
		for off := 0; off <= len(hay)-len(keyword); {
			at := bytes.Index(hay[off:], keyword)
			if at < 0 {
				break
			}
			start := off + at
			spans = append(spans, Span{Start: start, End: start + len(keyword)})
			if len(spans) > max {
				return spans
			}
			off = start + len(keyword)
		}
	}
	return spans
}

// blocklistSpans returns non-overlapping occurrences of every blocklist
// literal in value, capped at max+1. Literals are non-empty (rejected at
// compile), so each occurrence advances the scan and it always terminates.
func blocklistSpans(value []byte, literals [][]byte, max int) []Span {
	var spans []Span
	for _, literal := range literals {
		for off := 0; off <= len(value)-len(literal); {
			at := bytes.Index(value[off:], literal)
			if at < 0 {
				break
			}
			start := off + at
			spans = append(spans, Span{Start: start, End: start + len(literal)})
			if len(spans) > max {
				return spans
			}
			off = start + len(literal)
		}
	}
	return spans
}

// allowlistSuppressed reports whether span lies inside one byte-exact
// occurrence of any literal in the given lists. The blocklist is never passed
// here: allowlists suppress rule matches only.
func allowlistSuppressed(value []byte, span Span, lists ...[][]byte) bool {
	for _, list := range lists {
		for _, literal := range list {
			if insideOccurrence(value, literal, span.Start, span.End) {
				return true
			}
		}
	}
	return false
}

// insideOccurrence reports whether [start,end) is contained in one byte-exact
// occurrence of literal. The scan window is bounded by the literal length, so
// the check is O(len(literal)) per candidate, independent of the value size.
func insideOccurrence(value, literal []byte, start, end int) bool {
	length := len(literal)
	if length == 0 || length < end-start {
		return false
	}
	lo, hi := max(0, end-length), min(len(value), start+length)
	if lo >= hi {
		return false
	}
	window := value[lo:hi]
	for off := 0; off+length <= len(window); {
		at := bytes.Index(window[off:], literal)
		if at < 0 {
			return false
		}
		if end <= lo+off+at+length {
			return true
		}
		off += at + 1
	}
	return false
}

// sortFindings orders findings by (leaf, start, end). The sort is stable, so
// findings with an identical span keep the deterministic rule invocation order
// (ascending priority, then id).
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.LeafIndex != b.LeafIndex {
			return a.LeafIndex < b.LeafIndex
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		return a.End < b.End
	})
}

// matchLimitError renders the bound failure.
func matchLimitError() error {
	return fmt.Errorf("%w: more than %d findings in one document", ErrMatchLimit, MaxMatches)
}
