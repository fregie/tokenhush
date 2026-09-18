package filter

// primitive_entropy.go is the opt-in high-entropy detector: Shannon entropy is
// measured over maximal base64-alphabet runs, with a minimum length and a
// minimum bits-per-byte threshold. Pure-hex runs (digests, UUIDs, object ids)
// are excluded explicitly because their entropy can reach the base64 floor of
// 4 bits per byte, and anything outside the run alphabet splits the run.

import (
	"math"
	"regexp"
)

// Fixed entropy defaults: the minimum candidate run length and the Shannon
// entropy floor in bits per byte. Natural-language runs sit below the floor;
// random base64 tokens sit well above it.
const (
	entropyDefaultMinLength      = 28
	entropyDefaultMinBitsPerChar = 4.0
	entropyConfidence            = 0.6
)

// entropyCandidatePattern captures maximal runs over the base64/url-safe
// alphabet. The quantifier is the hard floor; the rule's minLength applies on
// top of it, so a configurable threshold never widens the alphabet.
var entropyCandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)

// hexOnlyPattern recognises pure-hex runs (git object ids, UUIDs, digests).
// Their entropy can reach exactly 4.0 bits/char, so the floor alone would not
// exclude them; the explicit rule does.
var hexOnlyPattern = regexp.MustCompile(`^[0-9a-fA-F-]+$`)

// findEntropySpans returns candidate runs at or above minLength whose Shannon
// entropy is at least minEntropy, excluding pure-hex runs.
func findEntropySpans(content []byte, minLength int, minEntropy float64) []Span {
	matches := entropyCandidatePattern.FindAllIndex(content, -1)
	spans := make([]Span, 0, len(matches))
	for _, m := range matches {
		run := content[m[0]:m[1]]
		if len(run) < minLength {
			continue
		}
		if hexOnlyPattern.Match(run) {
			continue
		}
		if shannonEntropy(run) < minEntropy {
			continue
		}
		spans = append(spans, Span{Start: m[0], End: m[1]})
	}
	return spans
}

// shannonEntropy returns the Shannon entropy of run in bits per byte.
func shannonEntropy(run []byte) float64 {
	if len(run) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range run {
		counts[b]++
	}
	total := float64(len(run))
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// entropyRule is the built-in high-entropy rule. It is opt-in: the built-in
// default set leaves it disabled.
type entropyRule struct {
	minLength  int
	minEntropy float64
	budget     int
}

// NewEntropyRule returns the built-in high-entropy rule with the documented
// defaults and the documented default byte budget.
func NewEntropyRule() Rule {
	return NewEntropyRuleBudget(PrimitiveByteBudgetBytes)
}

// NewEntropyRuleBudget returns the high-entropy rule with the documented
// thresholds and an explicit per-call byte budget.
func NewEntropyRuleBudget(budget int) Rule {
	return entropyRule{
		minLength: entropyDefaultMinLength, minEntropy: entropyDefaultMinBitsPerChar,
		budget: normalizeBudget(budget),
	}
}

// ID returns the frozen detector id.
func (entropyRule) ID() string { return DetectorHighEntropy }

// Type returns the frozen rule type id.
func (entropyRule) Type() string { return TypeEntropy }

// Category returns the frozen category.
func (entropyRule) Category() string { return CategoryHighEntropy }

// Scope returns the request phase: only requests may substitute a placeholder.
func (entropyRule) Scope() Scope { return ScopeRequest }

// Action returns redact, the built-in action for a high-entropy match.
func (entropyRule) Action() Action { return ActionRedact }

// Priority returns the default rule priority.
func (entropyRule) Priority() int { return DefaultPriority }

// Confidence returns the fixed detector confidence.
func (entropyRule) Confidence() float64 { return entropyConfidence }

// inspectEntropy runs the entropy algorithm with the documented thresholds over
// content truncated to budget; it is the compiled-document entry, where no rule
// struct is materialised.
func inspectEntropy(content []byte, budget int) []Span {
	return findEntropySpans(primitiveInput(content, budget), entropyDefaultMinLength, entropyDefaultMinBitsPerChar)
}

// Inspect returns the spans of high-entropy base64 runs inside leaf.
func (r entropyRule) Inspect(leaf []byte) []Span {
	return findEntropySpans(primitiveInput(leaf, r.budget), r.minLength, r.minEntropy)
}
