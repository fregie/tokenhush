package filter

// primitive_prefix.go is the provider-prefix detector plus the scaffolding
// every primitive shares: the documented default byte budget, the frozen
// detector ids and the tiny ASCII helpers. Each primitive is a concrete Rule
// that reads only the leaf it is handed; primitiveInput caps every call at the
// rule's budget so a hostile leaf cannot make detection unbounded. The budget
// is injectable (CompileWithBudget, BuiltinDetectorsBudget and the
// New*RuleBudget constructors): `internal/cli` aligns it with the configured
// scan budget, and PrimitiveByteBudgetBytes stays the documented default.

import "regexp"

// PrimitiveByteBudgetBytes is the documented DEFAULT per-call byte budget: a
// primitive built without an explicit budget inspects at most this many bytes
// of one leaf, so detection cost is O(budget) regardless of the input size and
// spans never extend past the budget.
const PrimitiveByteBudgetBytes = 1 << 20

// Frozen detector ids: the wire names of the six bundled algorithms. They are
// distinct from the rule type ids for pem ("private_key") and entropy
// ("high_entropy").
const (
	DetectorPrefix      = "prefix"
	DetectorHighEntropy = "high_entropy"
	DetectorJWT         = "jwt"
	DetectorPrivateKey  = "private_key"
	DetectorLuhn        = "luhn"
	DetectorEmail       = "email"
)

// normalizeBudget returns budget, or the documented default for a
// non-positive budget, so a zero value can never disable detection silently.
func normalizeBudget(budget int) int {
	if budget <= 0 {
		return PrimitiveByteBudgetBytes
	}
	return budget
}

// primitiveInput truncates leaf at budget, defaulting a non-positive budget to
// PrimitiveByteBudgetBytes. Every primitive starts here, so no primitive ever
// scans past its budget: a match ending exactly at the budget is still found,
// and everything starting at or past it is never inspected.
func primitiveInput(leaf []byte, budget int) []byte {
	budget = normalizeBudget(budget)
	if len(leaf) > budget {
		return leaf[:budget]
	}
	return leaf
}

// isASCIIDigit reports whether b is an ASCII decimal digit.
func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// isASCIIAlnum reports whether b is an ASCII letter or digit.
func isASCIIAlnum(b byte) bool {
	return isASCIIDigit(b) || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// prefixConfidence is the fixed confidence of the prefix rule: known provider
// key shapes are the highest-signal shape heuristic.
const prefixConfidence = 0.95

// prefixPattern covers the bundled known-provider key shapes. Each alternative
// is greedy over its own token alphabet so a match cannot stop mid-key; the
// word-boundary check lives in findPrefixSpans.
var prefixPattern = regexp.MustCompile(
	`sk-[A-Za-z0-9_-]{16,}` +
		`|AKIA[A-Z0-9]{16}` +
		`|ghp_[A-Za-z0-9]{20,}` +
		`|glpat-[A-Za-z0-9_-]{20,}` +
		`|xox[baprs]-[A-Za-z0-9-]{10,}` +
		`|AIza[A-Za-z0-9_-]{35}` +
		`|npm_[A-Za-z0-9]{36,}`,
)

// isTokenByte reports whether b could extend a provider-key token, so a match
// embedded in a longer alphanumeric run is rejected.
func isTokenByte(b byte) bool { return isASCIIAlnum(b) || b == '_' || b == '-' }

// findPrefixSpans returns word-bounded matches of prefixPattern: a candidate
// touching a token byte on either side is part of a longer run, not a key.
func findPrefixSpans(content []byte) []Span {
	matches := prefixPattern.FindAllIndex(content, -1)
	spans := make([]Span, 0, len(matches))
	for _, m := range matches {
		start, end := m[0], m[1]
		if start > 0 && isTokenByte(content[start-1]) {
			continue
		}
		if end < len(content) && isTokenByte(content[end]) {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// prefixRule is the built-in provider-prefix rule.
type prefixRule struct{ budget int }

// NewPrefixRule returns the built-in rule that flags known provider key shapes
// with the documented default byte budget.
func NewPrefixRule() Rule { return NewPrefixRuleBudget(PrimitiveByteBudgetBytes) }

// NewPrefixRuleBudget returns the provider-prefix rule with an explicit
// per-call byte budget.
func NewPrefixRuleBudget(budget int) Rule { return prefixRule{budget: normalizeBudget(budget)} }

// ID returns the frozen detector id.
func (prefixRule) ID() string { return DetectorPrefix }

// Type returns the frozen rule type id.
func (prefixRule) Type() string { return TypePrefix }

// Category returns the frozen category.
func (prefixRule) Category() string { return CategoryAPIKey }

// Scope returns the request phase: only requests may substitute a placeholder.
func (prefixRule) Scope() Scope { return ScopeRequest }

// Action returns redact, the built-in action for a credential match.
func (prefixRule) Action() Action { return ActionRedact }

// Priority returns the default rule priority.
func (prefixRule) Priority() int { return DefaultPriority }

// Confidence returns the fixed detector confidence.
func (prefixRule) Confidence() float64 { return prefixConfidence }

// inspectPrefix runs the prefix algorithm over content truncated to budget; it
// is the compiled-document entry, where no rule struct is materialised.
func inspectPrefix(content []byte, budget int) []Span {
	return findPrefixSpans(primitiveInput(content, budget))
}

// Inspect returns the spans of known provider keys inside leaf.
func (r prefixRule) Inspect(leaf []byte) []Span { return inspectPrefix(leaf, r.budget) }
