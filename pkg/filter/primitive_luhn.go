package filter

// primitive_luhn.go is the payment-card detector. A candidate is a run of
// 13..19 digits (single spaces or dashes allowed between digits) that passes
// the Luhn checksum; runs of one repeated digit are rejected because no issuer
// assigns them and a run of zeros always passes the checksum.

// luhnConfidence is the fixed confidence of the Luhn rule. A valid checksum
// still leaves roughly a one-in-ten false-positive rate for arbitrary numbers.
const luhnConfidence = 0.9

// Card-number length bounds: issuer identification numbers plus account
// numbers fit 13..19 digits.
const (
	luhnMinDigits = 13
	luhnMaxDigits = 19
)

// findLuhnSpans returns the spans of Luhn-valid card-number runs. The span
// starts at the first digit and ends after the last one, so surrounding
// separators are not reported.
func findLuhnSpans(content []byte) []Span {
	var spans []Span
	for i := 0; i < len(content); {
		if !isASCIIDigit(content[i]) {
			i++
			continue
		}
		runStart := i
		lastDigit := i
		digits := 0
		for i < len(content) && (isASCIIDigit(content[i]) || content[i] == ' ' || content[i] == '-') {
			if isASCIIDigit(content[i]) {
				digits++
				lastDigit = i
			}
			i++
		}
		if digits < luhnMinDigits || digits > luhnMaxDigits {
			continue
		}
		normalized := make([]byte, 0, digits)
		for _, b := range content[runStart : lastDigit+1] {
			if isASCIIDigit(b) {
				normalized = append(normalized, b)
			}
		}
		if allSameDigit(normalized) || !luhnValid(normalized) {
			continue
		}
		spans = append(spans, Span{Start: runStart, End: lastDigit + 1})
	}
	return spans
}

// allSameDigit reports whether every digit is identical. digits is non-empty
// on every call because the digit bound has already been checked.
func allSameDigit(digits []byte) bool {
	for _, b := range digits[1:] {
		if b != digits[0] {
			return false
		}
	}
	return true
}

// luhnValid reports whether digits (ASCII digits only) satisfies the Luhn
// checksum: double every second digit from the right, subtract 9 when the
// doubled value exceeds 9, and require the sum to be a multiple of 10.
func luhnValid(digits []byte) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// luhnRule is the built-in payment-card rule.
type luhnRule struct{ budget int }

// NewLuhnRule returns the built-in rule that flags Luhn-valid card numbers with
// the documented default byte budget.
func NewLuhnRule() Rule { return NewLuhnRuleBudget(PrimitiveByteBudgetBytes) }

// NewLuhnRuleBudget returns the payment-card rule with an explicit per-call
// byte budget.
func NewLuhnRuleBudget(budget int) Rule { return luhnRule{budget: normalizeBudget(budget)} }

// ID returns the frozen detector id.
func (luhnRule) ID() string { return DetectorLuhn }

// Type returns the frozen rule type id.
func (luhnRule) Type() string { return TypeLuhn }

// Category returns the frozen category.
func (luhnRule) Category() string { return CategoryCreditCard }

// Scope returns the request phase: only requests may substitute a placeholder.
func (luhnRule) Scope() Scope { return ScopeRequest }

// Action returns redact, the built-in action for a card-number match.
func (luhnRule) Action() Action { return ActionRedact }

// Priority returns the default rule priority.
func (luhnRule) Priority() int { return DefaultPriority }

// Confidence returns the fixed detector confidence.
func (luhnRule) Confidence() float64 { return luhnConfidence }

// inspectLuhn runs the Luhn algorithm over content truncated to budget; it is
// the compiled-document entry, where no rule struct is materialised.
func inspectLuhn(content []byte, budget int) []Span {
	return findLuhnSpans(primitiveInput(content, budget))
}

// Inspect returns the spans of Luhn-valid card numbers inside leaf.
func (r luhnRule) Inspect(leaf []byte) []Span { return inspectLuhn(leaf, r.budget) }
