package filter

// primitive_pem.go is the private-key detector. A private-key header is
// unambiguous, so it is the highest-confidence primitive; when the matching
// END marker follows, the span covers the whole block. When no matching END is
// found, the span is over-redacted to the end of the scanned input on purpose:
// an unterminated or budget-truncated PEM would otherwise leak the whole key
// body while redacting only the header, and over-redaction beats leaking a
// key.

import (
	"bytes"
	"regexp"
)

// pemConfidence is the fixed confidence of the PEM rule.
const pemConfidence = 0.99

// privateKeyHeaderPattern matches PEM private-key headers (PKCS#1/PKCS#8,
// OpenSSH, PGP "BLOCK", ...). The literal "PRIVATE KEY" excludes PUBLIC KEY
// and CERTIFICATE markers by construction.
var privateKeyHeaderPattern = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----`)

// findPEMSpans returns private-key blocks. A span extends through the matching
// `-----END <kind>-----` marker when one follows the header; otherwise it
// extends to the end of the scanned input, so the body of an unterminated or
// budget-truncated block is redacted rather than leaked. A mismatched END is
// therefore never treated as a terminator: only the block's own END closes it.
func findPEMSpans(content []byte) []Span {
	matches := privateKeyHeaderPattern.FindAllSubmatchIndex(content, -1)
	spans := make([]Span, 0, len(matches))
	for _, m := range matches {
		start, end := m[0], m[1]
		kind := content[m[2]:m[3]]
		footer := make([]byte, 0, len(kind)+len("-----END -----"))
		footer = append(footer, "-----END "...)
		footer = append(footer, kind...)
		footer = append(footer, "-----"...)
		if i := bytes.Index(content[end:], footer); i >= 0 {
			end += i + len(footer)
		} else {
			end = len(content)
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// pemRule is the built-in private-key rule.
type pemRule struct{ budget int }

// NewPEMRule returns the built-in rule that flags PEM private-key blocks with
// the documented default byte budget.
func NewPEMRule() Rule { return NewPEMRuleBudget(PrimitiveByteBudgetBytes) }

// NewPEMRuleBudget returns the private-key rule with an explicit per-call byte
// budget.
func NewPEMRuleBudget(budget int) Rule { return pemRule{budget: normalizeBudget(budget)} }

// ID returns the frozen detector id.
func (pemRule) ID() string { return DetectorPrivateKey }

// Type returns the frozen rule type id.
func (pemRule) Type() string { return TypePEM }

// Category returns the frozen category.
func (pemRule) Category() string { return CategoryPrivateKey }

// Scope returns the request phase: only requests may substitute a placeholder.
func (pemRule) Scope() Scope { return ScopeRequest }

// Action returns redact, the built-in action for a key match.
func (pemRule) Action() Action { return ActionRedact }

// Priority returns the default rule priority.
func (pemRule) Priority() int { return DefaultPriority }

// Confidence returns the fixed detector confidence.
func (pemRule) Confidence() float64 { return pemConfidence }

// inspectPEM runs the PEM algorithm over content truncated to budget; it is the
// compiled-document entry, where no rule struct is materialised.
func inspectPEM(content []byte, budget int) []Span {
	return findPEMSpans(primitiveInput(content, budget))
}

// Inspect returns the spans of PEM private-key blocks inside leaf.
func (r pemRule) Inspect(leaf []byte) []Span { return inspectPEM(leaf, r.budget) }
