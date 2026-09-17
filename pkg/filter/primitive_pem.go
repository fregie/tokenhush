package filter

// primitive_pem.go is the private-key detector. A private-key header is
// unambiguous, so it is the highest-confidence primitive; when the matching
// END marker follows, the span covers the whole block, and an unrelated END is
// never swallowed.

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
// `-----END <kind>-----` marker when one follows the header; otherwise it is
// exactly the header, so a mismatched END is not part of the span.
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
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// pemRule is the built-in private-key rule.
type pemRule struct{}

// NewPEMRule returns the built-in rule that flags PEM private-key blocks.
func NewPEMRule() Rule { return pemRule{} }

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

// Inspect returns the spans of PEM private-key blocks inside leaf.
func (pemRule) Inspect(leaf []byte) []Span { return findPEMSpans(primitiveInput(leaf)) }
