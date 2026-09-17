package filter

// primitive_email.go is the email-address detector: an address matches only
// when its local and domain parts are both non-empty and neither contains a
// dot run, so "a..b@example.com" and "@example.com" are not addresses.

import (
	"bytes"
	"regexp"
)

// emailConfidence is the fixed confidence of the email rule: mail addresses
// are frequently legitimate, so it is the lowest of the six.
const emailConfidence = 0.8

// emailPattern requires a local part and a dotted domain ending in a 2+ letter
// TLD, so "user@localhost" and "user@example" never match.
var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// findEmailSpans returns email-shaped spans, rejecting candidates with a dot
// run anywhere and candidates whose parts cannot be split at one '@'.
func findEmailSpans(content []byte) []Span {
	matches := emailPattern.FindAllIndex(content, -1)
	spans := make([]Span, 0, len(matches))
	for _, m := range matches {
		candidate := content[m[0]:m[1]]
		if bytes.Contains(candidate, []byte("..")) {
			continue
		}
		local, domain, ok := splitEmail(candidate)
		if !ok || len(local) == 0 || len(domain) == 0 {
			continue
		}
		spans = append(spans, Span{Start: m[0], End: m[1]})
	}
	return spans
}

// splitEmail splits candidate at its single '@'. It reports false for an empty
// local or domain part and for a second '@'.
func splitEmail(candidate []byte) (local, domain []byte, ok bool) {
	at := bytes.IndexByte(candidate, '@')
	if at <= 0 || at == len(candidate)-1 {
		return nil, nil, false
	}
	if bytes.IndexByte(candidate[at+1:], '@') >= 0 {
		return nil, nil, false
	}
	return candidate[:at], candidate[at+1:], true
}

// emailRule is the built-in email-address rule.
type emailRule struct{}

// NewEmailRule returns the built-in rule that flags email addresses.
func NewEmailRule() Rule { return emailRule{} }

// ID returns the frozen detector id.
func (emailRule) ID() string { return DetectorEmail }

// Type returns the frozen rule type id.
func (emailRule) Type() string { return TypeEmail }

// Category returns the frozen category.
func (emailRule) Category() string { return CategoryEmail }

// Scope returns the request phase: only requests may substitute a placeholder.
func (emailRule) Scope() Scope { return ScopeRequest }

// Action returns redact, the built-in action for an address match.
func (emailRule) Action() Action { return ActionRedact }

// Priority returns the default rule priority.
func (emailRule) Priority() int { return DefaultPriority }

// Confidence returns the fixed detector confidence.
func (emailRule) Confidence() float64 { return emailConfidence }

// Inspect returns the spans of email addresses inside leaf.
func (emailRule) Inspect(leaf []byte) []Span { return findEmailSpans(primitiveInput(leaf)) }
