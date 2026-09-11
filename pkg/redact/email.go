package redact

import (
	"bytes"
	"regexp"

	"github.com/fregie/tokenhush/pkg/extension"
)

// emailConfidence is the fixed confidence for the email detector. Email is the
// least specific built-in rule (mail addresses are frequently legitimate), so
// the value is the lowest of the six.
const emailConfidence = 0.8

// emailPattern requires a local part and a dotted domain ending in a 2+ letter
// TLD, so "foo@bar", "@decorator" and "user@localhost" never match.
var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// findEmails returns email-shaped spans, rejecting candidates with consecutive
// dots in the domain ("foo@bar..com").
func findEmails(content []byte) []span {
	matches := emailPattern.FindAllIndex(content, -1)
	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		if bytes.Contains(content[m[0]:m[1]], []byte("..")) {
			continue
		}
		spans = append(spans, span{start: m[0], end: m[1]})
	}
	return spans
}

// NewEmailDetector returns the built-in Inspector that flags email addresses.
// It reports Type "email" with confidence 0.8.
func NewEmailDetector(opts ...Option) extension.Inspector {
	return newDetector(detectorIDEmail, typeEmail, emailConfidence, findEmails, opts)
}
