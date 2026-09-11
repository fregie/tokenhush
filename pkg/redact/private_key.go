package redact

import (
	"bytes"
	"regexp"

	"github.com/fregie/tokenhush/pkg/extension"
)

// privateKeyConfidence is the fixed confidence for the private-key detector.
// A PEM private-key header is unambiguous, so this is the highest-confidence
// built-in rule.
const privateKeyConfidence = 0.99

// privateKeyHeaderPattern matches PEM private-key headers (PKCS#1/PKCS#8,
// OpenSSH, PGP "BLOCK", ...). The literal "PRIVATE KEY" excludes PUBLIC KEY and
// CERTIFICATE markers by construction.
var privateKeyHeaderPattern = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----`)

// findPrivateKeys returns private-key blocks. When a matching END marker is
// present the span is extended through it (the whole PEM block); otherwise the
// span is just the header.
func findPrivateKeys(content []byte) []span {
	matches := privateKeyHeaderPattern.FindAllSubmatchIndex(content, -1)
	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		start, end := m[0], m[1]
		kind := content[m[2]:m[3]]
		footer := make([]byte, 0, len(kind)+16)
		footer = append(footer, "-----END "...)
		footer = append(footer, kind...)
		footer = append(footer, "-----"...)
		if i := bytes.Index(content[end:], footer); i >= 0 {
			end += i + len(footer)
		}
		spans = append(spans, span{start: start, end: end})
	}
	return spans
}

// NewPrivateKeyDetector returns the built-in Inspector that flags PEM
// private-key blocks. It reports Type "private_key" with confidence 0.99.
func NewPrivateKeyDetector(opts ...Option) extension.Inspector {
	return newDetector(detectorIDPrivateKey, typePrivateKey, privateKeyConfidence, findPrivateKeys, opts)
}
