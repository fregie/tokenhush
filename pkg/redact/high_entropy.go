package redact

import (
	"math"
	"regexp"

	"github.com/fregie/tokenhush/pkg/extension"
)

// highEntropyConfidence is the fixed confidence for the high-entropy detector.
// Entropy is a weaker signal than a known prefix, so the value is deliberately
// low: redaction is still applied, but policy can treat it as advisory.
const highEntropyConfidence = 0.6

// highEntropyMinBitsPerChar is the Shannon entropy floor, in bits per byte.
// Natural-language runs sit below it; random base64 tokens sit well above it.
const highEntropyMinBitsPerChar = 4.0

// entropyCandidatePattern captures maximal runs over the base64/url-safe
// alphabet. The {28,} quantifier is the minimum candidate length.
var entropyCandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{28,}`)

// hexOnlyPattern recognises pure-hex runs (git object ids, UUIDs, digests).
// Their entropy can reach exactly 4.0 bits/char, so the entropy floor alone
// would not exclude them; the explicit rule does.
var hexOnlyPattern = regexp.MustCompile(`^[0-9a-fA-F-]+$`)

// findHighEntropy returns candidate runs whose Shannon entropy is at least
// highEntropyMinBitsPerChar. Two exclusion rules keep precision high:
//
//   - pure-hex runs (plus dashes) are skipped: git SHAs, UUIDs and digests are
//     common in developer traffic and not credentials;
//   - a run must contain a digit or one of "+/_=", which removes ordinary long
//     identifiers and natural-language words while keeping random tokens.
func findHighEntropy(content []byte) []span {
	matches := entropyCandidatePattern.FindAllIndex(content, -1)
	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		candidate := content[m[0]:m[1]]
		if hexOnlyPattern.Match(candidate) {
			continue
		}
		if !hasDigitOrEntropyPunctuation(candidate) {
			continue
		}
		if shannonEntropy(candidate) < highEntropyMinBitsPerChar {
			continue
		}
		spans = append(spans, span{start: m[0], end: m[1]})
	}
	return spans
}

// hasDigitOrEntropyPunctuation reports whether candidate contains an ASCII
// digit or one of the characters that rarely occur in prose tokens: + / _ =.
func hasDigitOrEntropyPunctuation(candidate []byte) bool {
	for _, b := range candidate {
		if isASCIIDigit(b) {
			return true
		}
		switch b {
		case '+', '/', '_', '=':
			return true
		}
	}
	return false
}

// shannonEntropy returns the Shannon entropy of candidate in bits per byte.
func shannonEntropy(candidate []byte) float64 {
	if len(candidate) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range candidate {
		counts[b]++
	}
	total := float64(len(candidate))
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

// NewHighEntropyDetector returns the built-in Inspector that flags long,
// high-entropy runs while excluding hex digests and ordinary identifiers. It
// reports Type "high_entropy" with confidence 0.6.
func NewHighEntropyDetector(opts ...Option) extension.Inspector {
	return newDetector(detectorIDHighEntropy, typeHighEntropy, highEntropyConfidence, findHighEntropy, opts)
}
