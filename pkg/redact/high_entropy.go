package redact

import (
	"bytes"
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

// structuralIdentifierPatterns are the well-formed identifier shapes the
// structural-identifier exemption skips: provider-assigned opaque ids (tool
// calls, tool uses, completions, messages, responses) that are long and random
// enough to clear the entropy floor but are structural, not credentials.
// A candidate is exempt only when the WHOLE candidate run matches, never a
// substring, so a secret that merely starts with one of these prefixes is
// exempt only when it also fits the rest of the grammar (see the honest gap in
// KnownStructuralIdentifierExemptions and egress.go's StructuralIdentifierContains,
// which refuses a known secret hidden inside one of these runs).
var structuralIdentifierPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^(?:call_|toolu_)[A-Za-z0-9_-]{16,}$`),
	regexp.MustCompile(`^(?:chatcmpl-|msg_|resp_)[A-Za-z0-9]{16,}$`),
}

// isStructuralIdentifier reports whether candidate matches one of the
// structural-identifier exemption grammars in full.
func isStructuralIdentifier(candidate []byte) bool {
	for _, pattern := range structuralIdentifierPatterns {
		if pattern.Match(candidate) {
			return true
		}
	}
	return false
}

// StructuralIdentifierContains reports whether needle occurs inside a
// structural-identifier exemption run of content — that is, inside a maximal
// candidate run whose bytes match one of the exemption grammars in full.
//
// It exists so the outbound re-check can refuse a secret the engine knows when
// the only reason it survived redaction is this exemption: the exemption is
// "this run is not a secret", so a known secret inside such a run is not
// trusted and must block at egress. The check is deliberately fail-closed and
// narrower than findHighEntropy's other skip rules: it fires only for the
// structural-identifier grammar, leaving the pre-existing pure-hex exclusion
// (a recorded limitation) byte-for-byte unchanged.
func StructuralIdentifierContains(content, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
	for _, m := range entropyCandidatePattern.FindAllIndex(content, -1) {
		run := content[m[0]:m[1]]
		if isStructuralIdentifier(run) && bytes.Contains(run, needle) {
			return true
		}
	}
	return false
}

// findHighEntropy returns candidate runs whose Shannon entropy is at least
// highEntropyMinBitsPerChar. Three exclusion rules keep precision high:
//
//   - pure-hex runs (plus dashes) are skipped: git SHAs, UUIDs and digests are
//     common in developer traffic and not credentials (frozen);
//   - structural-identifier runs are skipped: provider tool-call, tool-use,
//     completion, message and response ids are structural, not secrets;
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
		if isStructuralIdentifier(candidate) {
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
