package redact

import (
	"bytes"
	"math"
	"regexp"
	"strconv"

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

// structuralPayloadMinRun is the base64-alphabet run length at or above which
// a run is treated as an opaque payload rather than a credential. Real
// credentials are short: even the longest common key forms are well under 256
// bytes, while multimodal image/attachment bodies and file artifacts routinely
// exceed it. Redacting a body the model must perceive directly (a vision
// request, an inline attachment) is a capability loss, not a privacy win, so
// the length itself is the discriminator. This is a frozen constant: changing
// it changes the exemption surface and must be a deliberate, documented
// decision, not silent drift.
const structuralPayloadMinRun = 256

// structuralPayloadMinHexRun is the hex-segment length at or above which a hex
// run inside an absolute path marks the path as hash-addressed (a
// content-addressed or hash-named artifact). It feeds the quantifier of
// hashedArtifactPathPattern, so the constant and the grammar cannot diverge.
const structuralPayloadMinHexRun = 32

// dataURIMarker is the `;base64,` delimiter that closes a data-URI header
// (`data:<mime>[;param];base64,`). A candidate run whose bytes immediately
// follow this marker is a data-URI payload: it is the image/attachment body
// itself, not a credential, so it is skipped whole.
var dataURIMarker = []byte(";base64,")

// hashedArtifactPathPattern recognises an absolute path carrying a long hex
// segment (for example /tmp/build/<40hex>/out.bin or
// /repo/.git/objects/ab/<38hex>): it starts with '/', uses only path
// characters, and contains at least structuralPayloadMinHexRun consecutive hex
// digits. Only the hash-bearing shape is exempt; an absolute path without such
// a segment stays a normal candidate. The run comes from
// entropyCandidatePattern, so its bytes are already limited to the
// base64/url-safe alphabet, and requiring a 32-hex segment makes an accidental
// match on random base64 astronomically unlikely (32 hex characters ≈ 2^-64).
var hashedArtifactPathPattern = regexp.MustCompile(
	`^/[A-Za-z0-9._/-]*[0-9a-fA-F]{` + strconv.Itoa(structuralPayloadMinHexRun) + `,}[A-Za-z0-9._/-]*$`)

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

// isExemptRun reports whether the candidate run content[start:end] is skipped
// as an enumerated high_entropy structural exemption. It is the single
// predicate shared by the detector (findHighEntropy) and by the outbound
// re-check's closure (StructuralIdentifierContains), so every class the
// detector skips is also one the closure refuses to trust a known secret
// inside — the two cannot drift apart.
//
// The classes, all enumerated in knownStructuralIdentifierExemptions:
//
//   - provider structural identifiers (isStructuralIdentifier);
//   - a data-URI base64 payload: the run immediately after `;base64,`;
//   - any base64-alphabet run at or above structuralPayloadMinRun, treated as
//     an opaque payload because real credentials are short;
//   - an absolute path carrying a hex segment of structuralPayloadMinHexRun or
//     more (a hash-addressed artifact path).
//
// A run is exempt only when the WHOLE candidate run matches a class, never a
// substring, so a secret that merely resembles one of these shapes is covered
// by the same closure the structural-identifier class already relies on: a
// known secret inside an exempted run is refused at egress.
func isExemptRun(content []byte, start, end int) bool {
	run := content[start:end]
	if isStructuralIdentifier(run) {
		return true
	}
	if isDataURIPayload(content, start) {
		return true
	}
	if len(run) >= structuralPayloadMinRun {
		return true
	}
	return hashedArtifactPathPattern.Match(run)
}

// isDataURIPayload reports whether the run starting at start immediately
// follows the `;base64,` marker of a data URI. Only the delimiter is
// inspected, so the predicate needs the surrounding content, not just the run.
func isDataURIPayload(content []byte, start int) bool {
	if start < len(dataURIMarker) {
		return false
	}
	return bytes.Equal(content[start-len(dataURIMarker):start], dataURIMarker)
}

// StructuralIdentifierContains reports whether needle occurs inside a
// high_entropy structural-exemption run of content — that is, inside a maximal
// candidate run that isExemptRun skips. It covers every exemption class, not
// just the provider-identifier grammar: data-URI payloads, payload-length
// base64 runs and hash-addressed artifact paths are all blanket skips, so a
// known secret inside any of them must not be trusted either.
//
// It exists so the outbound re-check can refuse a secret the engine knows when
// the only reason it survived redaction is an exemption: the exemption is
// "this run is not a secret", so a known secret inside such a run is not
// trusted and must block at egress. The check is deliberately fail-closed and
// narrower than findHighEntropy's other skip rules: it fires only for the
// enumerated exemption classes, leaving the pre-existing pure-hex exclusion (a
// recorded limitation) byte-for-byte unchanged.
func StructuralIdentifierContains(content, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
	for _, m := range entropyCandidatePattern.FindAllIndex(content, -1) {
		run := content[m[0]:m[1]]
		if isExemptRun(content, m[0], m[1]) && bytes.Contains(run, needle) {
			return true
		}
	}
	return false
}

// findHighEntropy returns candidate runs whose Shannon entropy is at least
// highEntropyMinBitsPerChar. Four exclusion rules keep precision high:
//
//   - pure-hex runs (plus dashes) are skipped: git SHAs, UUIDs and digests are
//     common in developer traffic and not credentials (frozen);
//   - isExemptRun's enumerated structural exemptions are skipped whole:
//     provider ids, data-URI payloads, payload-length base64 runs and
//     hash-addressed artifact paths;
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
		if isExemptRun(content, m[0], m[1]) {
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
