package redact

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"

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
// calls, tool uses, completions, messages, responses) plus the common
// request/trace/job id prefixes seen in logs and traces (req_, trace_, span_,
// run_, job_, build_). They are long and random enough to clear the entropy
// floor but are structural, not credentials.
// A candidate is exempt only when the WHOLE candidate run matches, never a
// substring, so a secret that merely starts with one of these prefixes is
// exempt only when it also fits the rest of the grammar (see the honest gap in
// KnownStructuralIdentifierExemptions and egress.go's StructuralIdentifierContains,
// which refuses a known secret hidden inside one of these runs).
var structuralIdentifierPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^(?:call_|toolu_)[A-Za-z0-9_-]{16,}$`),
	regexp.MustCompile(`^(?:chatcmpl-|msg_|resp_)[A-Za-z0-9]{16,}$`),
	regexp.MustCompile(`^(?:req_|trace_|span_|run_|job_|build_)[A-Za-z0-9_-]{16,}$`),
}

// structuralPayloadMinRun is the base64-alphabet run length at or above which
// a run is treated as an opaque payload rather than a credential. Real
// credentials are short: even the longest common key forms are well under 128
// bytes, while multimodal image/attachment bodies and file artifacts routinely
// exceed it. Redacting a body the model must perceive directly (a vision
// request, an inline attachment, a plain JSON string field carrying a blob) is
// a capability loss, not a privacy win, so the length itself is the
// discriminator. The live case that set the bound was a 200-character
// plain-field base64 the model had to read: 256 redacted it, 128 exempts it.
// This is a frozen constant: changing it changes the exemption surface and must
// be a deliberate, documented decision, not silent drift.
const structuralPayloadMinRun = 128

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

// hashedArtifactPathPattern recognises a path carrying a long hex segment (for
// example /tmp/build/<40hex>/out.bin, dist/<40hex>/out.bin or
// /repo/.git/objects/ab/<38hex>): it is absolute or relative, uses only path
// characters, and contains at least structuralPayloadMinHexRun consecutive hex
// digits. Only the hash-bearing shape is exempt; a path without such a segment
// stays a normal candidate. The relative form is deliberate: build tools write
// hash-named artifacts relative to the working directory, and a live request
// redacted dist/<40hex>/out.bin. The run comes from entropyCandidatePattern, so
// its bytes are already limited to the base64/url-safe alphabet, and requiring a
// 32-hex segment makes an accidental match on random base64 astronomically
// unlikely (32 hex characters ≈ 2^-64).
var hashedArtifactPathPattern = regexp.MustCompile(
	`^(?:/)?[A-Za-z0-9._/-]*[0-9a-fA-F]{` + strconv.Itoa(structuralPayloadMinHexRun) + `,}[A-Za-z0-9._/-]*$`)

// prefixedHashPattern recognises a well-formed prefixed hash in the
// Subresource Integrity (SRI) / npm `integrity` spelling: `<algo>-<base64>`,
// where algo is one of the enumerated hash names and the rest is the
// standard-base64 digest. Real provider traffic carries these in package
// manifests and HTML `integrity` attributes, and a live request redacted a
// `sha512-<base64>` integrity value as high_entropy. The body is restricted to
// the standard base64 alphabet (`+`, `/`, `=`) and alphanumerics and must be at
// least 16 bytes, so a credential that merely starts with a hash name and then
// uses url-safe punctuation is NOT exempt.
//
// The `?<options>` suffix SRI allows after the digest is not part of an entropy
// candidate: `?` is outside entropyCandidatePattern's alphabet, so a run ends at
// the digest and the suffix is never a run on its own. Exempting the digest run
// therefore exempts the whole SRI value in practice.
var prefixedHashPattern = regexp.MustCompile(
	`^(?:sha1|sha256|sha384|sha512|md5|blake2b|blake3)-[A-Za-z0-9+/=]{16,}$`)

// structuralPayloadKeys is the enumerated set of JSON member names whose string
// value is a payload the model must perceive directly (an inline file body, an
// image or audio blob, a base64 attachment). A base64-alphabet run that is the
// string value of one of these keys is exempt even below
// structuralPayloadMinRun: the live case was a 120-character base64 `file_data`
// field the model had to read. The key is matched case-insensitively and only
// when the run is the immediately-following JSON string value, so a generic key
// (for example `input`) still takes the length rule and a short credential stays
// redacted. This is an explicit context rule, deliberately NOT a lowering of
// structuralPayloadMinRun (which stays 128).
var structuralPayloadKeys = []string{
	"file_data", "data", "b64", "base64", "blob", "payload",
	"attachment", "image_url", "audio", "content_bytes",
}

// isPrefixedHash reports whether run is a whole SRI / prefixed-hash value.
func isPrefixedHash(run []byte) bool {
	return prefixedHashPattern.Match(run)
}

// payloadKeyBeforeRunPattern matches the JSON member name immediately before a
// run, ending at the run's first byte: optional surrounding quote escaping
// (so a double-encoded leaf's `\"key\":\"` form is recognised as well as plain
// `"key":"`), the key name, the colon, optional whitespace and the value's
// opening quote.
var payloadKeyBeforeRunPattern = regexp.MustCompile(`\\?"([A-Za-z0-9_]+)\\?"\s*:\s*\\?"$`)

// isPayloadKeyValue reports whether the run starting at start is the string
// value of a payload-carrying JSON key from structuralPayloadKeys. It scans
// backwards over the fixed shape `"<key>"<ws>:<ws>"` (optionally escaped) and
// returns false on anything else, so it cannot exempt a run that is not a plain
// JSON string value.
func isPayloadKeyValue(content []byte, start int) bool {
	if start <= 0 || start > len(content) || content[start-1] != '"' {
		return false
	}
	m := payloadKeyBeforeRunPattern.FindSubmatchIndex(content[:start])
	if m == nil || m[1] != start {
		return false
	}
	key := strings.ToLower(string(content[m[2]:m[3]]))
	for _, want := range structuralPayloadKeys {
		if key == want {
			return true
		}
	}
	return false
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

// isExemptRun reports whether the candidate run content[start:end] is skipped
// as an enumerated high_entropy structural exemption. It is the single
// predicate shared by the detector (findHighEntropy) and by the outbound
// re-check's closure (StructuralIdentifierContains), so every class the
// detector skips is also one the closure refuses to trust a known secret
// inside — the two cannot drift apart.
//
// The classes, all enumerated in knownStructuralIdentifierExemptions:
//
//   - provider structural identifiers and common request/trace/job id prefixes
//     (isStructuralIdentifier);
//   - a well-formed prefixed hash / SRI value (isPrefixedHash);
//   - a data-URI base64 payload: the run immediately after `;base64,`;
//   - a base64-alphabet run that is the string value of a payload-carrying key
//     (isPayloadKeyValue), even below structuralPayloadMinRun;
//   - any base64-alphabet run at or above structuralPayloadMinRun, treated as
//     an opaque payload because real credentials are short;
//   - an absolute or relative path carrying a hex segment of
//     structuralPayloadMinHexRun or more (a hash-addressed artifact path).
//
// A run is exempt only when the WHOLE candidate run matches a class, never a
// substring, so a secret that merely resembles one of these shapes is covered
// by the same closure the structural-identifier class already relies on: a
// known secret inside an exempted run is refused at egress.
func isExemptRun(content []byte, start, end int, payloadKey bool) bool {
	run := content[start:end]
	if isStructuralIdentifier(run) {
		return true
	}
	if isPrefixedHash(run) {
		return true
	}
	if isDataURIPayload(content, start) {
		return true
	}
	if payloadKey || isPayloadKeyValue(content, start) {
		return true
	}
	if len(run) >= structuralPayloadMinRun {
		return true
	}
	return hashedArtifactPathPattern.Match(run)
}

// payloadKeyFromPath reports whether the last JSON Pointer segment of path is an
// enumerated payload-carrying key. The detector scans a leaf's decoded value,
// which does not carry its member name, so the member name comes from the path;
// the outbound closure cannot use this (it sees raw bytes only) and scans
// backwards with isPayloadKeyValue instead. Both consult structuralPayloadKeys,
// so the two cannot drift apart.
func payloadKeyFromPath(path string) bool {
	if path == "" {
		return false
	}
	last := path
	if i := strings.LastIndexAny(last, "/#"); i >= 0 {
		last = last[i+1:]
	}
	if last == "" {
		return false
	}
	key := strings.ToLower(last)
	for _, want := range structuralPayloadKeys {
		if key == want {
			return true
		}
	}
	return false
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
// just the provider-identifier grammar: prefixed-hash/SRI values, data-URI
// payloads, payload-length base64 runs, payload-key string values and
// hash-addressed artifact paths are all blanket skips, so a known secret inside
// any of them must not be trusted either.
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
		if isExemptRun(content, m[0], m[1], false) && bytes.Contains(run, needle) {
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
//     provider/request ids, prefixed-hash SRI values, data-URI payloads,
//     payload-key string values, payload-length base64 runs and hash-addressed
//     artifact paths;
//   - a run must contain a digit or one of "+/_=", which removes ordinary long
//     identifiers and natural-language words while keeping random tokens.
//
// The path is the leaf's JSON Pointer; it supplies the member name for the
// payload-key exemption, which the leaf's value alone cannot carry.
func findHighEntropy(content []byte, path string) []span {
	payloadKey := payloadKeyFromPath(path)
	matches := entropyCandidatePattern.FindAllIndex(content, -1)
	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		candidate := content[m[0]:m[1]]
		if hexOnlyPattern.Match(candidate) {
			continue
		}
		if isExemptRun(content, m[0], m[1], payloadKey) {
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
// high-entropy runs while excluding hex digests, ordinary identifiers, and the
// enumerated structural exemptions (including a leaf whose member name is a
// payload-carrying key). It reports Type "high_entropy" with confidence 0.6.
func NewHighEntropyDetector(opts ...Option) extension.Inspector {
	return newPathDetector(detectorIDHighEntropy, typeHighEntropy, highEntropyConfidence, findHighEntropy, opts)
}
