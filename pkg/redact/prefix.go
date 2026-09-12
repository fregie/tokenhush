package redact

import (
	"regexp"

	"github.com/fregie/tokenhush/pkg/extension"
)

// prefixConfidence is the fixed confidence for the prefix detector. Known
// provider key prefixes are the highest-signal shape rule, so this detector
// favours precision over recall (docs/security.md).
const prefixConfidence = 0.95

// prefixPattern matches known credential shapes for widely used AI, cloud and
// developer providers. It is intentionally greedy over each token alphabet so
// a match cannot stop mid-token; the word-boundary check lives in
// findPrefixKeys.
var prefixPattern = regexp.MustCompile(
	`sk-[A-Za-z0-9_-]{16,}` +
		`|(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}` +
		`|github_pat_[A-Za-z0-9_]{30,}` +
		`|gh[pousr]_[A-Za-z0-9]{20,}` +
		`|glpat-[A-Za-z0-9_-]{20,}` +
		`|xox[bapr]-[A-Za-z0-9-]{10,}` +
		`|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}` +
		`|AIza[A-Za-z0-9_-]{35}` +
		`|ya29\.[A-Za-z0-9_-]{20,}` +
		`|npm_[A-Za-z0-9]{36,}` +
		`|pypi-[A-Za-z0-9_-]{20,}` +
		`|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}` +
		`|hf_[A-Za-z0-9]{20,}`,
)

// findPrefixKeys returns word-bounded matches of prefixPattern. A candidate is
// dropped when it is embedded in a longer run of token bytes, so
// "xAKIA..." and "AKIA...ef" are not reported.
func findPrefixKeys(content []byte) []span {
	matches := prefixPattern.FindAllIndex(content, -1)
	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		start, end := m[0], m[1]
		if start > 0 && isTokenByte(content[start-1]) {
			continue
		}
		if end < len(content) && isTokenByte(content[end]) {
			continue
		}
		spans = append(spans, span{start: start, end: end})
	}
	return spans
}

// NewPrefixDetector returns the built-in Inspector that flags known provider
// key prefixes. It reports Type "api_key" with confidence 0.95.
func NewPrefixDetector(opts ...Option) extension.Inspector {
	return newDetector(detectorIDPrefix, typeAPIKey, prefixConfidence, findPrefixKeys, opts)
}
