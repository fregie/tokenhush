package filter

// primitive_jwt.go is the JWT detector and the one allowlisted decoder site in
// pkg/filter: it decodes only the header segment of a candidate, and only to
// prove the token is structural (a JSON object carrying an "alg" member).
// Nothing decoded here is handed back to any detector.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
)

// jwtConfidence is the fixed confidence of the JWT rule: a header that decodes
// to JSON with an "alg" member is a structural guarantee, not a heuristic.
const jwtConfidence = 0.95

// jwtPattern matches three base64url segments separated by dots. '=' is in the
// alphabet because base64url padding is tolerated; segment contents are
// validated by decoding the header.
var jwtPattern = regexp.MustCompile(`[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+`)

// findJWTspans returns word-bounded candidates of exactly three segments whose
// header decodes to JSON containing an "alg" member.
func findJWTspans(content []byte) []Span {
	matches := jwtPattern.FindAllIndex(content, -1)
	spans := make([]Span, 0, len(matches))
	for _, m := range matches {
		start, end := m[0], m[1]
		if start > 0 && isJWTBoundaryByte(content[start-1]) {
			continue
		}
		if end < len(content) && isJWTBoundaryByte(content[end]) {
			continue
		}
		dot := bytes.IndexByte(content[start:end], '.')
		if dot <= 0 || start+dot >= end {
			continue
		}
		if !isJWTHeader(content[start : start+dot]) {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// isJWTBoundaryByte reports whether b could extend a JWT-shaped token. The dot
// is included so a four-segment run is never truncated into a false positive.
func isJWTBoundaryByte(b byte) bool {
	return isASCIIAlnum(b) || b == '_' || b == '-' || b == '.' || b == '='
}

// isJWTHeader reports whether segment is a base64url-encoded JSON object with
// an "alg" member.
func isJWTHeader(segment []byte) bool {
	decoded, ok := decodeBase64URL(segment)
	if !ok {
		return false
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &header); err != nil {
		return false
	}
	_, ok = header["alg"]
	return ok
}

// decodeBase64URL decodes one base64url segment, tolerating optional '='
// padding. This is the only decoder call any primitive makes.
func decodeBase64URL(segment []byte) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimRight(segment, "=")))
	if err != nil {
		return nil, false
	}
	return decoded, true
}

// jwtRule is the built-in JWT rule.
type jwtRule struct{ budget int }

// NewJWTRule returns the built-in rule that flags JSON Web Tokens with the
// documented default byte budget.
func NewJWTRule() Rule { return NewJWTRuleBudget(PrimitiveByteBudgetBytes) }

// NewJWTRuleBudget returns the JWT rule with an explicit per-call byte budget.
func NewJWTRuleBudget(budget int) Rule { return jwtRule{budget: normalizeBudget(budget)} }

// ID returns the frozen detector id.
func (jwtRule) ID() string { return DetectorJWT }

// Type returns the frozen rule type id.
func (jwtRule) Type() string { return TypeJWT }

// Category returns the frozen category.
func (jwtRule) Category() string { return CategoryJWT }

// Scope returns the request phase: only requests may substitute a placeholder.
func (jwtRule) Scope() Scope { return ScopeRequest }

// Action returns redact, the built-in action for a token match.
func (jwtRule) Action() Action { return ActionRedact }

// Priority returns the default rule priority.
func (jwtRule) Priority() int { return DefaultPriority }

// Confidence returns the fixed detector confidence.
func (jwtRule) Confidence() float64 { return jwtConfidence }

// inspectJWT runs the JWT algorithm over content truncated to budget; it is the
// compiled-document entry, where no rule struct is materialised.
func inspectJWT(content []byte, budget int) []Span {
	return findJWTspans(primitiveInput(content, budget))
}

// Inspect returns the spans of JSON Web Tokens inside leaf.
func (r jwtRule) Inspect(leaf []byte) []Span { return inspectJWT(leaf, r.budget) }
