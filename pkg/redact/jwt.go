package redact

import (
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/fregie/tokenhush/pkg/extension"
)

// jwtConfidence is the fixed confidence for the JWT detector. A decoded JSON
// header carrying "alg" is a structural guarantee, not a heuristic.
const jwtConfidence = 0.95

// jwtPattern matches the three base64url segments of a JWT. Segment contents
// are validated separately: the first must decode to a JSON object with an
// "alg" key.
var jwtPattern = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// findJWTs returns word-bounded JWT candidates whose header segment decodes to
// JSON containing an "alg" key.
func findJWTs(content []byte) []span {
	matches := jwtPattern.FindAllIndex(content, -1)
	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		start, end := m[0], m[1]
		if start > 0 && isJWTBoundaryByte(content[start-1]) {
			continue
		}
		if end < len(content) && isJWTBoundaryByte(content[end]) {
			continue
		}
		headerEnd := start
		for headerEnd < end && content[headerEnd] != '.' {
			headerEnd++
		}
		if !isJWTHeader(content[start:headerEnd]) {
			continue
		}
		spans = append(spans, span{start: start, end: end})
	}
	return spans
}

// isJWTBoundaryByte reports whether b could extend a JWT-shaped token. The dot
// is included so a four-segment (or longer) run is never truncated into a
// three-segment false positive.
func isJWTBoundaryByte(b byte) bool {
	return isASCIIAlnum(b) || b == '_' || b == '-' || b == '.'
}

// isJWTHeader reports whether segment is unpadded base64url of a JSON object
// with an "alg" key.
func isJWTHeader(segment []byte) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(string(segment))
	if err != nil {
		return false
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &header); err != nil {
		return false
	}
	_, ok := header["alg"]
	return ok
}

// NewJWTDetector returns the built-in Inspector that flags three-segment JWTs
// by validating the decoded header. It reports Type "jwt" with confidence 0.95.
func NewJWTDetector(opts ...Option) extension.Inspector {
	return newDetector(detectorIDJWT, typeJWT, jwtConfidence, findJWTs, opts)
}
