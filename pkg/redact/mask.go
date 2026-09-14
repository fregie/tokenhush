package redact

// Masking policy for the human-facing redaction log.
//
// A redaction log line must let an operator recognise WHICH value was replaced
// without ever exposing it, so MaskSecret reveals a bounded, fixed number of
// leading and trailing runes for opaque credential tokens only. Every other
// detector type — card numbers, email, JWT and PEM private keys — reveals
// nothing. The result is provably never the full value: the reveal class keeps
// at least maskMinHidden runes masked, and the no-reveal class returns a
// constant shorter than every built-in detector's minimum match.
const (
	// maskMinLen is the shortest value eligible for an edge reveal. Below it the
	// value is fully masked, so a short secret can never be reconstructed.
	maskMinLen = 16
	// maskMinHidden is the fewest runes an edge reveal may leave masked.
	maskMinHidden = 8
	// maskEdgePrefix and maskEdgeSuffix are the runes revealed for an eligible
	// opaque token.
	maskEdgePrefix = 4
	maskEdgeSuffix = 2
	// maskFull is the fixed no-reveal form. It is shorter than every built-in
	// detector's minimum match, so it can neither equal nor contain a match.
	maskFull = "****"
	// maskEllipsis separates the revealed edges from the masked middle.
	maskEllipsis = "…"
	// maskFallback is a second, distinct constant used only when the computed
	// form would equal the value itself (defensive; unreachable for a real
	// detector match, whose length is well above len(maskFull)).
	maskFallback = "[redacted]"
)

// maskEdgeTypes are the detector types whose matched value is an opaque
// credential token, where a bounded prefix and suffix show provider shape (for
// example "sk-p…j0") without revealing it. Structured and PII types are absent
// on purpose: a card number, email, JWT or PEM block must never reveal a byte.
var maskEdgeTypes = map[string]struct{}{
	"api_key":      {},
	"high_entropy": {},
}

// MaskSecret returns a masked, human-readable form of a detected value for a
// redaction log line. It never returns value and never contains value as a
// substring:
//
//   - opaque token types (api_key, high_entropy) with at least maskMinLen runes
//     keep the first maskEdgePrefix and last maskEdgeSuffix runes and replace
//     the middle with an ellipsis, so at least maskMinHidden runes stay hidden;
//   - every other value becomes the constant maskFull.
//
// detectorType selects the reveal class; an unknown type is treated as
// no-reveal. MaskSecret works on runes, so a multi-byte value is never split
// mid-character.
func MaskSecret(value, detectorType string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return maskFull
	}
	masked := maskFull
	if _, ok := maskEdgeTypes[detectorType]; ok &&
		len(runes) >= maskMinLen &&
		len(runes)-maskEdgePrefix-maskEdgeSuffix >= maskMinHidden {
		masked = string(runes[:maskEdgePrefix]) + maskEllipsis + string(runes[len(runes)-maskEdgeSuffix:])
	}
	if masked == value {
		masked = maskFallback
	}
	return masked
}
