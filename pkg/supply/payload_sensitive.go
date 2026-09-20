package supply

// payload_sensitive.go holds the Feature-A signed projection type, split out
// of payload.go so that file stays under the pure-LOC ceiling. The type is a
// hand-written member of the frozen rules-pack payload exactly like the ones in
// payload.go: its field set, JSON names, Go types and omitempty tags define the
// bytes the Pro signing backend and this client hash.

// SensitiveKeysPayload is the frozen signed projection of the rules-pack
// `sensitive_keys` block: the immediate object member key names whose values
// the request path redacts, and whether that match is case-sensitive. Both
// fields carry omitempty so an empty block never emits a key the frozen
// preimage did not have, and the fields mirror pkg/filter's decoded
// SensitiveKeysPayload: only the immediate key of a string member matches, and
// a container value never matches.
//
// Operational consequence of NOT bumping schema_version (an approved
// decision): a pack that carries `sensitive_keys` is rejected by an older
// client whose DisallowUnknownFields decode does not know the key. That client
// falls back to its built-in detectors, so the block is inert, never
// misapplied. The Pro signing backend must therefore emit this block only to
// clients that already support it; it must never rely on the pack alone to
// gate the feature.
type SensitiveKeysPayload struct {
	Keys          []string `json:"keys,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}
