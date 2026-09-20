package filter

// sensitive_schema.go holds the Feature-A sensitive_keys sub-object schema: its
// strict field set, its bounds and its validation. It is split out of schema.go
// so both files stay under the pure-LOC ceiling. The block is additive and
// opt-in: absent means no matcher, and its effect is a fixed request-phase
// redact, so it carries no action field.

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// MaxSensitiveKeys bounds the key list of one sensitive_keys block. The count
// bound fails with ErrBoundExceeded, exactly like every other document bound.
const MaxSensitiveKeys = 256

// SensitiveKeysPayload is the decoded sensitive_keys block: the immediate
// object member key names whose values are redacted on the request path, and
// whether matching is case-sensitive. The default, false, folds ASCII case.
type SensitiveKeysPayload struct {
	Keys          []string `json:"keys"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}

// sensitiveKeysFields is the complete allowed key set of the sub-object; every
// other sub-key is rejected by name as sensitive_keys.<name>.
var sensitiveKeysFields = map[string]bool{"keys": true, "case_sensitive": true}

// validateSensitiveFields strictly validates the raw sensitive_keys value of a
// document field set, when present. It keeps the DecodeDocument hook in
// schema.go to one call so that file stays under the pure-LOC ceiling.
func validateSensitiveFields(fields map[string]json.RawMessage) error {
	raw, ok := fields["sensitive_keys"]
	if !ok {
		return nil
	}
	return validateSensitiveKeys(raw)
}

// validateSensitiveKeys strictly validates one raw sensitive_keys value: the
// field set first (so an unknown sub-key is named), then the decoded key list
// against every bound. A JSON null is treated as an absent block.
func validateSensitiveKeys(raw json.RawMessage) error {
	if isJSONNull(raw) {
		return nil
	}
	if _, err := strictObject(raw, sensitiveKeysFields, "sensitive_keys"); err != nil {
		return err
	}
	var payload SensitiveKeysPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fieldError(ErrInvalidValue, "sensitive_keys", "%v", err)
	}
	return checkSensitiveKeys(payload.Keys)
}

// checkSensitiveKeys enforces the block bounds on a decoded key list: at least
// one key, at most MaxSensitiveKeys, no empty key and no key above
// MaxLiteralBytes. It runs on both the decode path and the compile path, so a
// hand-built document cannot skip a bound the decoder enforces.
func checkSensitiveKeys(keys []string) error {
	if len(keys) == 0 {
		return fieldError(ErrInvalidValue, "sensitive_keys.keys", "at least one key is required")
	}
	if len(keys) > MaxSensitiveKeys {
		return fieldError(ErrBoundExceeded, "sensitive_keys.keys", "%d keys exceed the %d-key bound", len(keys), MaxSensitiveKeys)
	}
	for i, key := range keys {
		path := fmt.Sprintf("sensitive_keys.keys[%d]", i)
		if key == "" {
			return fieldError(ErrInvalidValue, path, "key must not be empty")
		}
		if len(key) > MaxLiteralBytes {
			return fieldError(ErrBoundExceeded, path, "key is %d bytes, above the %d-byte bound", len(key), MaxLiteralBytes)
		}
	}
	return nil
}

// isJSONNull reports whether raw is the JSON literal null, ignoring whitespace.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
