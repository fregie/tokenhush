package rules

// Embedded rule-signing trust root. Rule keys are independent of the license
// and update keys (ADR-0020 §1): a compromise of one channel never authorizes
// another.

import "crypto/ed25519"

// bootstrapRuleKeyID names the placeholder rule-signing key compiled into this
// build. It mirrors pkg/update's bootstrap root: the owner generates the
// production rule key offline during the signing ceremony (ADR-0021) and
// replaces this entry. Tests inject their own keys and never depend on it.
const bootstrapRuleKeyID = "rules-bootstrap-2026-09"

// bootstrapRulePublic is a public-only placeholder. The matching private half
// is not committed and is not held by this build, so it verifies nothing today.
var bootstrapRulePublic = ed25519.PublicKey{
	0x8f, 0x2c, 0x64, 0xa1, 0x03, 0x7e, 0xd5, 0x19,
	0xbb, 0x40, 0x92, 0x6a, 0xf1, 0x58, 0xc7, 0x0d,
	0x34, 0xe6, 0x71, 0x2b, 0xa8, 0x50, 0x9c, 0xde,
	0x17, 0x63, 0xf4, 0x85, 0x2e, 0xb0, 0x4a, 0xd9,
}

// DefaultKeys returns the embedded rule-signing key set.
func DefaultKeys() []Key {
	return []Key{{ID: bootstrapRuleKeyID, Public: bootstrapRulePublic}}
}
