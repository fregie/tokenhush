package rules

// Embedded rule-signing trust root. Rule keys are independent of the license
// and update keys (ADR-0020 §1): a compromise of one channel never authorizes
// another.

import "crypto/ed25519"

// ruleKeyID names the production rule-signing key compiled into this build.
// The owner generated the key pair offline during the signing ceremony
// (ADR-0021); only the public half ships here, so this binary verifies signed
// rule packs but can never sign them.
const ruleKeyID = "rules-2026-09"

// rulePublic is the production public-only rule key. The matching private half
// is held by the owner offline and is never committed or embedded.
var rulePublic = ed25519.PublicKey{
	0x20, 0x10, 0xaf, 0xb1, 0xef, 0x01, 0x41, 0x66,
	0x9f, 0x1e, 0x4d, 0x07, 0xc0, 0xb6, 0xda, 0xab,
	0xd8, 0x32, 0x71, 0x09, 0xbf, 0xf6, 0xe0, 0xcd,
	0xf3, 0xee, 0x83, 0x1d, 0xdf, 0x94, 0x72, 0xfc,
}

// DefaultKeys returns the embedded rule-signing key set.
func DefaultKeys() []Key {
	return []Key{{ID: ruleKeyID, Public: rulePublic}}
}
