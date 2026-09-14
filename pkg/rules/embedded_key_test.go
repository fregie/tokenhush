package rules

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// TestEmbeddedRuleKeyIsTheProductionKey locks the rule trust root: the embedded
// key_id and public bytes must equal this checked-in expectation. The literal
// is independent of rulePublic so a placeholder regression or an accidental key
// swap fails here instead of shipping silently.
func TestEmbeddedRuleKeyIsTheProductionKey(t *testing.T) {
	want := ed25519.PublicKey{
		0x20, 0x10, 0xaf, 0xb1, 0xef, 0x01, 0x41, 0x66,
		0x9f, 0x1e, 0x4d, 0x07, 0xc0, 0xb6, 0xda, 0xab,
		0xd8, 0x32, 0x71, 0x09, 0xbf, 0xf6, 0xe0, 0xcd,
		0xf3, 0xee, 0x83, 0x1d, 0xdf, 0x94, 0x72, 0xfc,
	}
	keys := DefaultKeys()
	if len(keys) != 1 {
		t.Fatalf("DefaultKeys() has %d entries, want exactly 1", len(keys))
	}
	if got := keys[0].ID; got != "rules-2026-09" {
		t.Errorf("DefaultKeys()[0].ID = %q, want %q", got, "rules-2026-09")
	}
	if got := keys[0].Public; !bytes.Equal(got, want) {
		t.Errorf("DefaultKeys()[0].Public = %x, want %x", got, want)
	}
	if got := ruleKeyID; got != "rules-2026-09" {
		t.Errorf("ruleKeyID = %q, want %q", got, "rules-2026-09")
	}
}
