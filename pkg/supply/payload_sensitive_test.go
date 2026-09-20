package supply

// payload_sensitive_test.go pins the Feature-A signed projection (A-FD6): the
// SensitiveKeysPayload type and its RulesPackPayload slot. Three properties are
// asserted byte-for-byte, never by hash alone: a pack WITHOUT the block is
// byte-identical to the pre-existing preimage, a pack WITH the block has a
// frozen preimage at the pinned declaration slot, and the Ed25519 signature
// really covers the block (a tampered or added block fails verification). The
// floor is checked here too: the block is additive and leaves the baseline
// unchanged.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/filter"
)

// sensitivePackPreimageJSON is the exact frozen preimage of the pack WITH the
// block: the block sits immediately after the omitted optional lists and before
// rules, in the pinned declaration slot.
const (
	sensitivePackPreimageJSON = `{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":4,` +
		`"key_id":"rules-2026-09","not_before":1789344000,"expires":1820880000,` +
		`"sensitive_keys":{"keys":["password","token"],"case_sensitive":true}}`
	sensitivePackHashHex = "fc93d905a53cab49e626eac56718d3aa2aaee5d6e859d54d66bfef5fea19b8fb"
)

// sensitivePackFixture builds one pack whose only optional content is the
// Feature-A block.
func sensitivePackFixture() RulesPackPayload {
	return RulesPackPayload{
		Channel: "stable", SchemaVersion: 1, MinBinaryVersion: "0.3.0", Serial: 4,
		KeyID: "rules-2026-09", NotBefore: EpochSeconds(fixtureNotBefore), Expires: EpochSeconds(fixtureExpires),
		SensitiveKeys: &SensitiveKeysPayload{Keys: []string{"password", "token"}, CaseSensitive: true},
	}
}

// signRulesPack returns pack with its frozen projection signed by priv.
func signRulesPack(pack RulesPackPayload, priv ed25519.PrivateKey) RulesPackPayload {
	pack.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, RulesPackSigningInput(pack)))
	return pack
}

// TestRulesPackPayloadGoldenUnchangedWithoutSensitiveKeys proves the additive
// pointer field does not move a single byte of a pack that omits it: the
// existing rich preimage still marshals unchanged and still hashes to the
// frozen vector, so no signature in force is invalidated.
func TestRulesPackPayloadGoldenUnchangedWithoutSensitiveKeys(t *testing.T) {
	pack := rulesPackFixture()
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("json.Marshal(payload): %v", err)
	}
	if string(raw) != rulesPackPreimageJSON {
		t.Fatalf("preimage drifted:\n got %s\nwant %s", raw, rulesPackPreimageJSON)
	}
	if strings.Contains(string(raw), "sensitive_keys") {
		t.Fatalf("a pack without the block must not emit the key: %s", raw)
	}
	want := DomainRulesPack + "\n" + rulesPackHashHex
	if got := string(RulesPackSigningInput(pack)); got != want {
		t.Fatalf("signing input drifted:\n got %s\nwant %s", got, want)
	}
	if derived := DomainRulesPack + "\n" + testHexHash([]byte(rulesPackPreimageJSON)); derived != want {
		t.Fatal("the existing frozen preimage no longer hashes to its frozen vector")
	}
}

// TestRulesPackPayloadGoldenWithSensitiveKeys pins the exact preimage of a pack
// that carries the block, and the pinned declaration slot: after blocklist and
// before rules.
func TestRulesPackPayloadGoldenWithSensitiveKeys(t *testing.T) {
	pack := sensitivePackFixture()
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("json.Marshal(payload): %v", err)
	}
	if string(raw) != sensitivePackPreimageJSON {
		t.Fatalf("preimage drifted:\n got %s\nwant %s", raw, sensitivePackPreimageJSON)
	}
	want := DomainRulesPack + "\n" + sensitivePackHashHex
	if got := string(RulesPackSigningInput(pack)); got != want {
		t.Fatalf("signing input drifted:\n got %s\nwant %s", got, want)
	}
	if derived := DomainRulesPack + "\n" + testHexHash([]byte(sensitivePackPreimageJSON)); derived != want {
		t.Fatal("the inline preimage does not hash to the inline expected hex")
	}

	// The declaration slot is load-bearing: sensitive_keys must render after
	// blocklist and before rules, or the Pro backend cannot reproduce it.
	rich := rulesPackFixture()
	rich.SensitiveKeys = &SensitiveKeysPayload{Keys: []string{"password"}}
	richRaw, err := json.Marshal(rich)
	if err != nil {
		t.Fatalf("json.Marshal(rich payload): %v", err)
	}
	blockAt := strings.Index(string(richRaw), `"blocklist"`)
	sensitiveAt := strings.Index(string(richRaw), `"sensitive_keys"`)
	rulesAt := strings.Index(string(richRaw), `"rules"`)
	if blockAt < 0 || sensitiveAt < 0 || rulesAt < 0 || blockAt >= sensitiveAt || sensitiveAt >= rulesAt {
		t.Fatalf("sensitive_keys is not pinned between blocklist and rules: %s", richRaw)
	}
}

// TestRulesPackSignatureCoversSensitiveKeys proves the signature really covers
// the block. A pack signed WITH it verifies; any change to the block — a
// different key list, a flipped case flag, or dropping it entirely — fails
// verification. Conversely a pack signed WITHOUT the block cannot have one
// added under the old signature.
func TestRulesPackSignatureCoversSensitiveKeys(t *testing.T) {
	public, priv := substrateKeyPair(t)
	verifier := &rulesKeyVerifier{keyID: rulesTestKeyID, public: public}

	signed := signRulesPack(sensitivePackFixture(), priv)
	if err := VerifyRulesPack(signed, verifier); err != nil {
		t.Fatalf("a pack signed with the block must verify: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*RulesPackPayload)
	}{
		{"keys changed", func(p *RulesPackPayload) {
			p.SensitiveKeys = &SensitiveKeysPayload{Keys: []string{"password", "other"}, CaseSensitive: true}
		}},
		{"case_sensitive flipped", func(p *RulesPackPayload) {
			p.SensitiveKeys = &SensitiveKeysPayload{Keys: []string{"password", "token"}, CaseSensitive: false}
		}},
		{"block dropped", func(p *RulesPackPayload) { p.SensitiveKeys = nil }},
	}
	for _, tc := range mutations {
		mutated := signed
		tc.mutate(&mutated)
		if err := VerifyRulesPack(mutated, verifier); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: err = %v, want ErrBadSignature", tc.name, err)
		}
	}

	// Signing the same pack WITHOUT the block, then adding it, must not verify:
	// the block is inside the signed bytes, not appended to them.
	withoutBlock := signRulesPack(rulesPackFixture(), priv)
	if err := VerifyRulesPack(withoutBlock, verifier); err != nil {
		t.Fatalf("the no-block pack signature must verify: %v", err)
	}
	extended := withoutBlock
	extended.SensitiveKeys = &SensitiveKeysPayload{Keys: []string{"password"}}
	if err := VerifyRulesPack(extended, verifier); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("an added block under the old signature = %v, want ErrBadSignature", err)
	}
}

// TestFloorAcceptsSensitiveKeys pins that the additive block passes the OD-3
// non-weakening floor and does not move the baseline: the six built-in detector
// ids and six categories are unchanged, and a doc that carries the block AND
// weakens the baseline is still refused.
func TestFloorAcceptsSensitiveKeys(t *testing.T) {
	baseline := filter.DefaultFloorBaseline()
	if len(baseline.Detectors) != 6 || len(baseline.Categories) != 6 {
		t.Fatalf("baseline = %d detectors / %d categories, want 6 / 6", len(baseline.Detectors), len(baseline.Categories))
	}

	doc := &filter.Document{
		RemotePack: true, Serial: 1,
		SensitiveKeys: &filter.SensitiveKeysPayload{Keys: []string{"password", "Secret"}},
	}
	if err := baseline.Check(doc); err != nil {
		t.Fatalf("the additive sensitive_keys block must pass the floor: %v", err)
	}

	weakened := &filter.Document{
		RemotePack: true, Detectors: map[string]bool{"prefix": false},
		SensitiveKeys: &filter.SensitiveKeysPayload{Keys: []string{"password"}},
	}
	if err := baseline.Check(weakened); !errors.Is(err, filter.ErrFloorDisablesDetector) {
		t.Fatalf("a disabling pack carrying the block = %v, want ErrFloorDisablesDetector", err)
	}
	if got := filter.DefaultFloorBaseline(); len(got.Detectors) != 6 || len(got.Categories) != 6 {
		t.Fatalf("the floor baseline moved after a sensitive_keys check: %d / %d", len(got.Detectors), len(got.Categories))
	}
}
