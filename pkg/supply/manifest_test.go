package supply

// manifest_test.go is the W5.2 suite: the frozen payload structs, the two
// signing-input projections, decode, verify and the OD-4 gate. Every expected
// value is an inline literal — the golden corpus lands in W5.7 and is not
// referenced here — and every rules expectation is cross-checked against an
// inline projection JSON literal, so a shape drift (not just a hash drift)
// fails the test.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/filter"
)

// Fixture timestamps: 2026-09-14T00:00:00Z and 2027-09-14T00:00:00Z.
const (
	fixtureNotBefore = 1789344000
	fixtureExpires   = 1820880000
	fixtureSHA256    = "9feaf199f64436846911f45c8dee377367d52dbc6277191a1cf740e4e535c2a3"
	fixtureUpdateURL = "https://updates.tokenhush.com/dl/tokenhush_0.4.1_linux_amd64.tar.gz"
	fixturePublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// Inline update expectations: exact projection bytes, computed independently
// from the legacy field order and list rendering, not from this package.
const (
	wantUpdateManifestProjection = "tokenhush-update-manifest-v1\n" +
		"version:0.4.1\n" +
		"os:linux\n" +
		"arch:amd64\n" +
		"url:" + fixtureUpdateURL + "\n" +
		"sha256:" + fixtureSHA256 + "\n" +
		"channel:stable\n" +
		"serial:2\n" +
		"key_id:upd-2026-09\n" +
		"not_before:1789344000\n" +
		"expires:1820880000\n" +
		"revoked_serials:9,10,11\n" +
		"revoked_versions:1.10.0,1.9.0\n"

	wantUpdateManifestEmptyProjection = "tokenhush-update-manifest-v1\n" +
		"version:0.4.1\n" +
		"os:linux\n" +
		"arch:amd64\n" +
		"url:" + fixtureUpdateURL + "\n" +
		"sha256:" + fixtureSHA256 + "\n" +
		"channel:stable\n" +
		"serial:2\n" +
		"key_id:upd-2026-09\n" +
		"not_before:1789344000\n" +
		"expires:1820880000\n" +
		"revoked_serials:\n" +
		"revoked_versions:\n"

	wantUpdateRevocationsProjection = "tokenhush-update-revocations-v1\n" +
		"channel:stable\n" +
		"serial:2\n" +
		"key_id:upd-2026-09\n" +
		"not_before:1789344000\n" +
		"expires:1820880000\n" +
		"revoked_serials:1,5\n" +
		"revoked_versions:0.3.9\n"

	wantUpdateRevocationsEmptyProjection = "tokenhush-update-revocations-v1\n" +
		"channel:stable\n" +
		"serial:1\n" +
		"key_id:upd-2026-09\n" +
		"not_before:1789344000\n" +
		"expires:1820880000\n" +
		"revoked_serials:\n" +
		"revoked_versions:\n"

	wantUpdateKeyListProjection = "tokenhush-update-keylist-v1\n" +
		"serial:1\n" +
		"key_id:root-2026-09\n" +
		"not_before:1789344000\n" +
		"expires:1820880000\n" +
		"key:upd-2026-09:" + fixturePublicKey + ":1789344000:1820880000\n" +
		"key:upd-2026-10:" + fixturePublicKey + ":1789344000:1820880000\n"
)

// Inline rules expectations: the exact projection preimage JSON and the hash
// the domain-separated signing input carries. The preimages were hashed
// independently of this package; the tests also re-hash them in place.
const (
	rulesPackPreimageJSON = `{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":2,` +
		`"key_id":"rules-2026-09","not_before":1789344000,"expires":1820880000,` +
		`"detectors":{"email":true,"prefix":true},"disabled_categories":["internal_only"],` +
		`"allowlist":["example.com"],"blocklist":["TOKENHUSH_BLOCK"],` +
		`"rules":[` + rulesProjRuleJSON + `,` +
		`{"id":"secret","type":"keyword","keywords":["secret","token"],"action":"block","case_sensitive":true,` +
		`"allowlist":["not-a-secret"]},` + rulesCommandRuleJSON + `]}`
	rulesPackHashHex = "c0eba4383f234dd6bc944c30d98d2185a5b9934b514d5fd87449ddc8d8bc7eee"

	// rulesCommandPackPreimageJSON is a dedicated command-bearing payload: the
	// legacy command fields must appear in the signed preimage exactly here.
	rulesCommandPackPreimageJSON = `{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":5,` +
		`"key_id":"rules-2026-09","not_before":1789344000,"expires":1820880000,` +
		`"rules":[` + rulesCommandRuleJSON + `]}`
	rulesCommandPackHashHex = "e27facebe13a6bc55b13347fb8e07db1cd6ea75f865cec2bde39080816f201a8"

	rulesCommandRuleJSON = `{"id":"cmd","type":"command","action":"block","command":"aws",` +
		`"subcommand":"s3","verbs":["rm","delete"],"targets":["s3://prod"]}`
	rulesProjRuleJSON = `{"id":"proj","type":"regex","pattern":"PROJ-[0-9]{4,}","action":"warn","confidence":0.85}`

	rulesPackEmptyPreimageJSON = `{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":2,` +
		`"key_id":"rules-2026-09","not_before":1789344000,"expires":1820880000}`
	rulesPackEmptyHashHex = "fdb407c8f62d71ed58cbca9306239a05c9db28a15ff5cd620f2064f85e462472"

	rulesManifestPreimageJSON = `{"channel":"stable","schema_version":2,"min_binary_version":"0.3.0","serial":3,` +
		`"key_id":"rules-2026-09","not_before":1789344000,"expires":1820880000,` +
		`"bundle_sha256":"` + fixtureSHA256 + `","bundle":"rules/stable/3.json","revoked_serials":[1,4]}`
	rulesManifestHashHex = "436807db8ac71a2158229383477106c76309e2933a35b27ae97133e9ce6bfed6"

	rulesManifestEmptyPreimageJSON = `{"channel":"stable","schema_version":2,"min_binary_version":"0.3.0","serial":3,` +
		`"key_id":"rules-2026-09","not_before":1789344000,"expires":1820880000,` +
		`"bundle_sha256":"` + fixtureSHA256 + `","bundle":"rules/stable/3.json"}`
	rulesManifestEmptyHashHex = "9efec41bf70205071cdfccfc13c98120467f6bfe509989fc7196f8e690dc1cb9"

	rulesRevocationsPreimageJSON = `{"channel":"stable","serial":2,"key_id":"rules-2026-09",` +
		`"not_before":1789344000,"expires":1820880000,"revoked_serials":[2,5,9]}`
	rulesRevocationsHashHex = "d852fd117197c87d7303eff9af040360dc0684657090da48cb2fc90a82bb90fa"

	rulesRevocationsEmptyPreimageJSON = `{"channel":"stable","serial":1,"key_id":"rules-2026-09",` +
		`"not_before":1789344000,"expires":1820880000,"revoked_serials":[]}`
	rulesRevocationsEmptyHashHex = "4fdd27e72cfd43ecdb32d67b913508084475601073e957d36d89fc2f580c7d6e"

	filterFixtureDocJSON = `{"channel":"stable","schema_version":1,"rules":[` + rulesProjRuleJSON + `]}`
)

// rulesManifestDocJSON is a raw wire document: RFC 3339 timestamps, unsorted
// revoked serials. Decoding it must reach the same frozen projection.
const rulesManifestDocJSON = `{"channel":"stable","schema_version":2,"min_binary_version":"0.3.0","serial":3,` +
	`"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z",` +
	`"bundle_sha256":"` + fixtureSHA256 + `","bundle":"rules/stable/3.json","revoked_serials":[4,1]}`

const rulesManifestSignedDocJSON = `{"channel":"stable","schema_version":2,"min_binary_version":"0.3.0","serial":3,` +
	`"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z",` +
	`"bundle_sha256":"` + fixtureSHA256 + `","bundle":"rules/stable/3.json","revoked_serials":[4,1],` +
	`"signature":"c2ln"}`

// rulesManifestVerifier is a Verifier bound to one test key. It resolves only
// the rules-manifest domain, so a projection wired to the wrong domain fails.
type rulesManifestVerifier struct{ public string }

func (v rulesManifestVerifier) Verify(domain, keyID string, signingInput, sig []byte) error {
	if domain != DomainRulesManifest {
		return ErrWrongKey
	}
	return VerifyEd25519(v.public, signingInput, sig)
}

// signRulesManifest signs m in place with priv.
func signRulesManifest(t *testing.T, m *RulesManifestPayload, priv ed25519.PrivateKey) {
	t.Helper()
	m.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, RulesManifestSigningInput(*m)))
}

// testHexHash is the test's own sha256-hex, independent of the projection
// helpers, so an inline preimage can be checked against an inline hash.
func testHexHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func f64(v float64) *float64 { return &v }

func updateManifestFixture() UpdateManifestPayload {
	return UpdateManifestPayload{
		Version: "0.4.1", OS: "linux", Arch: "amd64", URL: fixtureUpdateURL,
		SHA256: fixtureSHA256, Channel: "stable", Serial: 2, KeyID: "upd-2026-09",
		NotBefore: time.Unix(fixtureNotBefore, 0).UTC(), Expires: time.Unix(fixtureExpires, 0).UTC(),
		RevokedSerials: []uint64{11, 9, 10}, RevokedVersions: []string{"1.9.0", "1.10.0"},
	}
}

func updateKeyListFixture() UpdateKeyListPayload {
	notBefore, expires := time.Unix(fixtureNotBefore, 0).UTC(), time.Unix(fixtureExpires, 0).UTC()
	return UpdateKeyListPayload{
		Serial: 1, KeyID: "root-2026-09", NotBefore: notBefore, Expires: expires,
		Keys: []UpdateKey{
			{KeyID: "upd-2026-10", PublicKey: fixturePublicKey, NotBefore: notBefore, Expires: expires},
			{KeyID: "upd-2026-09", PublicKey: fixturePublicKey, NotBefore: notBefore, Expires: expires},
		},
	}
}

func rulesPackFixture() RulesPackPayload {
	return RulesPackPayload{
		Channel: "stable", SchemaVersion: 1, MinBinaryVersion: "0.3.0", Serial: 2,
		KeyID: "rules-2026-09", NotBefore: EpochSeconds(fixtureNotBefore), Expires: EpochSeconds(fixtureExpires),
		Detectors: map[string]bool{"email": true, "prefix": true}, DisabledCategories: []string{"internal_only"},
		Allowlist: []string{"example.com"}, Blocklist: []string{"TOKENHUSH_BLOCK"},
		Rules: []RulesRule{
			{ID: "proj", Type: "regex", Pattern: "PROJ-[0-9]{4,}", Action: "warn", Confidence: f64(0.85)},
			{ID: "secret", Type: "keyword", Keywords: []string{"secret", "token"}, Action: "block", CaseSensitive: true, Allowlist: []string{"not-a-secret"}},
			{ID: "cmd", Type: "command", Action: "block", Command: "aws", Subcommand: "s3", Verbs: []string{"rm", "delete"}, Targets: []string{"s3://prod"}},
		},
	}
}

func rulesCommandPackFixture() RulesPackPayload {
	return RulesPackPayload{
		Channel: "stable", SchemaVersion: 1, MinBinaryVersion: "0.3.0", Serial: 5,
		KeyID: "rules-2026-09", NotBefore: EpochSeconds(fixtureNotBefore), Expires: EpochSeconds(fixtureExpires),
		Rules: []RulesRule{
			{ID: "cmd", Type: "command", Action: "block", Command: "aws", Subcommand: "s3", Verbs: []string{"rm", "delete"}, Targets: []string{"s3://prod"}},
		},
	}
}

func rulesManifestFixture() RulesManifestPayload {
	return RulesManifestPayload{
		Channel: "stable", SchemaVersion: 2, MinBinaryVersion: "0.3.0", Serial: 3,
		KeyID: "rules-2026-09", NotBefore: EpochSeconds(fixtureNotBefore), Expires: EpochSeconds(fixtureExpires),
		BundleSHA256: fixtureSHA256, Bundle: "rules/stable/3.json", RevokedSerials: []uint64{4, 1},
	}
}

func rulesRevocationsFixture() RulesRevocationsPayload {
	return RulesRevocationsPayload{
		Channel: "stable", Serial: 2, KeyID: "rules-2026-09",
		NotBefore: EpochSeconds(fixtureNotBefore), Expires: EpochSeconds(fixtureExpires),
		RevokedSerials: []uint64{9, 2, 5},
	}
}

// TestManifest is the W5.2 suite: the frozen projections, decode, verify, the
// OD-4 gate and the two mandatory failure demonstrations.
func TestManifest(t *testing.T) {
	t.Run("update manifest projection pins domain, epoch seconds and line order", func(t *testing.T) {
		p := updateManifestFixture()
		got := string(UpdateManifestSigningInput(p))
		if got != wantUpdateManifestProjection {
			t.Fatalf("projection drifted:\n got %q\nwant %q", got, wantUpdateManifestProjection)
		}
		for _, line := range []string{
			"not_before:1789344000\n",
			"expires:1820880000\n",
			"revoked_serials:9,10,11\n",
			"revoked_versions:1.10.0,1.9.0\n",
		} {
			if !strings.Contains(got, line) {
				t.Errorf("projection is missing %q", line)
			}
		}
		if slices.Equal(p.RevokedSerials, []uint64{9, 10, 11}) {
			t.Error("fixture does not exercise numeric serial sorting")
		}
		if !slices.Equal(p.RevokedSerials, []uint64{11, 9, 10}) || !slices.Equal(p.RevokedVersions, []string{"1.9.0", "1.10.0"}) {
			t.Error("projection mutated the caller's slices")
		}
		t.Logf("QA happy: update manifest projection is %d bytes with epoch-second timestamps", len(got))
	})

	t.Run("update projections render empty revoked lists as empty strings", func(t *testing.T) {
		p := updateManifestFixture()
		p.RevokedSerials, p.RevokedVersions = nil, nil
		got := string(UpdateManifestSigningInput(p))
		if got != wantUpdateManifestEmptyProjection {
			t.Fatalf("empty manifest projection drifted:\n got %q\nwant %q", got, wantUpdateManifestEmptyProjection)
		}
		if !strings.Contains(got, "revoked_serials:\n") || !strings.Contains(got, "revoked_versions:\n") {
			t.Fatalf("empty lists must render as empty values, got %q", got)
		}
		rev := UpdateRevocationsPayload{
			Channel: "stable", Serial: 1, KeyID: "upd-2026-09",
			NotBefore: time.Unix(fixtureNotBefore, 0).UTC(), Expires: time.Unix(fixtureExpires, 0).UTC(),
		}
		if got := string(UpdateRevocationsSigningInput(rev)); got != wantUpdateRevocationsEmptyProjection {
			t.Fatalf("empty revocations projection drifted:\n got %q\nwant %q", got, wantUpdateRevocationsEmptyProjection)
		}
	})

	t.Run("update revocations projection", func(t *testing.T) {
		rev := UpdateRevocationsPayload{
			Channel: "stable", Serial: 2, KeyID: "upd-2026-09",
			NotBefore: time.Unix(fixtureNotBefore, 0).UTC(), Expires: time.Unix(fixtureExpires, 0).UTC(),
			RevokedSerials: []uint64{5, 1}, RevokedVersions: []string{"0.3.9"},
		}
		if got := string(UpdateRevocationsSigningInput(rev)); got != wantUpdateRevocationsProjection {
			t.Fatalf("revocations projection drifted:\n got %q\nwant %q", got, wantUpdateRevocationsProjection)
		}
	})

	t.Run("key-list entries sort by key id ascending", func(t *testing.T) {
		got := string(UpdateKeyListSigningInput(updateKeyListFixture()))
		if got != wantUpdateKeyListProjection {
			t.Fatalf("key list projection drifted:\n got %q\nwant %q", got, wantUpdateKeyListProjection)
		}
		if strings.Index(got, "key:upd-2026-09:") > strings.Index(got, "key:upd-2026-10:") {
			t.Fatal("entries are not sorted by key id ascending")
		}
		if !strings.Contains(got, "key:upd-2026-09:"+fixturePublicKey+":1789344000:1820880000\n") {
			t.Fatal("entry does not render key:<id>:<pub>:<not_before_epoch>:<expires_epoch>")
		}
	})

	t.Run("rules pack projection hashes the frozen payload", func(t *testing.T) {
		p := rulesPackFixture()
		marshaled, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("json.Marshal(payload): %v", err)
		}
		if string(marshaled) != rulesPackPreimageJSON {
			t.Fatalf("payload shape drifted:\n got %s\nwant %s", marshaled, rulesPackPreimageJSON)
		}
		want := DomainRulesPack + "\n" + rulesPackHashHex
		if got := string(RulesPackSigningInput(p)); got != want {
			t.Fatalf("rules pack projection drifted:\n got %s\nwant %s", got, want)
		}
		if derived := DomainRulesPack + "\n" + testHexHash([]byte(rulesPackPreimageJSON)); derived != want {
			t.Fatalf("inline preimage does not hash to the inline expected hex")
		}
		empty := rulesPackFixture()
		empty.Detectors, empty.DisabledCategories, empty.Allowlist, empty.Blocklist, empty.Rules = nil, nil, nil, nil, nil
		wantEmpty := DomainRulesPack + "\n" + rulesPackEmptyHashHex
		if got := string(RulesPackSigningInput(empty)); got != wantEmpty {
			t.Fatalf("minimal rules pack projection drifted:\n got %s\nwant %s", got, wantEmpty)
		}
		for _, key := range []string{`"detectors":`, `"disabled_categories":`, `"allowlist":`, `"blocklist":`, `"rules":[`} {
			if strings.Contains(rulesPackEmptyPreimageJSON, key) {
				t.Fatalf("the minimal pack preimage must omit %s", key)
			}
		}
		if derived := DomainRulesPack + "\n" + testHexHash([]byte(rulesPackEmptyPreimageJSON)); derived != wantEmpty {
			t.Fatal("inline minimal preimage does not hash to the inline expected hex")
		}
	})

	t.Run("rules manifest projection sorts serials and omits the empty list", func(t *testing.T) {
		p := rulesManifestFixture()
		want := DomainRulesManifest + "\n" + rulesManifestHashHex
		if got := string(RulesManifestSigningInput(p)); got != want {
			t.Fatalf("rules manifest projection drifted:\n got %s\nwant %s", got, want)
		}
		if derived := DomainRulesManifest + "\n" + testHexHash([]byte(rulesManifestPreimageJSON)); derived != want {
			t.Fatal("inline manifest preimage does not hash to the inline expected hex")
		}
		empty := rulesManifestFixture()
		empty.RevokedSerials = nil
		wantEmpty := DomainRulesManifest + "\n" + rulesManifestEmptyHashHex
		if got := string(RulesManifestSigningInput(empty)); got != wantEmpty {
			t.Fatalf("empty rules manifest projection drifted:\n got %s\nwant %s", got, wantEmpty)
		}
		if strings.Contains(rulesManifestEmptyPreimageJSON, "revoked_serials") {
			t.Fatal("the empty manifest preimage must omit the revoked_serials key")
		}
		if derived := DomainRulesManifest + "\n" + testHexHash([]byte(rulesManifestEmptyPreimageJSON)); derived != wantEmpty {
			t.Fatal("inline empty-manifest preimage does not hash to the inline expected hex")
		}
	})

	t.Run("rules revocations projection renders an empty list as []", func(t *testing.T) {
		p := rulesRevocationsFixture()
		want := DomainRulesRevocations + "\n" + rulesRevocationsHashHex
		if got := string(RulesRevocationsSigningInput(p)); got != want {
			t.Fatalf("rules revocations projection drifted:\n got %s\nwant %s", got, want)
		}
		if derived := DomainRulesRevocations + "\n" + testHexHash([]byte(rulesRevocationsPreimageJSON)); derived != want {
			t.Fatal("inline revocations preimage does not hash to the inline expected hex")
		}
		empty := RulesRevocationsPayload{
			Channel: "stable", Serial: 1, KeyID: "rules-2026-09",
			NotBefore: EpochSeconds(fixtureNotBefore), Expires: EpochSeconds(fixtureExpires),
		}
		wantEmpty := DomainRulesRevocations + "\n" + rulesRevocationsEmptyHashHex
		if got := string(RulesRevocationsSigningInput(empty)); got != wantEmpty {
			t.Fatalf("empty rules revocations projection drifted:\n got %s\nwant %s", got, wantEmpty)
		}
		direct, err := json.Marshal(empty)
		if err != nil {
			t.Fatalf("json.Marshal(payload): %v", err)
		}
		if !strings.Contains(string(direct), `"revoked_serials":null`) {
			t.Fatalf("raw marshal = %s, want a nil list; the projection is what renders []", direct)
		}
		if !strings.Contains(rulesRevocationsEmptyPreimageJSON, `"revoked_serials":[]`) {
			t.Fatal("the frozen empty preimage must contain []")
		}
		if derived := DomainRulesRevocations + "\n" + testHexHash([]byte(rulesRevocationsEmptyPreimageJSON)); derived != wantEmpty {
			t.Fatal("inline empty-revocations preimage does not hash to the inline expected hex")
		}
	})

	t.Run("rules payload carries the legacy command fields", func(t *testing.T) {
		pack := rulesCommandPackFixture()
		marshaled, err := json.Marshal(pack)
		if err != nil {
			t.Fatalf("json.Marshal(payload): %v", err)
		}
		if string(marshaled) != rulesCommandPackPreimageJSON {
			t.Fatalf("command payload drifted:\n got %s\nwant %s", marshaled, rulesCommandPackPreimageJSON)
		}
		for _, field := range []string{`"command":"aws"`, `"subcommand":"s3"`, `"verbs":["rm","delete"]`, `"targets":["s3://prod"]`} {
			if !strings.Contains(string(marshaled), field) {
				t.Errorf("projection input is missing %s", field)
			}
		}
		want := DomainRulesPack + "\n" + rulesCommandPackHashHex
		if got := string(RulesPackSigningInput(pack)); got != want {
			t.Fatalf("command pack projection drifted:\n got %s\nwant %s", got, want)
		}
		if derived := DomainRulesPack + "\n" + testHexHash([]byte(rulesCommandPackPreimageJSON)); derived != want {
			t.Fatal("inline command preimage does not hash to the inline expected hex")
		}
	})

	t.Run("rules projections strip the signature", func(t *testing.T) {
		signedManifest := rulesManifestFixture()
		signedManifest.Signature = "c2lnbmF0dXJl"
		if got := string(RulesManifestSigningInput(signedManifest)); got != DomainRulesManifest+"\n"+rulesManifestHashHex {
			t.Fatalf("signature leaked into the manifest projection: %s", got)
		}
		signedPack := rulesPackFixture()
		signedPack.Signature = "c2lnbmF0dXJl"
		if got := string(RulesPackSigningInput(signedPack)); got != DomainRulesPack+"\n"+rulesPackHashHex {
			t.Fatalf("signature leaked into the pack projection: %s", got)
		}
		signedRevocations := rulesRevocationsFixture()
		signedRevocations.Signature = "c2lnbmF0dXJl"
		if got := string(RulesRevocationsSigningInput(signedRevocations)); got != DomainRulesRevocations+"\n"+rulesRevocationsHashHex {
			t.Fatalf("signature leaked into the revocations projection: %s", got)
		}
		// A decoded document keeps its signature for verification while its
		// projection stays byte-identical to the unsigned payload.
		decoded, err := DecodeRulesManifest([]byte(rulesManifestSignedDocJSON))
		if err != nil {
			t.Fatalf("DecodeRulesManifest: %v", err)
		}
		if decoded.Signature != "c2ln" {
			t.Fatalf("decoded signature = %q, want c2ln", decoded.Signature)
		}
		if got := string(RulesManifestSigningInput(decoded)); got != DomainRulesManifest+"\n"+rulesManifestHashHex {
			t.Fatalf("decoded manifest projection drifted: %s", got)
		}
	})

	t.Run("decode is strict and typed", func(t *testing.T) {
		m, err := DecodeRulesManifest([]byte(rulesManifestDocJSON))
		if err != nil {
			t.Fatalf("DecodeRulesManifest: %v", err)
		}
		if m.SchemaVersion != 2 || m.Serial != 3 || m.KeyID != "rules-2026-09" {
			t.Fatalf("decoded envelope = %+v", m)
		}
		if m.NotBefore != EpochSeconds(fixtureNotBefore) || m.Expires != EpochSeconds(fixtureExpires) {
			t.Fatalf("decoded window = %v/%v", m.NotBefore.Time(), m.Expires.Time())
		}
		if !slices.Equal(m.RevokedSerials, []uint64{4, 1}) {
			t.Fatalf("decoded revoked serials = %v, want the raw order [4 1]", m.RevokedSerials)
		}
		if got := string(RulesManifestSigningInput(m)); got != DomainRulesManifest+"\n"+rulesManifestHashHex {
			t.Fatalf("decoded document projects differently:\n got %s", got)
		}
		cases := []struct {
			name string
			data string
			want error
		}{
			{"unknown field", strings.Replace(rulesManifestDocJSON, `"channel":"stable"`, `"channel":"stable","unexpected":1`, 1), ErrMalformedDoc},
			{"trailing data", rulesManifestDocJSON + `{}`, ErrMalformedDoc},
			{"bad timestamp", strings.Replace(rulesManifestDocJSON, `"not_before":"2026-09-14T00:00:00Z"`, `"not_before":"not-a-time"`, 1), ErrMalformedDoc},
			{"null timestamp", strings.Replace(rulesManifestDocJSON, `"not_before":"2026-09-14T00:00:00Z"`, `"not_before":null`, 1), ErrMalformedDoc},
		}
		for _, tc := range cases {
			if _, err := DecodeRulesManifest([]byte(tc.data)); !errors.Is(err, tc.want) {
				t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
			}
		}
		if _, err := DecodeRulesManifest(make([]byte, int(MaxRulesDocBytes)+1)); !errors.Is(err, ErrDocTooLarge) {
			t.Errorf("oversized document: err = %v, want ErrDocTooLarge", err)
		}
	})

	t.Run("freshness window", func(t *testing.T) {
		public, private := substrateKeyPair(t)
		verifier := rulesManifestVerifier{public: public}
		now := time.Unix(1790000000, 0).UTC()

		fresh := rulesManifestFixture()
		fresh.RevokedSerials = nil
		fresh.NotBefore, fresh.Expires = EpochSeconds(now.Unix()-3600), EpochSeconds(now.Unix()+3600)
		signRulesManifest(t, &fresh, private)
		if err := VerifyRulesManifest(fresh, verifier, now); err != nil {
			t.Fatalf("fresh manifest: %v", err)
		}

		early := fresh
		early.NotBefore, early.Expires = EpochSeconds(now.Unix()+3600), EpochSeconds(now.Unix()+7200)
		signRulesManifest(t, &early, private)
		if err := VerifyRulesManifest(early, verifier, now); !errors.Is(err, ErrNotYetValid) {
			t.Fatalf("not-yet-valid manifest: err = %v, want ErrNotYetValid", err)
		}

		late := fresh
		late.NotBefore, late.Expires = EpochSeconds(now.Unix()-7200), EpochSeconds(now.Unix()-3600)
		signRulesManifest(t, &late, private)
		if err := VerifyRulesManifest(late, verifier, now); !errors.Is(err, ErrExpired) {
			t.Fatalf("expired manifest: err = %v, want ErrExpired", err)
		}
		t.Logf("QA failure: windows outside [not_before, expires] -> %v / %v", ErrNotYetValid, ErrExpired)

		signature, err := base64.RawURLEncoding.DecodeString(fresh.Signature)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		signature[0] ^= 0x01
		tampered := fresh
		tampered.Signature = base64.RawURLEncoding.EncodeToString(signature)
		if err := VerifyRulesManifest(tampered, verifier, now); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("tampered signature: err = %v, want ErrBadSignature", err)
		}
		other, _ := substrateKeyPair(t)
		if err := VerifyRulesManifest(fresh, rulesManifestVerifier{public: other}, now); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("wrong key: err = %v, want ErrBadSignature", err)
		}
	})

	t.Run("schema version gate", func(t *testing.T) {
		cases := []struct {
			version int
			open    bool
			ok      bool
		}{
			{1, false, true}, {2, true, true},
			{0, false, false}, {-1, false, false}, {3, false, false},
		}
		for _, tc := range cases {
			open, err := SchemaVersionGate(tc.version)
			switch {
			case tc.ok && (err != nil || open != tc.open):
				t.Errorf("SchemaVersionGate(%d) = %v, %v; want %v, nil", tc.version, open, err, tc.open)
			case !tc.ok && !errors.Is(err, ErrSchemaVersion):
				t.Errorf("SchemaVersionGate(%d) = %v, %v; want ErrSchemaVersion", tc.version, open, err)
			}
		}

		public, private := substrateKeyPair(t)
		verifier := rulesManifestVerifier{public: public}
		now := time.Unix(1790000000, 0).UTC()
		for _, version := range []int{1, 2} {
			p := rulesManifestFixture()
			p.SchemaVersion = version
			signRulesManifest(t, &p, private)
			if err := VerifyRulesManifest(p, verifier, now); err != nil {
				t.Fatalf("schema_version %d must verify: %v", version, err)
			}
			open, err := SchemaVersionGate(p.SchemaVersion)
			if err != nil || open != (version >= 2) {
				t.Fatalf("schema_version %d: gate = %v, %v", version, open, err)
			}
		}
		for _, version := range []int{0, 3} {
			p := rulesManifestFixture()
			p.SchemaVersion = version
			signRulesManifest(t, &p, private)
			if err := VerifyRulesManifest(p, verifier, now); !errors.Is(err, ErrSchemaVersion) {
				t.Fatalf("schema_version %d: err = %v, want ErrSchemaVersion", version, err)
			}
		}
		t.Logf("QA happy: schema_version 1 and 2 verify, the gate opens only on >= 2")
	})

	t.Run("QA failure: un-sorting revoked_versions changes the projection", func(t *testing.T) {
		p := updateManifestFixture()
		got := UpdateManifestSigningInput(p)
		want := []byte(wantUpdateManifestProjection)
		if !bytes.Equal(got, want) {
			t.Fatalf("projection drifted:\n got %q\nwant %q", got, want)
		}
		unsorted := strings.Join(p.RevokedVersions, ",")
		if unsorted != "1.9.0,1.10.0" {
			t.Fatalf("fixture does not exercise string ordering: %q", unsorted)
		}
		unsortedProjection := bytes.Replace(want, []byte("revoked_versions:1.10.0,1.9.0\n"), []byte("revoked_versions:"+unsorted+"\n"), 1)
		if bytes.Equal(unsortedProjection, want) {
			t.Fatal("un-sorting the input must change the projection bytes")
		}
		if bytes.Equal(got, unsortedProjection) {
			t.Fatal("the projection emitted the unsorted order")
		}
		t.Logf("QA failure: un-sorted revoked_versions would project %q, the frozen bytes are the sorted order", "revoked_versions:"+unsorted)
	})

	t.Run("QA failure: applying the scope default changes the projection", func(t *testing.T) {
		pack := rulesPackFixture()
		want := DomainRulesPack + "\n" + rulesPackHashHex
		if got := string(RulesPackSigningInput(pack)); got != want {
			t.Fatalf("projection drifted:\n got %s\nwant %s", got, want)
		}
		doc, err := filter.DecodeDocument([]byte(filterFixtureDocJSON))
		if err != nil {
			t.Fatalf("filter.DecodeDocument: %v", err)
		}
		if doc.Rules[0].Scope != filter.ScopeRequest {
			t.Fatalf("scope default = %q, want %q", doc.Rules[0].Scope, filter.ScopeRequest)
		}
		defaultedRule, err := json.Marshal(doc.Rules[0])
		if err != nil {
			t.Fatalf("json.Marshal(defaulted rule): %v", err)
		}
		if !strings.Contains(string(defaultedRule), `"scope":"request"`) {
			t.Fatalf("defaulted rule = %s, want an emitted scope", defaultedRule)
		}
		defaultedPreimage := strings.Replace(rulesPackPreimageJSON, rulesProjRuleJSON, string(defaultedRule), 1)
		if !strings.Contains(defaultedPreimage, `"scope":"request"`) {
			t.Fatal("test fixture did not replace the raw rule")
		}
		if testHexHash([]byte(defaultedPreimage)) == rulesPackHashHex {
			t.Fatal("applying the scope default did not change the projection")
		}
		t.Logf("QA failure: a defaulted projection hashes %s, the frozen preimage hashes %s",
			testHexHash([]byte(defaultedPreimage)), rulesPackHashHex)
	})
}
