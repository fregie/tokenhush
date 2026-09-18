package supply

// keylist_test.go is the W5.4 suite: the root-signed online key list and the
// two revocation documents. The embedded key set is asserted inline, and every
// fixture below is generated in-process: no network, no vendored vectors (the
// golden corpus lands in W5.7 and is never referenced here).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// keyPair returns a fresh Ed25519 pair. Signing in tests stands in for the
// issuer: the verifier seam is the only trust input.
func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey = %v", err)
	}
	return pub, priv
}

// proofKey returns a fresh public key for entries whose private half is unused.
func proofKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _ := keyPair(t)
	return pub
}

// staticVerifierFor builds the substrate verifier over injected test roots.
func staticVerifierFor(pubs map[string]ed25519.PublicKey) *StaticVerifier {
	keys := make(map[string]string, len(pubs))
	for id, pub := range pubs {
		keys[id] = base64.RawURLEncoding.EncodeToString(pub)
	}
	return &StaticVerifier{keys: keys}
}

// updateKeyEntry builds one online update key entry with the fixture window.
func updateKeyEntry(id string, pub ed25519.PublicKey) UpdateKey {
	return UpdateKey{
		KeyID:     id,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		NotBefore: time.Unix(fixtureNotBefore, 0).UTC(),
		Expires:   time.Unix(fixtureExpires, 0).UTC(),
	}
}

// keyListPayload builds an unsigned key list claiming the update root.
func keyListPayload(serial uint64, entries ...UpdateKey) UpdateKeyListPayload {
	return UpdateKeyListPayload{
		Serial:    serial,
		KeyID:     KeyRootUpdate,
		NotBefore: time.Unix(fixtureNotBefore, 0).UTC(),
		Expires:   time.Unix(fixtureExpires, 0).UTC(),
		Keys:      entries,
	}
}

// signKeyList signs the frozen key-list projection.
func signKeyList(t *testing.T, list UpdateKeyListPayload, priv ed25519.PrivateKey) UpdateKeyListPayload {
	t.Helper()
	list.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, UpdateKeyListSigningInput(list)))
	return list
}

// updateRevocationsPayload builds an unsigned update-revocations document.
func updateRevocationsPayload(serial uint64, serials []uint64, versions []string) UpdateRevocationsPayload {
	return UpdateRevocationsPayload{
		Channel:         "stable",
		Serial:          serial,
		KeyID:           "upd-2026-10",
		NotBefore:       time.Unix(fixtureNotBefore, 0).UTC(),
		Expires:         time.Unix(fixtureExpires, 0).UTC(),
		RevokedSerials:  serials,
		RevokedVersions: versions,
	}
}

// signUpdateRevocations signs the frozen update-revocations projection.
func signUpdateRevocations(t *testing.T, doc UpdateRevocationsPayload, priv ed25519.PrivateKey) UpdateRevocationsPayload {
	t.Helper()
	doc.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, UpdateRevocationsSigningInput(doc)))
	return doc
}

func TestKeyListEmbeddedIDsExactlyTheRoots(t *testing.T) {
	roots := DefaultRootKeys()
	if len(roots) != 2 {
		t.Fatalf("DefaultRootKeys() has %d keys, want exactly 2", len(roots))
	}
	got := make([]string, 0, len(roots))
	for _, root := range roots {
		if strings.HasPrefix(root.ID, "upd-") {
			t.Fatalf("embedded key %q is an online update key; upd-* must come from the root-signed key list", root.ID)
		}
		got = append(got, root.ID)
	}
	slices.Sort(got)
	want := []string{KeyRootUpdate, KeyRulesRoot}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("embedded ids = %v, want exactly %v", got, want)
	}
}

func TestKeyListRootSignedInstall(t *testing.T) {
	rootPub, rootPriv := keyPair(t)
	updPub, _ := keyPair(t)
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRootUpdate: rootPub})
	store := newKeyListStore()

	listing := signKeyList(t, keyListPayload(2, updateKeyEntry("upd-2026-10", updPub)), rootPriv)
	if err := store.install(listing, verifier); err != nil {
		t.Fatalf("Install(root-signed) = %v, want nil", err)
	}
	wantPub := base64.RawURLEncoding.EncodeToString(updPub)
	gotPub, ok := store.publicKey("upd-2026-10")
	if !ok || gotPub != wantPub {
		t.Fatalf("PublicKey(upd-2026-10) = (%q, %v), want the installed public key", gotPub, ok)
	}
	if ids := store.ids(); !slices.Equal(ids, []string{"upd-2026-10"}) {
		t.Fatalf("IDs() = %v, want [upd-2026-10]", ids)
	}
	if got := store.activeSerial(); got != 2 {
		t.Fatalf("ActiveSerial() = %d, want 2", got)
	}
}

func TestKeyListSignedByRandomKeyRejected(t *testing.T) {
	rootPub, _ := keyPair(t)
	_, randomPriv := keyPair(t)
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRootUpdate: rootPub})
	store := newKeyListStore()

	// The random signer even claims the root id: the id is not the trust
	// anchor, the embedded root public key is.
	listing := signKeyList(t, keyListPayload(1, updateKeyEntry("upd-rogue", proofKey(t))), randomPriv)
	err := store.install(listing, verifier)
	if !errors.Is(err, ErrUnauthorizedKey) {
		t.Fatalf("Install(random-key-signed) = %v, want an error wrapping ErrUnauthorizedKey", err)
	}
	t.Logf("QA failure: a key list signed by a random key -> %v", err)
	if err := verifyKeyList(listing, verifier); !errors.Is(err, ErrUnauthorizedKey) {
		t.Fatalf("verifyKeyList(random-key-signed) = %v, want ErrUnauthorizedKey", err)
	}
	if ids := store.ids(); len(ids) != 0 {
		t.Fatalf("IDs() = %v after a rejected list, want none installed", ids)
	}
}

func TestKeyListWrongKeyIDRejected(t *testing.T) {
	rootPub, rootPriv := keyPair(t)
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRootUpdate: rootPub})
	listing := signKeyList(t, keyListPayload(1, updateKeyEntry("upd-2026-10", proofKey(t))), rootPriv)
	listing.KeyID = "upd-2026-10" // a list claiming an online key is not root authority

	if err := newKeyListStore().install(listing, verifier); !errors.Is(err, ErrUnauthorizedKey) {
		t.Fatalf("Install(online-key-id) = %v, want ErrUnauthorizedKey", err)
	}
}

func TestKeyListTamperedAfterSigningRejected(t *testing.T) {
	rootPub, rootPriv := keyPair(t)
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRootUpdate: rootPub})
	listing := signKeyList(t, keyListPayload(1, updateKeyEntry("upd-2026-10", proofKey(t))), rootPriv)
	listing.Serial = 99

	err := newKeyListStore().install(listing, verifier)
	if !errors.Is(err, ErrUnauthorizedKey) || !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Install(tampered) = %v, want ErrUnauthorizedKey and ErrBadSignature", err)
	}
}

func TestKeyListRollbackRetainsActiveKeys(t *testing.T) {
	rootPub, rootPriv := keyPair(t)
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRootUpdate: rootPub})
	store := newKeyListStore()

	oldPub, _ := keyPair(t)
	if err := store.install(signKeyList(t, keyListPayload(5, updateKeyEntry("upd-a", oldPub)), rootPriv), verifier); err != nil {
		t.Fatalf("Install(serial 5) = %v", err)
	}
	newPub, _ := keyPair(t)
	err := store.install(signKeyList(t, keyListPayload(3, updateKeyEntry("upd-b", newPub)), rootPriv), verifier)
	if !errors.Is(err, ErrKeyListRollback) {
		t.Fatalf("Install(serial 3) = %v, want an error wrapping ErrKeyListRollback", err)
	}
	if ids := store.ids(); !slices.Equal(ids, []string{"upd-a"}) {
		t.Fatalf("IDs() = %v after a rejected rollback, want the active [upd-a]", ids)
	}
	if got := store.activeSerial(); got != 5 {
		t.Fatalf("ActiveSerial() = %d after a rejected rollback, want 5", got)
	}

	// A legitimate replay of the active serial is idempotent.
	if err := store.install(signKeyList(t, keyListPayload(5, updateKeyEntry("upd-a", oldPub)), rootPriv), verifier); err != nil {
		t.Fatalf("replay of the active serial = %v, want nil", err)
	}
}

func TestKeyListRotationReplacesKeysAscending(t *testing.T) {
	rootPub, rootPriv := keyPair(t)
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRootUpdate: rootPub})
	store := newKeyListStore()

	pubA, _ := keyPair(t)
	pubB, _ := keyPair(t)
	// Rotation overlap: the first list carries only A, the second carries both
	// in reverse order, the third drops A.
	if err := store.install(signKeyList(t, keyListPayload(1, updateKeyEntry("upd-a", pubA)), rootPriv), verifier); err != nil {
		t.Fatalf("Install(serial 1) = %v", err)
	}
	both := keyListPayload(2, updateKeyEntry("upd-b", pubB), updateKeyEntry("upd-a", pubA))
	if err := store.install(signKeyList(t, both, rootPriv), verifier); err != nil {
		t.Fatalf("Install(serial 2) = %v", err)
	}
	if ids := store.ids(); !slices.Equal(ids, []string{"upd-a", "upd-b"}) {
		t.Fatalf("IDs() = %v, want ascending [upd-a upd-b]", ids)
	}
	if err := store.install(signKeyList(t, keyListPayload(3, updateKeyEntry("upd-b", pubB)), rootPriv), verifier); err != nil {
		t.Fatalf("Install(serial 3) = %v", err)
	}
	if ids := store.ids(); !slices.Equal(ids, []string{"upd-b"}) {
		t.Fatalf("IDs() = %v after rotation, want [upd-b]", ids)
	}
	if _, ok := store.publicKey("upd-a"); ok {
		t.Fatalf("PublicKey(upd-a) resolved after rotation, want it dropped")
	}
}

func TestKeyListEntriesAreValidated(t *testing.T) {
	rootPub, rootPriv := keyPair(t)
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRootUpdate: rootPub})
	shortKey := base64.RawURLEncoding.EncodeToString([]byte("short"))
	validEntry := updateKeyEntry("upd-a", proofKey(t))

	cases := map[string][]UpdateKey{
		"duplicate id":            {validEntry, updateKeyEntry("upd-a", proofKey(t))},
		"empty id":                {{PublicKey: validEntry.PublicKey}},
		"names the update root":   {{KeyID: KeyRootUpdate, PublicKey: validEntry.PublicKey}},
		"names the rules root":    {{KeyID: KeyRulesRoot, PublicKey: validEntry.PublicKey}},
		"public key not base64":   {{KeyID: "upd-a", PublicKey: "not base64!"}},
		"public key wrong length": {{KeyID: "upd-a", PublicKey: shortKey}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			store := newKeyListStore()
			listing := signKeyList(t, keyListPayload(1, entries...), rootPriv)
			if err := store.install(listing, verifier); !errors.Is(err, ErrMalformedDoc) {
				t.Fatalf("Install = %v, want an error wrapping ErrMalformedDoc", err)
			}
			if ids := store.ids(); len(ids) != 0 {
				t.Fatalf("IDs() = %v after a rejected list, want none installed", ids)
			}
		})
	}
}

func TestKeyListInstalledKeyVerifiesUpdateRevocations(t *testing.T) {
	rootPub, rootPriv := keyPair(t)
	updPub, updPriv := keyPair(t)
	keys := newKeyListStore()
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRootUpdate: rootPub})
	if err := keys.install(signKeyList(t, keyListPayload(1, updateKeyEntry("upd-2026-10", updPub)), rootPriv), verifier); err != nil {
		t.Fatalf("Install = %v", err)
	}

	active := NewRevocationStore()
	doc := signUpdateRevocations(t, updateRevocationsPayload(7, []uint64{5}, []string{"0.3.9"}), updPriv)
	if err := active.ApplyUpdate(doc, keys.verifier()); err != nil {
		t.Fatalf("ApplyUpdate = %v, want nil", err)
	}
	if got := active.ActiveSerial(); got != 7 {
		t.Fatalf("ActiveSerial() = %d, want 7", got)
	}
	if err := active.Check(5, "0.4.0"); !errors.Is(err, ErrRevokedSerial) {
		t.Fatalf("Check(revoked serial) = %v, want ErrRevokedSerial", err)
	}
	if err := active.Check(6, "0.3.9"); !errors.Is(err, ErrRevokedVersion) {
		t.Fatalf("Check(revoked version) = %v, want ErrRevokedVersion", err)
	}
	if err := active.Check(6, "0.4.0"); err != nil {
		t.Fatalf("Check(fresh) = %v, want nil", err)
	}

	// A rollback is rejected and the active pack is retained: a stale
	// revocation can never un-revoke anything.
	older := signUpdateRevocations(t, updateRevocationsPayload(3, nil, nil), updPriv)
	if err := active.ApplyUpdate(older, keys.verifier()); !errors.Is(err, ErrRevocationRollback) {
		t.Fatalf("ApplyUpdate(rollback) = %v, want ErrRevocationRollback", err)
	}
	if got := active.ActiveSerial(); got != 7 {
		t.Fatalf("ActiveSerial() = %d after a rollback, want the retained 7", got)
	}
	if !active.IsSerialRevoked(5) || !active.IsVersionRevoked("0.3.9") {
		t.Fatalf("rollback dropped the active revocations")
	}

	// An unsigned document and a tampered document are both rejected, and
	// neither changes the active pack.
	if err := active.ApplyUpdate(updateRevocationsPayload(8, []uint64{6}, nil), keys.verifier()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("ApplyUpdate(unsigned) = %v, want ErrBadSignature", err)
	}
	tampered := signUpdateRevocations(t, updateRevocationsPayload(8, []uint64{6}, nil), updPriv)
	tampered.RevokedSerials = []uint64{9}
	if err := active.ApplyUpdate(tampered, keys.verifier()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("ApplyUpdate(tampered) = %v, want ErrBadSignature", err)
	}
	// A document naming a key that was never installed fails closed too.
	unknown := signUpdateRevocations(t, updateRevocationsPayload(8, []uint64{6}, nil), updPriv)
	unknown.KeyID = "upd-unknown"
	if err := active.ApplyUpdate(unknown, keys.verifier()); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("ApplyUpdate(unknown key) = %v, want ErrWrongKey", err)
	}
	if got := active.ActiveSerial(); got != 7 || !active.IsSerialRevoked(5) {
		t.Fatalf("a failed verification changed the active pack")
	}
}

func TestKeyListRulesRevocationsApply(t *testing.T) {
	rulesPub, rulesPriv := keyPair(t)
	verifier := staticVerifierFor(map[string]ed25519.PublicKey{KeyRulesRoot: rulesPub})
	store := NewRevocationStore()

	doc := RulesRevocationsPayload{
		Channel:        "stable",
		Serial:         2,
		KeyID:          KeyRulesRoot,
		NotBefore:      EpochSeconds(fixtureNotBefore),
		Expires:        EpochSeconds(fixtureExpires),
		RevokedSerials: []uint64{4},
	}
	doc.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(rulesPriv, RulesRevocationsSigningInput(doc)))
	if err := store.applyRules(doc, verifier); err != nil {
		t.Fatalf("applyRules = %v, want nil", err)
	}
	if err := store.Check(4, ""); !errors.Is(err, ErrRevokedSerial) {
		t.Fatalf("Check(revoked serial) = %v, want ErrRevokedSerial", err)
	}
	if store.IsVersionRevoked("0.4.0") {
		t.Fatalf("rules revocations must not revoke versions")
	}
	if err := store.Check(9, "0.4.0"); err != nil {
		t.Fatalf("Check(fresh) = %v, want nil", err)
	}
	older := doc
	older.Serial = 1
	older.RevokedSerials = nil
	older.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(rulesPriv, RulesRevocationsSigningInput(older)))
	if err := store.applyRules(older, verifier); !errors.Is(err, ErrRevocationRollback) {
		t.Fatalf("applyRules(rollback) = %v, want ErrRevocationRollback", err)
	}
	if !store.IsSerialRevoked(4) || store.ActiveSerial() != 2 {
		t.Fatalf("rules rollback dropped the active revocations")
	}
}

func TestKeyListDecodeIsStrict(t *testing.T) {
	valid := `{"serial":1,"key_id":"root-2026-09","not_before":"2026-09-14T00:00:00Z",` +
		`"expires":"2027-09-14T00:00:00Z","keys":[]}`
	if _, err := decodeUpdateKeyList([]byte(valid)); err != nil {
		t.Fatalf("decodeUpdateKeyList(valid) = %v, want nil", err)
	}
	unknown := strings.Replace(valid, `"serial":1`, `"serial":1,"extra":true`, 1)
	if _, err := decodeUpdateKeyList([]byte(unknown)); !errors.Is(err, ErrMalformedDoc) {
		t.Fatalf("decodeUpdateKeyList(unknown field) = %v, want ErrMalformedDoc", err)
	}
	if _, err := decodeUpdateKeyList([]byte(valid + `{}`)); !errors.Is(err, ErrMalformedDoc) {
		t.Fatalf("decodeUpdateKeyList(trailing) = %v, want ErrMalformedDoc", err)
	}
	if _, err := decodeUpdateKeyList(make([]byte, MaxUpdateDocBytes+1)); !errors.Is(err, ErrDocTooLarge) {
		t.Fatalf("decodeUpdateKeyList(oversize) = %v, want ErrDocTooLarge", err)
	}

	revocations := `{"channel":"stable","serial":7,"key_id":"upd-2026-10",` +
		`"not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z",` +
		`"revoked_serials":[5],"revoked_versions":["0.3.9"]}`
	doc, err := DecodeUpdateRevocations([]byte(revocations))
	if err != nil {
		t.Fatalf("DecodeUpdateRevocations(valid) = %v, want nil", err)
	}
	if doc.Serial != 7 || !slices.Equal(doc.RevokedSerials, []uint64{5}) || !slices.Equal(doc.RevokedVersions, []string{"0.3.9"}) {
		t.Fatalf("DecodeUpdateRevocations = %+v, want the frozen fields", doc)
	}
}
