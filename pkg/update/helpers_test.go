package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fixedNow is the pinned clock for every verifier test. Freshness, rotation and
// recovery are all defined relative to it so the suite is deterministic on any
// host and any wall-clock date.
var fixedNow = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

// validFrom / validUntil bracket fixedNow for freshly signed documents.
func validFrom() time.Time  { return fixedNow.Add(-time.Hour) }
func validUntil() time.Time { return fixedNow.Add(time.Hour) }

// testKey is a deterministic Ed25519 key pair. Seeds make the fixtures
// reproducible: no randomness, no committed private key.
type testKey struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestKey(id string, seed byte) testKey {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return testKey{id: id, pub: priv.Public().(ed25519.PublicKey), priv: priv}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signBytes(t *testing.T, priv ed25519.PrivateKey, input []byte) string {
	t.Helper()
	return b64(ed25519.Sign(priv, input))
}

// keyRef is the Key the verifier accepts as a trust root.
func (k testKey) keyRef() Key { return Key{ID: k.id, Public: k.pub} }

// updateKey is k described as a key-list entry valid at fixedNow.
func (k testKey) updateKey() UpdateKey {
	return UpdateKey{KeyID: k.id, PublicKey: b64(k.pub), NotBefore: validFrom(), Expires: validUntil()}
}

// signManifest stamps k as signer. The key_id is covered by the signature, so
// it must be set before signing.
func (k testKey) signManifest(t *testing.T, m Manifest) Manifest {
	t.Helper()
	m.KeyID = k.id
	m.Signature = signBytes(t, k.priv, ManifestSigningInput(m))
	return m
}

func (k testKey) signRevocations(t *testing.T, r RevocationList) RevocationList {
	t.Helper()
	r.KeyID = k.id
	r.Signature = signBytes(t, k.priv, RevocationSigningInput(r))
	return r
}

func (k testKey) signKeyList(t *testing.T, kl KeyList) KeyList {
	t.Helper()
	kl.KeyID = k.id
	kl.Signature = signBytes(t, k.priv, KeyListSigningInput(kl))
	return kl
}

func marshalDoc(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return raw
}

// baseManifest is a fresh, well-formed manifest fixture that every failure test
// perturbs one field at a time from.
func baseManifest() Manifest {
	return Manifest{
		Version:   "0.4.0",
		OS:        "linux",
		Arch:      "amd64",
		URL:       "https://dl.tokenhush.com/v0.4.0/tokenhush-linux-amd64",
		SHA256:    strings.Repeat("ab", 32),
		Channel:   "stable",
		Serial:    10,
		NotBefore: validFrom(),
		Expires:   validUntil(),
	}
}

// newVerifier builds a verifier trusting roots, pinned to fixedNow, with a
// fresh in-memory high-water store.
func newVerifier(t *testing.T, roots ...testKey) *Verifier {
	t.Helper()
	refs := make([]Key, 0, len(roots))
	for _, r := range roots {
		refs = append(refs, r.keyRef())
	}
	return &Verifier{
		Roots:     refs,
		Now:       func() time.Time { return fixedNow },
		HighWater: NewMemHighWater(),
	}
}

// applyKeyList signs kl with root and installs it through the public API.
func applyKeyList(t *testing.T, v *Verifier, root testKey, kl KeyList) {
	t.Helper()
	if err := v.ApplyKeyList(marshalDoc(t, root.signKeyList(t, kl))); err != nil {
		t.Fatalf("ApplyKeyList: %v", err)
	}
}

// mustVerifyManifest verifies m and fails the test on any error.
func mustVerifyManifest(t *testing.T, v *Verifier, m Manifest) Manifest {
	t.Helper()
	got, err := v.VerifyManifest(marshalDoc(t, m))
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	return got
}
