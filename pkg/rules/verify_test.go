package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testVerifier(t *testing.T) (*Verifier, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return &Verifier{
		Keys:                 []Key{{ID: "rules-2026a", Public: pub}},
		CurrentBinaryVersion: "0.4.0",
		Now:                  func() time.Time { return time.Unix(1_750_000_000, 0) },
	}, priv
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func signInput(priv ed25519.PrivateKey, input []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, input))
}

func TestVerifyPackHappy(t *testing.T) {
	v, priv := testVerifier(t)
	p := compliantPack()
	p.Signature = signInput(priv, PackSigningInput(p))
	if _, err := v.VerifyPack(mustJSON(t, p)); err != nil {
		t.Fatalf("VerifyPack() error = %v", err)
	}
}

func TestVerifyPackRejectsTamperedContent(t *testing.T) {
	v, priv := testVerifier(t)
	p := compliantPack()
	p.Signature = signInput(priv, PackSigningInput(p))
	p.Rules = append(p.Rules, Rule{ID: "sneak", Type: RuleKeyword, Keywords: []string{"z"}, Action: "block"})
	if _, err := v.VerifyPack(mustJSON(t, p)); !errors.Is(err, ErrPackBadSignature) {
		t.Fatalf("error = %v, want ErrPackBadSignature", err)
	}
}

// TestVerifyPackRejectsWeakeningEvenWhenSigned: a genuinely signed but weakening
// pack is still refused by the floor.
func TestVerifyPackRejectsWeakeningEvenWhenSigned(t *testing.T) {
	v, priv := testVerifier(t)
	p := compliantPack()
	p.Detectors = map[string]bool{"prefix": false}
	p.Signature = signInput(priv, PackSigningInput(p))
	if _, err := v.VerifyPack(mustJSON(t, p)); !errors.Is(err, ErrFloorDisablesDetector) {
		t.Fatalf("error = %v, want ErrFloorDisablesDetector", err)
	}
}

func TestVerifyPackFreshness(t *testing.T) {
	v, priv := testVerifier(t)
	p := compliantPack()
	p.NotBefore = time.Unix(1_760_000_000, 0)
	p.Expires = time.Unix(1_770_000_000, 0)
	p.Signature = signInput(priv, PackSigningInput(p))
	if _, err := v.VerifyPack(mustJSON(t, p)); !errors.Is(err, ErrPackNotYetValid) {
		t.Fatalf("not-yet-valid error = %v, want ErrPackNotYetValid", err)
	}

	p = compliantPack()
	p.NotBefore = time.Unix(1_700_000_000, 0)
	p.Expires = time.Unix(1_740_000_000, 0)
	p.Signature = signInput(priv, PackSigningInput(p))
	if _, err := v.VerifyPack(mustJSON(t, p)); !errors.Is(err, ErrPackExpired) {
		t.Fatalf("expired error = %v, want ErrPackExpired", err)
	}
}

func TestVerifyPackIncompatibleBinary(t *testing.T) {
	v, priv := testVerifier(t)
	p := compliantPack()
	p.MinBinaryVersion = "0.5.0"
	p.Signature = signInput(priv, PackSigningInput(p))
	if _, err := v.VerifyPack(mustJSON(t, p)); !errors.Is(err, ErrIncompatibleBinary) {
		t.Fatalf("error = %v, want ErrIncompatibleBinary", err)
	}
}

func TestVerifyPackUnknownKey(t *testing.T) {
	v, _ := testVerifier(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := compliantPack()
	p.KeyID = "rules-unknown"
	p.Signature = signInput(other, PackSigningInput(p))
	if _, err := v.VerifyPack(mustJSON(t, p)); !errors.Is(err, ErrPackUnknownKey) {
		t.Fatalf("error = %v, want ErrPackUnknownKey", err)
	}
}

func TestVerifyManifestHappy(t *testing.T) {
	v, priv := testVerifier(t)
	m := Manifest{
		Channel: "stable", SchemaVersion: SchemaVersion, MinBinaryVersion: "0.3.0",
		Serial: 7, KeyID: "rules-2026a", NotBefore: time.Unix(1_700_000_000, 0),
		Expires: time.Unix(1_800_000_000, 0), BundleSHA256: "a", Bundle: "rules/stable/2.json",
	}
	m.Signature = signInput(priv, ManifestSigningInput(m))
	if _, err := v.VerifyManifest(mustJSON(t, m)); err != nil {
		t.Fatalf("VerifyManifest() error = %v", err)
	}

	m.Bundle = "rules/stable/999.json"
	if _, err := v.VerifyManifest(mustJSON(t, m)); !errors.Is(err, ErrPackBadSignature) {
		t.Fatalf("tampered manifest error = %v, want ErrPackBadSignature", err)
	}
}
