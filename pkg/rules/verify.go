package rules

// Signature verification for the signed remote pack and manifest. The verifier
// checks the Ed25519 signature against a trusted key set, enforces freshness and
// the min_binary_version compatibility floor, and then applies the non-weakening
// floor to the pack content. The Worker only distributes bytes; every trust
// decision happens here on the client.

import (
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// Key pairs a rotation id with the Ed25519 public key that verifies documents
// carrying that id. Only public halves ship.
type Key struct {
	ID     string
	Public ed25519.PublicKey
}

// Verifier verifies signed rule packs and manifests. The zero value trusts no
// key; populate Keys and CurrentBinaryVersion.
type Verifier struct {
	// Keys is the trusted rule-signing key set. Independent of the license and
	// update keys (ADR-0020 §1).
	Keys []Key
	// CurrentBinaryVersion is the running release version, compared against
	// min_binary_version. Empty disables the compatibility check.
	CurrentBinaryVersion string
	// Now supplies the current time. Nil means time.Now.
	Now func() time.Time
	// Baseline is the non-weakening floor. The zero value falls back to
	// DefaultBaseline.
	Baseline Baseline
}

// VerifyManifest verifies raw and returns the decoded manifest: signature,
// freshness and min_binary_version.
func (v *Verifier) VerifyManifest(raw []byte) (Manifest, error) {
	if len(raw) > MaxPackSize {
		return Manifest{}, ErrPackTooLarge
	}
	var m Manifest
	if err := decodeStrict(raw, &m); err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	key, err := v.key(m.KeyID)
	if err != nil {
		return Manifest{}, err
	}
	if !verifySignature(key, ManifestSigningInput(m), m.Signature) {
		return Manifest{}, ErrPackBadSignature
	}
	if err := v.checkFreshness(m.NotBefore, m.Expires); err != nil {
		return Manifest{}, err
	}
	if err := v.checkCompatible(m.MinBinaryVersion); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// VerifyPack verifies raw and returns the decoded pack: signature, freshness,
// min_binary_version and the non-weakening floor. A pack that tries to weaken
// the built-in baseline is rejected before its content is ever compiled.
func (v *Verifier) VerifyPack(raw []byte) (Pack, error) {
	if len(raw) > MaxPackSize {
		return Pack{}, ErrPackTooLarge
	}
	var p Pack
	if err := decodeStrict(raw, &p); err != nil {
		return Pack{}, err
	}
	if err := validatePack(p); err != nil {
		return Pack{}, err
	}
	key, err := v.key(p.KeyID)
	if err != nil {
		return Pack{}, err
	}
	if !verifySignature(key, PackSigningInput(p), p.Signature) {
		return Pack{}, ErrPackBadSignature
	}
	if err := v.checkFreshness(p.NotBefore, p.Expires); err != nil {
		return Pack{}, err
	}
	if err := v.checkCompatible(p.MinBinaryVersion); err != nil {
		return Pack{}, err
	}
	baseline := v.Baseline
	if len(baseline.Detectors) == 0 && len(baseline.Categories) == 0 {
		baseline = DefaultBaseline()
	}
	if err := baseline.Check(&p); err != nil {
		return Pack{}, err
	}
	return p, nil
}

// checkFreshness enforces the validity window at the verifier clock.
func (v *Verifier) checkFreshness(notBefore, expires time.Time) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	switch {
	case now.Before(notBefore):
		return ErrPackNotYetValid
	case now.After(expires):
		return ErrPackExpired
	default:
		return nil
	}
}

// checkCompatible refuses a pack that requires a newer binary than this build.
func (v *Verifier) checkCompatible(minBinary string) error {
	if v.CurrentBinaryVersion == "" || minBinary == "" {
		return nil
	}
	cmp, err := compareVersions(v.CurrentBinaryVersion, minBinary)
	if err != nil {
		return ErrPackMalformed
	}
	if cmp < 0 {
		return ErrIncompatibleBinary
	}
	return nil
}

// compareVersions compares two numeric release versions ("major.minor.patch",
// 1-3 components), padding missing components with zero. It is a local copy of
// pkg/update's rule so this package does not depend on the update engine.
func compareVersions(a, b string) (int, error) {
	av, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	bv, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range av {
		switch {
		case av[i] < bv[i]:
			return -1, nil
		case av[i] > bv[i]:
			return 1, nil
		}
	}
	return 0, nil
}

// parseVersion parses 1-3 dot-separated numeric components.
func parseVersion(s string) ([3]uint64, error) {
	var out [3]uint64
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, ErrPackMalformed
	}
	for i, p := range parts {
		if p == "" {
			return out, ErrPackMalformed
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return out, ErrPackMalformed
		}
		out[i] = n
	}
	return out, nil
}

// key resolves a key id against the trusted set.
func (v *Verifier) key(id string) (ed25519.PublicKey, error) {
	for _, k := range v.Keys {
		if k.ID == id && len(k.Public) == ed25519.PublicKeySize {
			return k.Public, nil
		}
	}
	return nil, ErrPackUnknownKey
}

// verifySignature checks a base64 raw-URL Ed25519 signature.
func verifySignature(pub ed25519.PublicKey, input []byte, sigB64 string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, input, sig)
}

// checkField bounds a free-text envelope field and rejects control characters
// that could forge a signing-input line.
func checkField(s string) bool {
	if s == "" || len(s) > maxPackFieldLen {
		return false
	}
	return !strings.ContainsAny(s, "\r\n\x00")
}

// validateManifest checks every manifest field not already covered by decode.
func validateManifest(m Manifest) error {
	for _, f := range []string{m.Channel, m.KeyID, m.MinBinaryVersion, m.Bundle, m.BundleSHA256, m.Signature} {
		if !checkField(f) {
			return ErrPackMalformed
		}
	}
	if m.SchemaVersion != SchemaVersion {
		return ErrSchemaVersion
	}
	if m.Serial == 0 {
		return ErrPackMalformed
	}
	if err := checkRevokedSerials(m.RevokedSerials); err != nil {
		return err
	}
	if m.Revokes(m.Serial) {
		return ErrPackMalformed
	}
	return checkWindow(m.NotBefore, m.Expires)
}

// checkRevokedSerials bounds the signed revocation list. A self-revoking
// manifest is rejected in validateManifest because a valid manifest may not
// revoke itself.
func checkRevokedSerials(serials []uint64) error {
	if len(serials) > MaxRevokedSerials {
		return ErrPackMalformed
	}
	for _, s := range serials {
		if s == 0 {
			return ErrPackMalformed
		}
	}
	return nil
}

// validatePack checks every pack field not already covered by decode.
func validatePack(p Pack) error {
	for _, f := range []string{p.Channel, p.KeyID, p.MinBinaryVersion, p.Signature} {
		if !checkField(f) {
			return ErrPackMalformed
		}
	}
	if p.SchemaVersion != SchemaVersion {
		return ErrSchemaVersion
	}
	if p.Serial == 0 {
		return ErrPackMalformed
	}
	return checkWindow(p.NotBefore, p.Expires)
}

// checkWindow requires both bounds and a strictly positive window.
func checkWindow(notBefore, expires time.Time) error {
	if notBefore.IsZero() || expires.IsZero() {
		return ErrPackMalformed
	}
	if !expires.After(notBefore) {
		return ErrPackMalformed
	}
	return nil
}
