// Online verification: signature, freshness, anti-rollback and downgrade for
// manifests and the independent revocation document, plus the user-visible
// status that must never hide an expired update.
package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// EnvAllowDowngrade is the environment variable that must be set, alongside
// the dev-only --allow-downgrade flag, before a downgrade is permitted. The
// flag alone is never enough: the variable forces a deliberate, auditable
// opt-in.
const EnvAllowDowngrade = "TOKENHUSH_ALLOW_DOWNGRADE"

// ExpiredMarker is the stable status marker rendered when update metadata is
// expired and cannot be refreshed.
const ExpiredMarker = "update expired"

// ExpiredWarning is the mandatory user-visible warning that accompanies
// ExpiredMarker. Expiry is never silent.
const ExpiredWarning = "tokenhush: update expired - update metadata could not be refreshed from the official channel; download the latest release manually"

// DowngradeEvent is the audit record written when the dev override admits a
// downgrade.
type DowngradeEvent struct {
	From string
	To   string
	At   time.Time
}

// AuditFunc receives downgrade audit events. Production wires the core audit
// seam; tests capture events in memory.
type AuditFunc func(DowngradeEvent)

// Verifier verifies signed update documents against a trust root, a clock and
// a persisted anti-rollback store. The zero value verifies nothing useful; use
// DefaultVerifier or populate Roots and install a key list via ApplyKeyList.
type Verifier struct {
	// Roots is the embedded root public key set. Required to accept key lists.
	Roots []Key
	// CurrentVersion is the running release version, used for downgrade
	// refusal. Empty disables the downgrade check (for pre-install probing).
	CurrentVersion string
	// Now supplies the current time. Nil means time.Now.
	Now func() time.Time
	// HighWater persists accepted serials. Nil falls back to an in-process
	// store, which protects a single run but not a restart; production passes
	// a FileHighWater.
	HighWater HighWaterStore
	// AllowDowngrade admits a lower version when the environment opt-in is
	// present. Callers set it from AllowDowngradeEnabled.
	AllowDowngrade bool
	// Audit receives downgrade events. Nil drops them.
	Audit AuditFunc

	updateKeys []acceptedKey
	hw         HighWaterStore
}

// DefaultVerifier returns a verifier trusting the embedded root set with the
// supplied anti-rollback store.
func DefaultVerifier(hw HighWaterStore) *Verifier {
	return &Verifier{Roots: DefaultRoots(), HighWater: hw}
}

// AllowDowngradeEnabled reports whether the dev-only downgrade opt-in is set.
func AllowDowngradeEnabled(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(getenv(EnvAllowDowngrade))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// VerifyManifest verifies raw and returns the decoded manifest. It rejects bad
// signatures, non-fresh or replayed documents, and downgrades, and only then
// advances the manifest high-water mark.
func (v *Verifier) VerifyManifest(raw []byte) (Manifest, error) {
	if len(raw) > MaxDocumentSize {
		return Manifest{}, ErrTooLarge
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, ErrMalformed
	}
	if err := m.validate(); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	now := v.now()
	pub, err := v.updateKey(m.KeyID, now)
	if err != nil {
		return Manifest{}, err
	}
	if err := verifySignature(pub, ManifestSigningInput(m), m.Signature); err != nil {
		return Manifest{}, err
	}
	switch m.Freshness(now) {
	case NotYetValid:
		return Manifest{}, ErrNotYetValid
	case Expired:
		return Manifest{}, ErrExpired
	}
	if err := v.checkDowngrade(m, now); err != nil {
		return Manifest{}, err
	}
	if err := v.admit(KindManifest, m.Serial); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// VerifyRevocations verifies the independent, self-contained revocation
// document. It is fetched on its own and carries its own freshness and serial,
// so revoking a version never depends on that version's own manifest.
func (v *Verifier) VerifyRevocations(raw []byte) (RevocationList, error) {
	if len(raw) > MaxDocumentSize {
		return RevocationList{}, ErrTooLarge
	}
	var r RevocationList
	if err := json.Unmarshal(raw, &r); err != nil {
		return RevocationList{}, ErrMalformed
	}
	if err := r.validate(); err != nil {
		return RevocationList{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	now := v.now()
	pub, err := v.updateKey(r.KeyID, now)
	if err != nil {
		return RevocationList{}, err
	}
	if err := verifySignature(pub, RevocationSigningInput(r), r.Signature); err != nil {
		return RevocationList{}, err
	}
	switch r.Freshness(now) {
	case NotYetValid:
		return RevocationList{}, ErrNotYetValid
	case Expired:
		return RevocationList{}, ErrExpired
	}
	if err := v.admit(KindRevocations, r.Serial); err != nil {
		return RevocationList{}, err
	}
	return r, nil
}

// Status is the user-visible update state. Expired is set, with a matching
// warning, when the last known manifest is past its expiry and no refresh has
// replaced it.
type Status struct {
	CurrentVersion string
	LatestVersion  string
	UpToDate       bool
	Expired        bool
	Warnings       []string
}

// Status derives the user-visible state from the last known manifest. An
// expired manifest is always surfaced, never silently dropped.
func (v *Verifier) Status(lastKnown *Manifest) Status {
	st := Status{CurrentVersion: v.CurrentVersion}
	if lastKnown == nil {
		return st
	}
	st.LatestVersion = lastKnown.Version
	now := v.now()
	if lastKnown.Freshness(now) == Expired {
		st.Expired = true
		st.Warnings = append(st.Warnings, ExpiredWarning)
		return st
	}
	if cmp, err := CompareVersions(v.CurrentVersion, lastKnown.Version); err == nil {
		st.UpToDate = cmp >= 0
	}
	return st
}

// checkDowngrade refuses a manifest below the running version unless the
// dev-only override is active, in which case it records an audit event.
func (v *Verifier) checkDowngrade(m Manifest, now time.Time) error {
	if v.CurrentVersion == "" {
		return nil
	}
	cmp, err := CompareVersions(m.Version, v.CurrentVersion)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if cmp >= 0 {
		return nil
	}
	if !v.AllowDowngrade {
		return ErrDowngrade
	}
	if v.Audit != nil {
		v.Audit(DowngradeEvent{From: v.CurrentVersion, To: m.Version, At: now})
	}
	return nil
}

// admit checks serial against the persisted high-water mark for kind and, on
// success, advances it. Rejected documents never advance the mark.
func (v *Verifier) admit(kind string, serial uint64) error {
	hw := v.store()
	if highest, ok, err := hw.Highest(kind); err != nil {
		return err
	} else if ok && serial <= highest {
		return ErrReplayed
	}
	return hw.Advance(kind, serial)
}

// updateKey resolves an update key id to its public key and requires the key
// to be inside its advertised validity window.
func (v *Verifier) updateKey(id string, now time.Time) (ed25519.PublicKey, error) {
	for _, k := range v.updateKeys {
		if k.id != id {
			continue
		}
		if freshness(k.notBefore, k.expires, now) != Fresh {
			return nil, ErrKeyNotValid
		}
		return k.public, nil
	}
	return nil, ErrUnknownKey
}

// now returns the verifier clock, defaulting to time.Now.
func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// store returns the resolved high-water store, lazily creating an in-process
// one when none was supplied.
func (v *Verifier) store() HighWaterStore {
	if v.HighWater != nil {
		return v.HighWater
	}
	if v.hw == nil {
		v.hw = NewMemHighWater()
	}
	return v.hw
}

// verifySignature checks a base64 raw-URL Ed25519 signature.
func verifySignature(pub ed25519.PublicKey, input []byte, sigB64 string) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, input, sig) {
		return ErrBadSignature
	}
	return nil
}
