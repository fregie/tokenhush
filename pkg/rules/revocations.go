package rules

// The independent, self-contained signed revocation document for the rule
// channel. It mirrors pkg/update's kill-switch: a rule pack must be revocable
// without the client accepting the same (or a newer) manifest, because a
// revocation carried only by a manifest is hidden by anyone able to freeze that
// manifest feed. The document carries its own monotonic serial and validity
// window, so it can never be rolled back or silently expired.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

// revocationDomain separates a revocation signature from a pack/manifest one.
const revocationDomain = "tokenhush-rules-revocations-v1"

// RevocationList is an independent signed kill-switch document for one channel.
type RevocationList struct {
	Channel        string    `json:"channel"`
	Serial         uint64    `json:"serial"`
	KeyID          string    `json:"key_id"`
	NotBefore      time.Time `json:"not_before"`
	Expires        time.Time `json:"expires"`
	RevokedSerials []uint64  `json:"revoked_serials"`
	Signature      string    `json:"signature"`
}

// Revokes reports whether serial appears on the revocation list.
func (r RevocationList) Revokes(serial uint64) bool {
	return slices.Contains(r.RevokedSerials, serial)
}

// RevocationSigningInput returns the canonical bytes covered by a revocation
// signature: the domain tag followed by the SHA-256 of the payload projection.
// Serials are sorted so issuer and verifier agree without JSON canonicalization.
func RevocationSigningInput(r RevocationList) []byte {
	revoked := append([]uint64(nil), r.RevokedSerials...)
	slices.Sort(revoked)
	payload, _ := json.Marshal(struct {
		Channel        string   `json:"channel"`
		Serial         uint64   `json:"serial"`
		KeyID          string   `json:"key_id"`
		NotBefore      int64    `json:"not_before"`
		Expires        int64    `json:"expires"`
		RevokedSerials []uint64 `json:"revoked_serials"`
	}{
		Channel:        r.Channel,
		Serial:         r.Serial,
		KeyID:          r.KeyID,
		NotBefore:      r.NotBefore.Unix(),
		Expires:        r.Expires.Unix(),
		RevokedSerials: revoked,
	})
	sum := sha256.Sum256(payload)
	return []byte(revocationDomain + "\n" + hex.EncodeToString(sum[:]))
}

// VerifyRevocations verifies raw and returns the independent revocation list:
// signature, freshness and validity window. Anti-rollback is enforced by the
// client's persisted serial high-water, exactly as for manifests.
func (v *Verifier) VerifyRevocations(raw []byte) (RevocationList, error) {
	if len(raw) > MaxPackSize {
		return RevocationList{}, ErrPackTooLarge
	}
	var r RevocationList
	if err := decodeStrict(raw, &r); err != nil {
		return RevocationList{}, err
	}
	if err := validateRevocations(r); err != nil {
		return RevocationList{}, err
	}
	key, err := v.key(r.KeyID)
	if err != nil {
		return RevocationList{}, err
	}
	if !verifySignature(key, RevocationSigningInput(r), r.Signature) {
		return RevocationList{}, ErrPackBadSignature
	}
	if err := v.checkFreshness(r.NotBefore, r.Expires); err != nil {
		return RevocationList{}, err
	}
	return r, nil
}

// validateRevocations checks every revocation field the signature covers.
func validateRevocations(r RevocationList) error {
	for _, f := range []string{r.Channel, r.KeyID, r.Signature} {
		if !checkField(f) {
			return ErrPackMalformed
		}
	}
	if r.Serial == 0 {
		return ErrPackMalformed
	}
	if err := checkRevokedSerials(r.RevokedSerials); err != nil {
		return err
	}
	return checkWindow(r.NotBefore, r.Expires)
}
