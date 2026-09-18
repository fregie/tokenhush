// revocation.go applies the two frozen revocation documents. A store retains
// its active revoked set across a rejected rollback or a failed verification:
// the client never drops to an older, less-revoked state, and a revocation
// failure never silently clears what the active pack already revoked.
package supply

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

// Typed revocation rejections. Callers branch on them with errors.Is.
var (
	// ErrRevokedSerial reports a serial the active list revokes.
	ErrRevokedSerial = errors.New("supply: serial is revoked")
	// ErrRevokedVersion reports a version the active list revokes.
	ErrRevokedVersion = errors.New("supply: version is revoked")
	// ErrRevocationRollback reports a revocation document older than the
	// active one. The active revoked set is retained.
	ErrRevocationRollback = errors.New("supply: revocations serial below the active serial")
)

// DecodeUpdateRevocations decodes one raw update-revocations document.
func DecodeUpdateRevocations(data []byte) (UpdateRevocationsPayload, error) {
	var doc UpdateRevocationsPayload
	if err := decodeFrozenDoc(DomainUpdateRevocations, data, &doc); err != nil {
		return UpdateRevocationsPayload{}, err
	}
	return doc, nil
}

// RevocationStore applies one revocation stream, update or rules. A document
// must verify under its frozen projection before any state changes; a lower
// serial is a rollback and an equal serial is an idempotent replay.
type RevocationStore struct {
	mu       sync.Mutex
	serial   uint64
	serials  []uint64
	versions []string
}

// NewRevocationStore returns a store with nothing revoked.
func NewRevocationStore() *RevocationStore { return &RevocationStore{} }

// ApplyUpdate verifies and applies an update-revocations document. The update
// stream revokes both serials and versions.
func (s *RevocationStore) ApplyUpdate(doc UpdateRevocationsPayload, verifier Verifier) error {
	if err := verifyFrozen(verifier, DomainUpdateRevocations, doc.KeyID, doc.Signature, UpdateRevocationsSigningInput(doc)); err != nil {
		return err
	}
	return s.apply(doc.Serial, doc.RevokedSerials, doc.RevokedVersions)
}

// applyRules verifies and applies a rules-revocations document. The rules
// stream revokes serials only.
func (s *RevocationStore) applyRules(doc RulesRevocationsPayload, verifier Verifier) error {
	if err := verifyFrozen(verifier, DomainRulesRevocations, doc.KeyID, doc.Signature, RulesRevocationsSigningInput(doc)); err != nil {
		return err
	}
	return s.apply(doc.Serial, doc.RevokedSerials, nil)
}

// apply installs a verified document under the lock. A rejected rollback
// returns before touching the active set.
func (s *RevocationStore) apply(serial uint64, serials []uint64, versions []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if serial < s.serial {
		return fmt.Errorf("%w: serial %d is below the active %d", ErrRevocationRollback, serial, s.serial)
	}
	if serial == s.serial && (s.serials != nil || s.versions != nil) {
		return nil
	}
	s.serial = serial
	s.serials = sortedSerials(serials)
	s.versions = sortedVersions(versions)
	return nil
}

// IsSerialRevoked reports whether serial is revoked by the active list.
func (s *RevocationStore) IsSerialRevoked(serial uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, revoked := slices.BinarySearch(s.serials, serial)
	return revoked
}

// IsVersionRevoked reports whether version is revoked by the active list.
func (s *RevocationStore) IsVersionRevoked(version string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, revoked := slices.BinarySearch(s.versions, version)
	return revoked
}

// ActiveSerial returns the serial of the active revocation document.
func (s *RevocationStore) ActiveSerial() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serial
}

// Check rejects a revoked serial or version with the matching typed error.
func (s *RevocationStore) Check(serial uint64, version string) error {
	if s.IsSerialRevoked(serial) {
		return fmt.Errorf("%w: serial %d", ErrRevokedSerial, serial)
	}
	if version != "" && s.IsVersionRevoked(version) {
		return ErrRevokedVersion
	}
	return nil
}

// verifyFrozen decodes the signature and verifies it over signingInput. It
// fails closed on a nil verifier, an absent signature and a bad signature.
func verifyFrozen(verifier Verifier, domain, keyID, signature string, signingInput []byte) error {
	if verifier == nil {
		return fmt.Errorf("%w: no verifier", ErrWrongKey)
	}
	sig, err := DecodeSignature(signature)
	if err != nil {
		return err
	}
	return verifier.Verify(domain, keyID, signingInput, sig)
}
