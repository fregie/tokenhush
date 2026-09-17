// keylist.go installs the online update keys from a root-signed key list. The
// update trust root (root-2026-09) is the only key that may sign a list; the
// list itself carries the upd-* keys the update path later resolves. No online
// update key is ever embedded in the binary, so a leaked or rotated upd-* key
// cannot outlive the key list that installed it.
package supply

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
)

// Typed key-list rejections. Callers branch on them with errors.Is.
var (
	// ErrUnauthorizedKey reports a key list that is not signed by the update
	// trust root: a mismatching key id, an absent signature or a bad one.
	ErrUnauthorizedKey = errors.New("supply: key list is not signed by the update root")
	// ErrKeyListRollback reports a key list older than the active one. The
	// installed key set is retained.
	ErrKeyListRollback = errors.New("supply: key list serial below the active serial")
)

// DecodeUpdateKeyList decodes one raw key-list document. The cap is the update
// cap; unknown fields and trailing data are rejected, exactly like the rules
// manifest, so a typo can never slip into the signed payload.
func DecodeUpdateKeyList(data []byte) (UpdateKeyListPayload, error) {
	var list UpdateKeyListPayload
	if err := decodeFrozenDoc(DomainUpdateKeylist, data, &list); err != nil {
		return UpdateKeyListPayload{}, err
	}
	return list, nil
}

// VerifyKeyList verifies the root signature over the frozen
// tokenhush-update-keylist-v1 projection. Only KeyRootUpdate may sign; another
// key id, a missing signature and a bad signature all fail with
// ErrUnauthorizedKey. There is no freshness check here: a replayed list is
// handled by the installer's serial rule, which is stronger.
func VerifyKeyList(list UpdateKeyListPayload, verifier Verifier) error {
	if list.KeyID != KeyRootUpdate {
		return fmt.Errorf("%w: the list does not claim the update root id", ErrUnauthorizedKey)
	}
	if verifier == nil {
		return fmt.Errorf("%w: no verifier", ErrWrongKey)
	}
	signature, err := DecodeSignature(list.Signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthorizedKey, err)
	}
	if err := verifier.Verify(DomainUpdateKeylist, list.KeyID, UpdateKeyListSigningInput(list), signature); err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthorizedKey, err)
	}
	return nil
}

// KeyListStore holds the installed online update keys. The active set is only
// ever replaced by a verified list; a lower serial is rejected and an equal
// serial is an idempotent replay.
type KeyListStore struct {
	mu     sync.Mutex
	serial uint64
	keys   map[string]string
}

// NewKeyListStore returns a store with no installed keys.
func NewKeyListStore() *KeyListStore { return &KeyListStore{} }

// Install verifies list, then replaces the active key set. Verification
// happens before the lock and before any state changes.
func (s *KeyListStore) Install(list UpdateKeyListPayload, verifier Verifier) error {
	if err := VerifyKeyList(list, verifier); err != nil {
		return err
	}
	keys, err := keyListKeys(list)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if list.Serial < s.serial {
		return fmt.Errorf("%w: serial %d is below the active %d", ErrKeyListRollback, list.Serial, s.serial)
	}
	if list.Serial == s.serial && s.keys != nil {
		return nil
	}
	s.serial = list.Serial
	s.keys = keys
	return nil
}

// PublicKey returns the public key installed for id, if any.
func (s *KeyListStore) PublicKey(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	public, ok := s.keys[id]
	return public, ok
}

// IDs returns the installed key ids, ascending.
func (s *KeyListStore) IDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// ActiveSerial returns the serial of the active key list.
func (s *KeyListStore) ActiveSerial() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serial
}

// Verifier returns a Verifier over the installed online keys only: a document
// naming a rotated-away or never-installed key fails closed.
func (s *KeyListStore) Verifier() Verifier { return keySetVerifier{store: s} }

// keySetVerifier resolves document signatures against the installed keys.
type keySetVerifier struct {
	store *KeyListStore
}

// Verify implements Verifier.
func (v keySetVerifier) Verify(domain, keyID string, signingInput, sig []byte) error {
	if domain == "" {
		return fmt.Errorf("%w: empty domain tag", ErrBadSignature)
	}
	public, ok := v.store.PublicKey(keyID)
	if !ok {
		return fmt.Errorf("%w: no installed update key for that id", ErrWrongKey)
	}
	return VerifyEd25519(public, signingInput, sig)
}

// keyListKeys validates and indexes the entries: an empty id, an embedded root
// id, a duplicate id and a public key that is not a base64 raw-URL Ed25519 key
// are all rejected, so a malformed entry never enters the active set.
func keyListKeys(list UpdateKeyListPayload) (map[string]string, error) {
	keys := make(map[string]string, len(list.Keys))
	for i, entry := range list.Keys {
		if entry.KeyID == "" {
			return nil, fmt.Errorf("%w: key list entry %d has an empty id", ErrMalformedDoc, i)
		}
		if entry.KeyID == KeyRootUpdate || entry.KeyID == KeyRulesRoot {
			return nil, fmt.Errorf("%w: key list entry %d names an embedded root", ErrMalformedDoc, i)
		}
		if _, dup := keys[entry.KeyID]; dup {
			return nil, fmt.Errorf("%w: key list repeats a key id", ErrMalformedDoc)
		}
		pub, err := base64.RawURLEncoding.DecodeString(entry.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: key list entry %d has an invalid public key", ErrMalformedDoc, i)
		}
		keys[entry.KeyID] = entry.PublicKey
	}
	return keys, nil
}

// decodeFrozenDoc enforces the domain size cap and strict single-object JSON.
func decodeFrozenDoc(domain string, data []byte, out any) error {
	if err := CheckDocSize(domain, data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedDoc, err)
	}
	var extra any
	switch err := dec.Decode(&extra); {
	case errors.Is(err, io.EOF):
		return nil
	case err == nil:
		return fmt.Errorf("%w: trailing data after the document", ErrMalformedDoc)
	default:
		return fmt.Errorf("%w: trailing data: %w", ErrMalformedDoc, err)
	}
}
