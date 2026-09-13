// Trust-root and update-key rotation. A root-signed key list is the only way
// new update keys enter a client: roots stay offline, update keys are the
// online signers, and dropping a key from a newer list revokes it (leak
// recovery). The key list is itself anti-rollback protected by a monotonic
// serial, so an attacker cannot replay an old list to revive a leaked key.
package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// bootstrapRootKeyID names the root public key compiled into this build. It is
// a placeholder for the Plan B offline root ceremony: the owner generates the
// production root offline and replaces this entry (and its key id) at release.
// Tests inject their own roots and never depend on this value.
const bootstrapRootKeyID = "root-bootstrap-2026-09"

// bootstrapRootPublic is a public-only bootstrap root key. The matching private
// key is not committed and not held by this build; it exists solely so the
// trust-root field is populated until the offline root ceremony lands.
var bootstrapRootPublic = ed25519.PublicKey{
	0xdd, 0x7a, 0x11, 0x25, 0xbe, 0xb4, 0xcf, 0x1e,
	0x79, 0x68, 0xcf, 0x6c, 0x75, 0x95, 0x02, 0xdc,
	0x48, 0xa4, 0xba, 0x76, 0x06, 0xf4, 0x7d, 0xcc,
	0x19, 0xb2, 0x63, 0xb0, 0x16, 0x08, 0x6c, 0xe1,
}

// DefaultRoots returns the embedded root public key set. Root rotation works
// by shipping a new build whose set contains both the old and the new root.
func DefaultRoots() []Key {
	return []Key{{ID: bootstrapRootKeyID, Public: bootstrapRootPublic}}
}

// UpdateKey is one online signing key advertised by a root-signed key list.
// The validity window expresses the rotation overlap: during overlap the list
// carries both the old and the new key, and after recovery only the new one.
type UpdateKey struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	Expires   time.Time `json:"expires"`
}

// KeyList is a root-signed document that publishes the accepted update keys.
type KeyList struct {
	Serial    uint64      `json:"serial"`
	KeyID     string      `json:"key_id"`
	NotBefore time.Time   `json:"not_before"`
	Expires   time.Time   `json:"expires"`
	Keys      []UpdateKey `json:"keys"`
	Signature string      `json:"signature"`
}

// KeyListSigningInput returns the canonical bytes covered by a key-list
// signature, with entries sorted by key id.
func KeyListSigningInput(k KeyList) []byte {
	keys := append([]UpdateKey(nil), k.Keys...)
	slices.SortFunc(keys, func(a, b UpdateKey) int { return strings.Compare(a.KeyID, b.KeyID) })

	var b strings.Builder
	b.WriteString(keyListDomain)
	b.WriteByte('\n')
	writeLine(&b, "serial", strconv.FormatUint(k.Serial, 10))
	writeLine(&b, "key_id", k.KeyID)
	writeLine(&b, "not_before", strconv.FormatInt(k.NotBefore.Unix(), 10))
	writeLine(&b, "expires", strconv.FormatInt(k.Expires.Unix(), 10))
	for _, key := range keys {
		writeLine(&b, "key", strings.Join([]string{
			key.KeyID,
			key.PublicKey,
			strconv.FormatInt(key.NotBefore.Unix(), 10),
			strconv.FormatInt(key.Expires.Unix(), 10),
		}, ":"))
	}
	return []byte(b.String())
}

// ApplyKeyList verifies a root-signed key list and installs its update keys on
// v. It refuses untrusted roots, stale nonces (replay), expired documents and
// malformed keys, so a replayed pre-recovery list cannot restore a leaked key.
func (v *Verifier) ApplyKeyList(raw []byte) error {
	if len(raw) > MaxDocumentSize {
		return ErrTooLarge
	}
	var kl KeyList
	if err := json.Unmarshal(raw, &kl); err != nil {
		return ErrMalformed
	}
	if err := kl.validate(); err != nil {
		return err
	}
	root, ok := lookupKey(v.Roots, kl.KeyID)
	if !ok {
		return ErrUnknownKey
	}
	if err := verifySignature(root, KeyListSigningInput(kl), kl.Signature); err != nil {
		return err
	}
	switch kl.Freshness(v.now()) {
	case NotYetValid:
		return ErrNotYetValid
	case Expired:
		return ErrExpired
	}
	keys, err := buildUpdateKeys(kl.Keys)
	if err != nil {
		return err
	}
	if err := v.admit(KindKeyList, kl.Serial); err != nil {
		return err
	}
	v.updateKeys = keys
	return nil
}

// Freshness reports the key list's validity state at now.
func (k KeyList) Freshness(now time.Time) Freshness {
	return freshness(k.NotBefore, k.Expires, now)
}

// validate checks the key list envelope and every advertised key.
func (k KeyList) validate() error {
	if err := checkField(k.KeyID); err != nil {
		return err
	}
	if err := checkWindow(k.NotBefore, k.Expires); err != nil {
		return err
	}
	if len(k.Keys) == 0 {
		return errors.New("update: key list must advertise at least one key")
	}
	seen := make(map[string]bool, len(k.Keys))
	for _, key := range k.Keys {
		if err := checkField(key.KeyID); err != nil {
			return err
		}
		if seen[key.KeyID] {
			return errors.New("update: duplicate key id in key list")
		}
		seen[key.KeyID] = true
		if _, err := decodePublicKey(key.PublicKey); err != nil {
			return err
		}
		if err := checkWindow(key.NotBefore, key.Expires); err != nil {
			return err
		}
	}
	return nil
}

// buildUpdateKeys turns validated key-list entries into the accepted key set,
// retaining each key's validity window for online signature verification.
func buildUpdateKeys(entries []UpdateKey) ([]acceptedKey, error) {
	out := make([]acceptedKey, 0, len(entries))
	for _, e := range entries {
		pub, err := decodePublicKey(e.PublicKey)
		if err != nil {
			return nil, err
		}
		out = append(out, acceptedKey{id: e.KeyID, public: pub, notBefore: e.NotBefore, expires: e.Expires})
	}
	return out, nil
}

// acceptedKey is a trusted update key plus the window during which it may sign
// manifests and revocation documents.
type acceptedKey struct {
	id        string
	public    ed25519.PublicKey
	notBefore time.Time
	expires   time.Time
}

// lookupKey finds id in a key set. It is used for root keys, which have no
// per-key validity window: roots only change with a new build.
func lookupKey(keys []Key, id string) (ed25519.PublicKey, bool) {
	for _, k := range keys {
		if k.ID == id && len(k.Public) == ed25519.PublicKeySize {
			return k.Public, true
		}
	}
	return nil, false
}

// decodePublicKey decodes a base64 raw-URL Ed25519 public key.
func decodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("update: malformed public key")
	}
	return ed25519.PublicKey(raw), nil
}
