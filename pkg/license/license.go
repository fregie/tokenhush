package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Badge is the exact human-facing string rendered when a license verifies. It
// is deliberately read-only: displaying it unlocks nothing, and no core
// package may branch on it.
const Badge = "Pro active (read-only)"

// FileName is the license file name below the platform config directory.
// internal/cli resolves the directory via pkg/platform; this package never
// resolves paths itself.
const FileName = "license.json"

// Version is the only token schema version this parser accepts.
const Version = 1

// MaxTokenSize bounds a license file. The limit is enforced before JSON
// decoding so an oversized file can never exhaust memory.
const MaxTokenSize = 64 << 10

// GracePeriod is how long past expires_at a license still renders the badge.
// It is intentionally generous (offline grace), and clock rollback is
// tolerated: an issued_at in the future does not invalidate a token.
const GracePeriod = 30 * 24 * time.Hour

// Field bounds keep the canonical signing input small and unambiguous.
const (
	maxFieldLen = 256
	maxFeatures = 32
)

// KeyID is the rotation ID of the embedded public key. Tokens must carry a
// key_id that names an embedded key; rotation ships a new key set in an app
// update while old tokens keep verifying.
const KeyID = "core-test-2026-09"

// embeddedPublicKey is the Ed25519 public key compiled into the open-source
// core. ONLY a public key is embedded: the private half is held by the
// closed-source license service and must never be committed to this
// repository. The V1 value is a freshly generated placeholder for the
// read-only display path; the production key set is swapped in when the
// license service ships (W10.3). Even a forged token for this key only ever
// renders the read-only badge - it gates no capability by design.
var embeddedPublicKey = ed25519.PublicKey{
	0x34, 0x4c, 0x42, 0xcb, 0xd8, 0x9d, 0xfb, 0x73,
	0xea, 0x47, 0x29, 0xec, 0x25, 0x53, 0xf3, 0x48,
	0xe7, 0x0a, 0x13, 0xc3, 0x21, 0xec, 0xf5, 0x95,
	0x3b, 0x99, 0xbd, 0x59, 0x0b, 0x9c, 0x4e, 0xf3,
}

// Errors classify every rejection. The CLI collapses all of them into "no
// badge" and never prints the cause; they exist for tests and diagnostics.
var (
	// ErrTooLarge reports a token above MaxTokenSize bytes.
	ErrTooLarge = errors.New("license: token exceeds size limit")
	// ErrMalformed reports unparseable JSON or a missing/invalid field.
	ErrMalformed = errors.New("license: malformed token")
	// ErrUnsupportedVersion reports a version this parser does not know.
	ErrUnsupportedVersion = errors.New("license: unsupported version")
	// ErrUnknownKey reports a key_id that names no embedded key.
	ErrUnknownKey = errors.New("license: unknown key id")
	// ErrBadSignature reports a missing, malformed or non-verifying signature.
	ErrBadSignature = errors.New("license: signature does not verify")
	// ErrExpired reports a token past expires_at + GracePeriod.
	ErrExpired = errors.New("license: expired beyond grace period")
)

// Key pairs a rotation ID with the Ed25519 public key that verifies tokens
// carrying that ID.
type Key struct {
	ID     string
	Public ed25519.PublicKey
}

// License is the decoded payload of a license token. Features are
// informational: the read-only core never enables behavior from them.
type License struct {
	Version   int       `json:"version"`
	KeyID     string    `json:"key_id"`
	LicenseID string    `json:"license_id"`
	Subject   string    `json:"subject"`
	Features  []string  `json:"features"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string    `json:"signature"`
}

// Verifier checks tokens against a key set and a clock. The zero value
// verifies nothing; use DefaultVerifier for the embedded key set.
type Verifier struct {
	// Keys is the accepted, rotation-aware key set. Required.
	Keys []Key
	// Now supplies the current time. Nil means time.Now. Tests use it to pin
	// expiry, grace and clock-rollback behavior.
	Now func() time.Time
}

// DefaultKeys returns the embedded public key set.
func DefaultKeys() []Key {
	return []Key{{ID: KeyID, Public: embeddedPublicKey}}
}

// DefaultVerifier returns a Verifier wired to the embedded public key set.
func DefaultVerifier() Verifier {
	return Verifier{Keys: DefaultKeys()}
}

// Parse verifies raw token bytes and returns the decoded license.
//
// Parse is total over arbitrary input: it returns an error, never a panic,
// and the error text contains no secret and no token bytes.
func (v Verifier) Parse(raw []byte) (License, error) {
	var lic License
	if len(raw) > MaxTokenSize {
		return License{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(raw))
	}
	if err := json.Unmarshal(raw, &lic); err != nil {
		return License{}, fmt.Errorf("%w: invalid JSON", ErrMalformed)
	}
	if lic.Version != Version {
		return License{}, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, lic.Version, Version)
	}
	if err := lic.validate(); err != nil {
		return License{}, err
	}
	pub, ok := v.publicKey(lic.KeyID)
	if !ok {
		return License{}, fmt.Errorf("%w: %q", ErrUnknownKey, lic.KeyID)
	}
	sig, err := base64.RawURLEncoding.DecodeString(lic.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return License{}, fmt.Errorf("%w: bad encoding", ErrBadSignature)
	}
	if !ed25519.Verify(pub, SigningInput(lic), sig) {
		return License{}, ErrBadSignature
	}
	if now := v.now(); now.After(lic.ExpiresAt.Add(GracePeriod)) {
		return License{}, ErrExpired
	}
	return lic, nil
}

// LoadFile reads and verifies the license file at path. A missing file is
// reported as an ordinary OS error; Badge collapses that into "no badge".
func (v Verifier) LoadFile(path string) (License, error) {
	f, err := os.Open(path)
	if err != nil {
		return License{}, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxTokenSize+1))
	if err != nil {
		return License{}, err
	}
	if len(raw) > MaxTokenSize {
		return License{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(raw))
	}
	return v.Parse(raw)
}

// Badge returns Badge exactly when path holds a license that verifies and is
// within its grace period. Every other outcome - absent, unreadable, malformed,
// tampered, unknown key, expired - returns "". The reason is never surfaced.
func (v Verifier) Badge(path string) string {
	if _, err := v.LoadFile(path); err != nil {
		return ""
	}
	return Badge
}

// BadgeForFile is Badge with the embedded public key set.
func BadgeForFile(path string) string {
	return DefaultVerifier().Badge(path)
}

// SigningInput returns the canonical bytes covered by License.Signature. The
// license service signs exactly these bytes; Parse recomputes them from the
// decoded token, so issuer and verifier agree without JSON canonicalization.
// Issuers must build values that pass validate (Parse enforces that on the
// verifying side); SigningInput itself is total and never fails.
func SigningInput(l License) []byte {
	features := append([]string(nil), l.Features...)
	sort.Strings(features)
	var b strings.Builder
	fmt.Fprintf(&b, "tokenhush-license-v%d\n", l.Version)
	fmt.Fprintf(&b, "key_id:%s\n", l.KeyID)
	fmt.Fprintf(&b, "license_id:%s\n", l.LicenseID)
	fmt.Fprintf(&b, "subject:%s\n", l.Subject)
	fmt.Fprintf(&b, "features:%s\n", strings.Join(features, ","))
	fmt.Fprintf(&b, "issued_at:%d\n", l.IssuedAt.Unix())
	fmt.Fprintf(&b, "expires_at:%d\n", l.ExpiresAt.Unix())
	return []byte(b.String())
}

// validate enforces the field rules shared by all verification paths. Error
// text never echoes token content.
func (l License) validate() error {
	if l.KeyID == "" || l.LicenseID == "" {
		return fmt.Errorf("%w: key_id and license_id are required", ErrMalformed)
	}
	if len(l.Features) > maxFeatures {
		return fmt.Errorf("%w: too many features", ErrMalformed)
	}
	for _, field := range append([]string{l.KeyID, l.LicenseID, l.Subject}, l.Features...) {
		if len(field) > maxFieldLen || strings.ContainsAny(field, "\r\n") {
			return fmt.Errorf("%w: field exceeds limits", ErrMalformed)
		}
	}
	if l.IssuedAt.IsZero() || l.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: issued_at and expires_at are required", ErrMalformed)
	}
	if l.ExpiresAt.Before(l.IssuedAt) {
		return fmt.Errorf("%w: expires_at precedes issued_at", ErrMalformed)
	}
	return nil
}

// publicKey looks key_id up in the key set, ignoring entries that cannot be
// used by ed25519.Verify (defence against a malformed injected key set; the
// embedded set is always well formed).
func (v Verifier) publicKey(id string) (ed25519.PublicKey, bool) {
	for _, k := range v.Keys {
		if k.ID == id && len(k.Public) == ed25519.PublicKeySize {
			return k.Public, true
		}
	}
	return nil, false
}

// now returns the verifier clock, defaulting to time.Now.
func (v Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}
