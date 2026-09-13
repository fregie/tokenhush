// This file owns the signed update manifest schema and the freshness/version
// rules that do not depend on any key set. Verification itself (signature,
// high-water, key rotation) lives in verify.go and keylist.go.
//
// The schema is the client side of the Cloudflare update service contract
// (ADR-0019 §2): version / os / arch / url / sha256 / signature / channel /
// expires / not_before / monotonic serial, plus revoked_serials and
// revoked_versions. Every field is covered by the Ed25519 signature.
package update

import (
	"crypto/ed25519"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxDocumentSize bounds any signed update document before JSON decoding, so a
// hostile or oversized response can never exhaust memory.
const MaxDocumentSize = 128 << 10

// maxFieldLen bounds every string field in a signed document. The manifest
// signs exactly these bytes, so the limit also keeps the signing input small.
const maxFieldLen = 512

// maxRevokedEntries bounds the revocation lists carried by a document.
const maxRevokedEntries = 4096

// Document kinds name the independent anti-rollback sequence a serial belongs
// to. Each kind has its own persisted high-water mark.
const (
	// KindManifest is the release manifest serial sequence.
	KindManifest = "manifest"
	// KindRevocations is the independent revocation document serial sequence.
	KindRevocations = "revocations"
	// KindKeyList is the root-signed update key list serial sequence.
	KindKeyList = "keylist"
)

// Domain-separation tags prefix each signing input so a signature over one
// document type can never be replayed as another.
const (
	manifestDomain   = "tokenhush-update-manifest-v1"
	revocationDomain = "tokenhush-update-revocations-v1"
	keyListDomain    = "tokenhush-update-keylist-v1"
)

// Errors classify every rejection. Callers branch on them with errors.Is; the
// error text never echoes untrusted bytes.
var (
	// ErrTooLarge reports a document above MaxDocumentSize bytes.
	ErrTooLarge = errors.New("update: document exceeds size limit")
	// ErrMalformed reports unparseable JSON or an invalid field.
	ErrMalformed = errors.New("update: malformed document")
	// ErrUnknownKey reports a key_id that names no trusted key.
	ErrUnknownKey = errors.New("update: unknown key id")
	// ErrKeyNotValid reports a known key outside its validity window.
	ErrKeyNotValid = errors.New("update: signing key not valid at this time")
	// ErrBadSignature reports a missing, malformed or non-verifying signature.
	ErrBadSignature = errors.New("update: signature does not verify")
	// ErrExpired reports a document past its expires time.
	ErrExpired = errors.New("update: document expired")
	// ErrNotYetValid reports a document before its not_before time.
	ErrNotYetValid = errors.New("update: document not yet valid")
	// ErrReplayed reports a serial at or below the persisted high-water mark.
	ErrReplayed = errors.New("update: serial at or below high-water mark")
	// ErrRevoked reports a manifest whose version or serial is revoked.
	ErrRevoked = errors.New("update: version or serial revoked")
	// ErrDowngrade reports an install below the running version.
	ErrDowngrade = errors.New("update: downgrade refused")
)

// Key pairs a rotation ID with the Ed25519 public key that verifies documents
// carrying that ID. Root keys sign key lists; update keys sign manifests and
// revocation documents. Both are public-only: private halves never ship.
type Key struct {
	ID     string
	Public ed25519.PublicKey
}

// Freshness is the result of evaluating a document against its validity window.
type Freshness int

const (
	// Fresh means now is within [not_before, expires].
	Fresh Freshness = iota
	// NotYetValid means now precedes not_before.
	NotYetValid
	// Expired means now is after expires.
	Expired
)

// Manifest is a signed release manifest. Version is the release version (used
// for downgrade comparison); Serial is the monotonic anti-rollback counter.
type Manifest struct {
	Version         string    `json:"version"`
	OS              string    `json:"os"`
	Arch            string    `json:"arch"`
	URL             string    `json:"url"`
	SHA256          string    `json:"sha256"`
	Channel         string    `json:"channel"`
	Serial          uint64    `json:"serial"`
	KeyID           string    `json:"key_id"`
	NotBefore       time.Time `json:"not_before"`
	Expires         time.Time `json:"expires"`
	RevokedSerials  []uint64  `json:"revoked_serials,omitempty"`
	RevokedVersions []string  `json:"revoked_versions,omitempty"`
	Signature       string    `json:"signature"`
}

// Freshness reports the manifest's validity state at now.
func (m Manifest) Freshness(now time.Time) Freshness {
	return freshness(m.NotBefore, m.Expires, now)
}

// RevocationList is an independent, self-contained signed document that a
// kill-switch can fetch on its own. It carries its own expires and monotonic
// serial so it can never be frozen or rolled back, and it is authoritative
// over the advisory revoked_* hints embedded in a manifest.
type RevocationList struct {
	Channel         string    `json:"channel"`
	Serial          uint64    `json:"serial"`
	KeyID           string    `json:"key_id"`
	NotBefore       time.Time `json:"not_before"`
	Expires         time.Time `json:"expires"`
	RevokedSerials  []uint64  `json:"revoked_serials"`
	RevokedVersions []string  `json:"revoked_versions"`
	Signature       string    `json:"signature"`
}

// Freshness reports the revocation document's validity state at now.
func (r RevocationList) Freshness(now time.Time) Freshness {
	return freshness(r.NotBefore, r.Expires, now)
}

// IsRevoked reports whether version or serial appears on the revocation list.
func (r RevocationList) IsRevoked(version string, serial uint64) bool {
	return slices.Contains(r.RevokedVersions, version) || slices.Contains(r.RevokedSerials, serial)
}

// ManifestSigningInput returns the canonical bytes covered by a manifest
// signature. Revoked lists are sorted so issuer and verifier agree without
// JSON canonicalization.
func ManifestSigningInput(m Manifest) []byte {
	serials := append([]uint64(nil), m.RevokedSerials...)
	slices.Sort(serials)
	versions := append([]string(nil), m.RevokedVersions...)
	slices.Sort(versions)

	var b strings.Builder
	b.WriteString(manifestDomain)
	b.WriteByte('\n')
	writeLine(&b, "version", m.Version)
	writeLine(&b, "os", m.OS)
	writeLine(&b, "arch", m.Arch)
	writeLine(&b, "url", m.URL)
	writeLine(&b, "sha256", m.SHA256)
	writeLine(&b, "channel", m.Channel)
	writeLine(&b, "serial", strconv.FormatUint(m.Serial, 10))
	writeLine(&b, "key_id", m.KeyID)
	writeLine(&b, "not_before", strconv.FormatInt(m.NotBefore.Unix(), 10))
	writeLine(&b, "expires", strconv.FormatInt(m.Expires.Unix(), 10))
	writeLine(&b, "revoked_serials", joinUint64(serials))
	writeLine(&b, "revoked_versions", strings.Join(versions, ","))
	return []byte(b.String())
}

// RevocationSigningInput returns the canonical bytes covered by a revocation
// document signature.
func RevocationSigningInput(r RevocationList) []byte {
	serials := append([]uint64(nil), r.RevokedSerials...)
	slices.Sort(serials)
	versions := append([]string(nil), r.RevokedVersions...)
	slices.Sort(versions)

	var b strings.Builder
	b.WriteString(revocationDomain)
	b.WriteByte('\n')
	writeLine(&b, "channel", r.Channel)
	writeLine(&b, "serial", strconv.FormatUint(r.Serial, 10))
	writeLine(&b, "key_id", r.KeyID)
	writeLine(&b, "not_before", strconv.FormatInt(r.NotBefore.Unix(), 10))
	writeLine(&b, "expires", strconv.FormatInt(r.Expires.Unix(), 10))
	writeLine(&b, "revoked_serials", joinUint64(serials))
	writeLine(&b, "revoked_versions", strings.Join(versions, ","))
	return []byte(b.String())
}

// CompareVersions compares two numeric release versions ("major.minor.patch",
// 1-3 numeric components). It returns -1, 0 or 1, or ErrMalformed when either
// side is not numeric.
func CompareVersions(a, b string) (int, error) {
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

// validate checks every manifest field the signature covers. It never echoes
// field content in the error.
func (m Manifest) validate() error {
	if err := checkField(m.Version); err != nil {
		return err
	}
	if _, err := parseVersion(m.Version); err != nil {
		return err
	}
	for _, f := range []string{m.OS, m.Arch, m.Channel, m.KeyID} {
		if err := checkField(f); err != nil {
			return err
		}
	}
	if err := checkURL(m.URL); err != nil {
		return err
	}
	if err := checkSHA256(m.SHA256); err != nil {
		return err
	}
	if err := checkWindow(m.NotBefore, m.Expires); err != nil {
		return err
	}
	if err := checkRevoked(m.RevokedSerials, m.RevokedVersions); err != nil {
		return err
	}
	if slices.Contains(m.RevokedSerials, m.Serial) || slices.Contains(m.RevokedVersions, m.Version) {
		return errors.New("update: manifest must not revoke itself")
	}
	return nil
}

// validate checks every revocation field the signature covers.
func (r RevocationList) validate() error {
	if err := checkField(r.Channel); err != nil {
		return err
	}
	if err := checkField(r.KeyID); err != nil {
		return err
	}
	if err := checkWindow(r.NotBefore, r.Expires); err != nil {
		return err
	}
	return checkRevoked(r.RevokedSerials, r.RevokedVersions)
}

// freshness is the shared validity-window evaluator.
func freshness(notBefore, expires, now time.Time) Freshness {
	switch {
	case now.Before(notBefore):
		return NotYetValid
	case now.After(expires):
		return Expired
	default:
		return Fresh
	}
}

// writeLine appends one "name:value\n" signing-input line.
func writeLine(b *strings.Builder, name, value string) {
	b.WriteString(name)
	b.WriteByte(':')
	b.WriteString(value)
	b.WriteByte('\n')
}

// joinUint64 renders serials as comma-separated decimal.
func joinUint64(vals []uint64) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(v, 10)
	}
	return strings.Join(parts, ",")
}
