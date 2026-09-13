package rules

// The signed remote rule pack and its manifest. A remote pack carries the reused
// rule-content schema (Config) inside a signed envelope that adds the freshness
// and compatibility fields ADR-0020 freezes: schema_version (from Config),
// min_binary_version, expires and a monotonic serial. The manifest is a signed
// pointer to the current pack.
//
// The envelope also recognises the two weakening vectors the floor rejects
// (a detector-disable map and a disabled-category list). A well-formed pack
// omits them entirely; built-in detectors are always on unless the *user*
// disables them in local configuration, which the remote pack can never touch.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// MaxPackSize bounds a signed pack or manifest before JSON decoding, so a
// hostile or oversized response can never exhaust memory.
const MaxPackSize = 256 << 10

// maxPackFieldLen bounds a free-text envelope field (channel/key id/version).
const maxPackFieldLen = 200

// Domain-separation tags prefix each signing payload so a signature over one
// document type can never be replayed as the other.
const (
	packDomain     = "tokenhush-rules-pack-v1"
	manifestDomain = "tokenhush-rules-manifest-v1"
)

// Pack errors classify every rejection. Callers branch on them with errors.Is;
// the error text never echoes untrusted bytes.
var (
	// ErrPackTooLarge reports a document above MaxPackSize bytes.
	ErrPackTooLarge = errors.New("rules: pack exceeds size limit")
	// ErrPackMalformed reports unparseable JSON or an invalid pack field.
	ErrPackMalformed = errors.New("rules: malformed pack")
	// ErrPackUnknownKey reports a key_id that names no trusted key.
	ErrPackUnknownKey = errors.New("rules: unknown pack key id")
	// ErrPackBadSignature reports a missing, malformed or non-verifying signature.
	ErrPackBadSignature = errors.New("rules: pack signature does not verify")
	// ErrPackExpired reports a pack or manifest past its expires time.
	ErrPackExpired = errors.New("rules: pack expired")
	// ErrPackNotYetValid reports a pack or manifest before its not_before time.
	ErrPackNotYetValid = errors.New("rules: pack not yet valid")
	// ErrIncompatibleBinary reports a min_binary_version above the running build.
	ErrIncompatibleBinary = errors.New("rules: pack requires a newer binary")
)

// Manifest is a signed pointer to the current rule pack for a channel. It is
// distributed independently of the pack, so the client can check whether an
// update exists without downloading bytes it already has.
type Manifest struct {
	Channel          string    `json:"channel"`
	SchemaVersion    int       `json:"schema_version"`
	MinBinaryVersion string    `json:"min_binary_version"`
	Serial           uint64    `json:"serial"`
	KeyID            string    `json:"key_id"`
	NotBefore        time.Time `json:"not_before"`
	Expires          time.Time `json:"expires"`
	BundleSHA256     string    `json:"bundle_sha256"`
	Bundle           string    `json:"bundle"`
	Signature        string    `json:"signature"`
}

// Pack is a signed remote rule pack: the envelope plus the reused rule content.
// Config is embedded, so schema_version/allowlist/blocklist/rules sit at the top
// level exactly as in a local rule file.
type Pack struct {
	Channel            string          `json:"channel"`
	MinBinaryVersion   string          `json:"min_binary_version"`
	Serial             uint64          `json:"serial"`
	KeyID              string          `json:"key_id"`
	NotBefore          time.Time       `json:"not_before"`
	Expires            time.Time       `json:"expires"`
	Signature          string          `json:"signature"`
	Detectors          map[string]bool `json:"detectors,omitempty"`
	DisabledCategories []string        `json:"disabled_categories,omitempty"`
	Config
}

// Content returns the rule-content document carried by the pack.
func (p Pack) Content() *Config {
	cfg := p.Config
	return &cfg
}

// packPayload is the canonical, signature-covered projection of a Pack with the
// signature field itself excluded. Marshaling it is deterministic because the
// only map (Detectors) is key-sorted by encoding/json.
type packPayload struct {
	Channel            string          `json:"channel"`
	SchemaVersion      int             `json:"schema_version"`
	MinBinaryVersion   string          `json:"min_binary_version"`
	Serial             uint64          `json:"serial"`
	KeyID              string          `json:"key_id"`
	NotBefore          int64           `json:"not_before"`
	Expires            int64           `json:"expires"`
	Detectors          map[string]bool `json:"detectors,omitempty"`
	DisabledCategories []string        `json:"disabled_categories,omitempty"`
	Allowlist          []string        `json:"allowlist,omitempty"`
	Blocklist          []string        `json:"blocklist,omitempty"`
	Rules              []Rule          `json:"rules,omitempty"`
}

// PackSigningInput returns the canonical bytes covered by a pack signature: the
// domain tag followed by the SHA-256 of the payload projection. Hashing keeps
// the signing input small regardless of how many rules the pack carries while
// still covering every field, including the floor-relevant ones.
func PackSigningInput(p Pack) []byte {
	payload, _ := json.Marshal(packPayload{
		Channel:            p.Channel,
		SchemaVersion:      p.SchemaVersion,
		MinBinaryVersion:   p.MinBinaryVersion,
		Serial:             p.Serial,
		KeyID:              p.KeyID,
		NotBefore:          p.NotBefore.Unix(),
		Expires:            p.Expires.Unix(),
		Detectors:          p.Detectors,
		DisabledCategories: p.DisabledCategories,
		Allowlist:          p.Allowlist,
		Blocklist:          p.Blocklist,
		Rules:              p.Rules,
	})
	sum := sha256.Sum256(payload)
	return []byte(packDomain + "\n" + hex.EncodeToString(sum[:]))
}

// ManifestSigningInput returns the canonical bytes covered by a manifest
// signature.
func ManifestSigningInput(m Manifest) []byte {
	payload, _ := json.Marshal(struct {
		Channel          string `json:"channel"`
		SchemaVersion    int    `json:"schema_version"`
		MinBinaryVersion string `json:"min_binary_version"`
		Serial           uint64 `json:"serial"`
		KeyID            string `json:"key_id"`
		NotBefore        int64  `json:"not_before"`
		Expires          int64  `json:"expires"`
		BundleSHA256     string `json:"bundle_sha256"`
		Bundle           string `json:"bundle"`
	}{
		Channel:          m.Channel,
		SchemaVersion:    m.SchemaVersion,
		MinBinaryVersion: m.MinBinaryVersion,
		Serial:           m.Serial,
		KeyID:            m.KeyID,
		NotBefore:        m.NotBefore.Unix(),
		Expires:          m.Expires.Unix(),
		BundleSHA256:     m.BundleSHA256,
		Bundle:           m.Bundle,
	})
	sum := sha256.Sum256(payload)
	return []byte(manifestDomain + "\n" + hex.EncodeToString(sum[:]))
}
