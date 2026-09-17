// rules_cache.go owns the local rules store and the pure document primitives
// the sync layer applies to a fetched document and to a stored one alike:
//
//   - the frozen cache layout, every write atomic and 0600:
//     <DataDir>/rules/active, <DataDir>/rules/revoked.json,
//     <DataDir>/rules/highwater.json (owned by highwater.go) and
//     <DataDir>/rules/<serial>/{manifest,bundle}.json;
//   - the strict decode, the Ed25519 signature verification and the
//     pkg/filter content decode of a frozen rules-pack document
//     (tokenhush-rules-pack-v1), and the signature half of the rules-manifest
//     verification;
//   - the manifest channel, minimum-binary-version and schema-version checks,
//     the minimum-binary-version ordering of a pack and the constant-time
//     bundle digest.
//
// The cache path re-runs exactly those checks when it re-loads a pack, so a
// stored document is held to the same standard as a freshly fetched one: the
// cache is a convenience, never a trust shortcut. The documents are stored
// exactly as they were fetched, so a re-verification is byte for byte the
// verification the network path performed.
package supply

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fregie/tokenhush/pkg/filter"
)

// ErrCacheCorrupt reports a rules cache that cannot be read or decoded. The
// store fails closed instead of resetting the pointer, so a damaged cache
// never silently promotes an unknown document to the active pack.
var ErrCacheCorrupt = errors.New("supply: corrupt rules cache")

// ErrNoCachedPack reports that no pack was ever cached. It is not a failure:
// the built-ins stay active.
var ErrNoCachedPack = errors.New("supply: no cached rules pack")

// Typed document rejections owned by this file. Callers branch on them with
// errors.Is; no error text ever echoes untrusted document content.
var (
	// ErrDigestMismatch reports a bundle whose SHA-256 differs from the digest
	// the manifest declares. The active pack is retained.
	ErrDigestMismatch = errors.New("supply: rules bundle digest does not match the manifest")
	// ErrMinBinaryVersion reports a document that requires a newer binary.
	ErrMinBinaryVersion = errors.New("supply: running binary is below the required minimum version")
	// ErrBadVersion reports a version string that cannot be ordered.
	ErrBadVersion = errors.New("supply: invalid version string")
)

// Frozen file names below <DataDir>/rules/.
const (
	rulesDirName      = "rules"
	rulesActiveName   = "active"
	rulesRevokedName  = "revoked.json"
	rulesManifestName = "manifest.json"
	rulesBundleName   = "bundle.json"
)

// RulesCache reads and writes the frozen rules cache layout.
type RulesCache struct {
	root string
}

// NewRulesCache returns a cache rooted at <dataDir>/rules. It performs no I/O.
func NewRulesCache(dataDir string) *RulesCache {
	return &RulesCache{root: filepath.Join(dataDir, rulesDirName)}
}

// RevocationsPath returns the frozen path of the cached rules-revocations
// document, <DataDir>/rules/revoked.json.
func (c *RulesCache) RevocationsPath() string {
	return filepath.Join(c.root, rulesRevokedName)
}

// CachedPack is one cached, previously verified pack: the raw manifest and
// bundle documents exactly as they were fetched.
type CachedPack struct {
	Serial      uint64
	ManifestRaw []byte
	BundleRaw   []byte
}

// activeDoc is the active pointer document. Serial zero is the sentinel for
// "no pack is active": a first-ever run has no pointer file at all, and a
// zero-serial manifest is never activated (it always equals the zero mark and
// is therefore treated as a replay).
type activeDoc struct {
	Serial uint64 `json:"serial"`
}

// ActiveSerial returns the cached serial, or zero when no pack was ever
// cached. A missing pointer is not an error; an unreadable or undecodable one
// is ErrCacheCorrupt.
func (c *RulesCache) ActiveSerial() (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(c.root, rulesActiveName))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: read active pointer: %w", ErrCacheCorrupt, err)
	}
	var doc activeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("%w: decode active pointer: %w", ErrCacheCorrupt, err)
	}
	return doc.Serial, nil
}

// Store writes the serial's directory documents and then flips the active
// pointer, atomically and 0600. The pointer is written last, so a crash before
// it leaves the previous active pack in force.
func (c *RulesCache) Store(serial uint64, manifestRaw, bundleRaw []byte) error {
	dir := filepath.Join(c.root, strconv.FormatUint(serial, 10))
	if err := writeFileAtomic(filepath.Join(dir, rulesManifestName), manifestRaw); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, rulesBundleName), bundleRaw); err != nil {
		return err
	}
	pointer, err := json.Marshal(activeDoc{Serial: serial})
	if err != nil {
		return fmt.Errorf("supply: encode active pointer: %w", err)
	}
	return writeFileAtomic(filepath.Join(c.root, rulesActiveName), pointer)
}

// LoadActive reads the pack the active pointer names. It returns
// ErrNoCachedPack when no pack was ever cached, and ErrCacheCorrupt when the
// pointer or either document cannot be read.
func (c *RulesCache) LoadActive() (*CachedPack, error) {
	serial, err := c.ActiveSerial()
	if err != nil {
		return nil, err
	}
	if serial == 0 {
		return nil, ErrNoCachedPack
	}
	dir := filepath.Join(c.root, strconv.FormatUint(serial, 10))
	manifestRaw, err := readCachedDoc(filepath.Join(dir, rulesManifestName))
	if err != nil {
		return nil, err
	}
	bundleRaw, err := readCachedDoc(filepath.Join(dir, rulesBundleName))
	if err != nil {
		return nil, err
	}
	return &CachedPack{Serial: serial, ManifestRaw: manifestRaw, BundleRaw: bundleRaw}, nil
}

// readCachedDoc reads one cached document; a missing or unreadable document is
// a corrupt cache, never a silent fallback to a partial pack.
func readCachedDoc(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrCacheCorrupt, path, err)
	}
	return raw, nil
}

// writeFileAtomic writes data to path through a temp file in the same
// directory, chmods it 0600, syncs it and renames it into place. A reader of
// path therefore never observes a partial write, and the file is never group-
// or world-readable.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("supply: create rules cache dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".rules-*.tmp")
	if err != nil {
		return fmt.Errorf("supply: create rules cache temp: %w", err)
	}
	tmpPath := tmp.Name()
	if err := writeTempFile(tmp, data); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("supply: replace %s: %w", path, err)
	}
	return nil
}

// writeTempFile fills and closes one temp file, failing closed at every step.
func writeTempFile(tmp *os.File, data []byte) error {
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: write rules cache temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: chmod rules cache temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: sync rules cache temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("supply: close rules cache temp: %w", err)
	}
	return nil
}

// DecodeRulesPack strictly decodes one raw rules-pack bundle. The cap is the
// rules cap and unknown fields and trailing data are rejected, exactly like
// the other frozen documents, so a typo can never slip past the signature
// check unnoticed.
func DecodeRulesPack(data []byte) (RulesPackPayload, error) {
	pack := RulesPackPayload{}
	err := decodeFrozenDoc(DomainRulesPack, data, &pack)
	return pack, err
}

// VerifyRulesPack verifies the Ed25519 signature over the frozen
// tokenhush-rules-pack-v1 projection with the injected verifier. A missing
// signature, a truncated one and a wrong key all fail closed.
func VerifyRulesPack(pack RulesPackPayload, verifier Verifier) error {
	return verifyFrozen(verifier, DomainRulesPack, pack.KeyID, pack.Signature, RulesPackSigningInput(pack))
}

// decodePackContent runs pkg/filter's strict content decoder over the frozen
// pack document. The frozen filter schema has no `signature` key, so that one
// field is removed first — and only that field: every other byte of the
// document reaches the decoder verbatim, in particular every legacy v1 field
// name. The signature itself was already verified over the frozen projection
// by VerifyRulesPack.
func decodePackContent(bundleRaw []byte) (*filter.Document, *filter.CommandSignal, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(bundleRaw, &fields); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMalformedDoc, err)
	}
	delete(fields, "signature")
	content, err := json.Marshal(fields)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMalformedDoc, err)
	}
	return filter.DecodeDocumentWithSignal(content)
}

// verifyRulesManifestSignature checks only the signature half of the manifest
// verification, for the cache path. The freshness half is deliberately not
// re-applied to a stored document: it was fresh when it was fetched, and
// dropping to the built-ins merely because the client has been offline would
// weaken the protection already in force.
func verifyRulesManifestSignature(manifest RulesManifestPayload, verifier Verifier) error {
	if verifier == nil {
		return fmt.Errorf("%w: no verifier", ErrWrongKey)
	}
	signature, err := DecodeSignature(manifest.Signature)
	if err != nil {
		return err
	}
	return verifier.Verify(DomainRulesManifest, manifest.KeyID, RulesManifestSigningInput(manifest), signature)
}

// checkManifestFields applies the manifest checks that do not depend on
// freshness: the stable channel, the minimum binary version and the OD-4
// schema-version verdict the OD-2 gate decision needs. The returned bool is
// true once the manifest schema_version opens the gate; any version other than
// 1 or 2 is refused with ErrSchemaVersion.
func checkManifestFields(manifest RulesManifestPayload, binary version) (bool, error) {
	if manifest.Channel != rulesChannel {
		return false, fmt.Errorf("%w", ErrChannelMismatch)
	}
	if err := checkMinBinaryVersion(manifest.MinBinaryVersion, binary); err != nil {
		return false, err
	}
	return SchemaVersionGate(manifest.SchemaVersion)
}

// version is a parsed dotted numeric version.
type version [3]int

// parseVersion parses a dotted numeric version with an optional leading v and
// an optional -prerelease/+build suffix, whose value does not affect ordering.
// A malformed string is ErrBadVersion, never a pass: an unorderable minimum
// must not silently satisfy the gate.
func parseVersion(text string) (version, error) {
	core := strings.TrimPrefix(strings.TrimSpace(text), "v")
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if core == "" || len(parts) > 3 {
		return version{}, fmt.Errorf("%w: malformed version", ErrBadVersion)
	}
	var parsed version
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return version{}, fmt.Errorf("%w: malformed version", ErrBadVersion)
		}
		parsed[i] = n
	}
	return parsed, nil
}

// checkMinBinaryVersion refuses a document that requires a newer binary than
// the running one. An absent requirement gates nothing; a malformed one is a
// typed refusal.
func checkMinBinaryVersion(required string, binary version) error {
	if strings.TrimSpace(required) == "" {
		return nil
	}
	minimum, err := parseVersion(required)
	if err != nil {
		return err
	}
	for i := range binary {
		if binary[i] < minimum[i] {
			return fmt.Errorf("%w: %d.%d.%d requires %d.%d.%d", ErrMinBinaryVersion,
				binary[0], binary[1], binary[2], minimum[0], minimum[1], minimum[2])
		}
		if binary[i] > minimum[i] {
			break
		}
	}
	return nil
}

// checkBundleDigest compares the manifest's declared bundle digest with the
// fetched bytes in CONSTANT TIME, so the comparison itself reveals nothing
// beyond the public verdict. A non-hex or wrong-length digest is a mismatch;
// there is no branch on the digest's content.
func checkBundleDigest(declared string, bundleRaw []byte) error {
	digest, err := hex.DecodeString(strings.TrimSpace(declared))
	sum := sha256.Sum256(bundleRaw)
	if err != nil || subtle.ConstantTimeCompare(sum[:], digest) != 1 {
		return fmt.Errorf("%w: sha256 is %s", ErrDigestMismatch, hex.EncodeToString(sum[:]))
	}
	return nil
}
