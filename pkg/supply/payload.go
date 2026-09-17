// payload.go freezes the two signing-input projections of D6 and the payload
// structs they cover. The projections are deliberately distinct and must never
// be unified:
//
//   - update documents sign `domain + "\n" + name:value lines`, one line per
//     field, timestamps as epoch seconds;
//   - rules documents sign `domain + "\n" + hex(sha256(json.Marshal(payload)))`.
//
// Every struct below is hand-written so its field set, field order, JSON
// names, Go types and omitempty tags reproduce the legacy documents exactly.
// The backend already signs these shapes: one drifted byte — a reordered
// field, a default that emits a key an existing document never carried —
// makes every signature fail and silently drops the client to built-ins.
//
// The new superset rule type in pkg/filter is never projection input. It
// applies defaults (scope, category, priority, confidence) that must not reach
// the projection: the frozen bytes are computed from the raw, undefaulted
// decoded values.
package supply

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Update documents: domain + "\n" + name:value lines, epoch-second timestamps.
// ---------------------------------------------------------------------------

// UpdateManifestPayload is the frozen update-manifest payload. Revoked lists
// are advisory hints; the independent revocations document is authoritative.
type UpdateManifestPayload struct {
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

// UpdateRevocationsPayload is the frozen independent revocation document. It
// carries its own serial and validity window, so revoking a release never
// depends on that release's own manifest.
type UpdateRevocationsPayload struct {
	Channel         string    `json:"channel"`
	Serial          uint64    `json:"serial"`
	KeyID           string    `json:"key_id"`
	NotBefore       time.Time `json:"not_before"`
	Expires         time.Time `json:"expires"`
	RevokedSerials  []uint64  `json:"revoked_serials"`
	RevokedVersions []string  `json:"revoked_versions"`
	Signature       string    `json:"signature"`
}

// UpdateKey is one online signing key advertised by a root-signed key list.
// The validity window expresses rotation overlap: during overlap the list
// carries both the old and the new key.
type UpdateKey struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	Expires   time.Time `json:"expires"`
}

// UpdateKeyListPayload is the frozen root-signed key list document.
type UpdateKeyListPayload struct {
	Serial    uint64      `json:"serial"`
	KeyID     string      `json:"key_id"`
	NotBefore time.Time   `json:"not_before"`
	Expires   time.Time   `json:"expires"`
	Keys      []UpdateKey `json:"keys"`
	Signature string      `json:"signature"`
}

// UpdateManifestSigningInput returns the exact bytes an update-manifest
// signature covers: the domain tag, then one name:value line per field in the
// frozen order, with epoch-second timestamps. Revoked lists are sorted
// (serials numerically, versions as strings) and comma-joined; an empty list
// renders as an empty value, never an omitted line.
func UpdateManifestSigningInput(p UpdateManifestPayload) []byte {
	return updateSigningInput(DomainUpdateManifest, [][2]string{
		{"version", p.Version},
		{"os", p.OS},
		{"arch", p.Arch},
		{"url", p.URL},
		{"sha256", p.SHA256},
		{"channel", p.Channel},
		{"serial", strconv.FormatUint(p.Serial, 10)},
		{"key_id", p.KeyID},
		{"not_before", strconv.FormatInt(p.NotBefore.Unix(), 10)},
		{"expires", strconv.FormatInt(p.Expires.Unix(), 10)},
		{"revoked_serials", joinSerials(sortedSerials(p.RevokedSerials))},
		{"revoked_versions", strings.Join(sortedVersions(p.RevokedVersions), ",")},
	})
}

// UpdateRevocationsSigningInput returns the exact bytes an update-revocations
// signature covers. The layout matches the manifest projection minus the
// release fields, with the same sorting and empty-string rendering.
func UpdateRevocationsSigningInput(p UpdateRevocationsPayload) []byte {
	return updateSigningInput(DomainUpdateRevocations, [][2]string{
		{"channel", p.Channel},
		{"serial", strconv.FormatUint(p.Serial, 10)},
		{"key_id", p.KeyID},
		{"not_before", strconv.FormatInt(p.NotBefore.Unix(), 10)},
		{"expires", strconv.FormatInt(p.Expires.Unix(), 10)},
		{"revoked_serials", joinSerials(sortedSerials(p.RevokedSerials))},
		{"revoked_versions", strings.Join(sortedVersions(p.RevokedVersions), ",")},
	})
}

// UpdateKeyListSigningInput returns the exact bytes a key-list signature
// covers. Entries sort by key id ascending and each renders as
// `key:<id>:<public_key>:<not_before_epoch>:<expires_epoch>`.
func UpdateKeyListSigningInput(p UpdateKeyListPayload) []byte {
	keys := append([]UpdateKey(nil), p.Keys...)
	slices.SortFunc(keys, func(a, b UpdateKey) int { return strings.Compare(a.KeyID, b.KeyID) })

	lines := [][2]string{
		{"serial", strconv.FormatUint(p.Serial, 10)},
		{"key_id", p.KeyID},
		{"not_before", strconv.FormatInt(p.NotBefore.Unix(), 10)},
		{"expires", strconv.FormatInt(p.Expires.Unix(), 10)},
	}
	for _, key := range keys {
		lines = append(lines, [2]string{"key", strings.Join([]string{
			key.KeyID,
			key.PublicKey,
			strconv.FormatInt(key.NotBefore.Unix(), 10),
			strconv.FormatInt(key.Expires.Unix(), 10),
		}, ":")})
	}
	return updateSigningInput(DomainUpdateKeylist, lines)
}

// updateSigningInput renders the line-oriented projection shared by every
// update document.
func updateSigningInput(domain string, lines [][2]string) []byte {
	var b strings.Builder
	b.WriteString(domain)
	b.WriteByte('\n')
	for _, line := range lines {
		b.WriteString(line[0])
		b.WriteByte(':')
		b.WriteString(line[1])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// sortedSerials returns a numerically sorted copy of vals. An empty input
// stays nil, so the rules JSON projections carrying `omitempty` omit the key.
func sortedSerials(vals []uint64) []uint64 {
	out := append([]uint64(nil), vals...)
	slices.Sort(out)
	return out
}

// sortedSerialsNonNil is sortedSerials with a non-nil empty result: the rules
// revocation payload is signed without `omitempty`, so an empty list must
// marshal as `[]`, never as `null`.
func sortedSerialsNonNil(vals []uint64) []uint64 {
	return append(make([]uint64, 0, len(vals)), sortedSerials(vals)...)
}

// sortedVersions returns a copy of vals sorted as strings. Versions never sort
// numerically here: "1.10.0" precedes "1.9.0" exactly as the issuer renders it.
func sortedVersions(vals []string) []string {
	out := append([]string(nil), vals...)
	slices.Sort(out)
	return out
}

// joinSerials renders serials as comma-separated decimal; empty renders "".
func joinSerials(vals []uint64) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(v, 10)
	}
	return strings.Join(parts, ",")
}

// ---------------------------------------------------------------------------
// Rules documents: domain + "\n" + hex(sha256(json.Marshal(payload))).
// ---------------------------------------------------------------------------

// EpochSeconds is the frozen rules-payload timestamp: whole seconds since the
// Unix epoch, as a JSON number. The wire document carries the RFC 3339 string
// form, the signed payload carries the number, so the type decodes both and
// always marshals the number. That is what lets one hand-written struct per
// document both decode a document and reproduce the frozen projection byte for
// byte.
type EpochSeconds int64

// MarshalJSON emits the epoch-second number the signed payload carries.
func (e EpochSeconds) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt(nil, int64(e), 10), nil
}

// UnmarshalJSON accepts the RFC 3339 document form and the epoch-second
// payload form; every other form, including null, is rejected.
func (e *EpochSeconds) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return fmt.Errorf("supply: timestamp must not be null")
	}
	if len(data) > 0 && data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return fmt.Errorf("supply: timestamp is not a JSON string: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339, text)
		if err != nil {
			return fmt.Errorf("supply: timestamp %q is not RFC 3339: %w", text, err)
		}
		*e = EpochSeconds(parsed.Unix())
		return nil
	}
	var seconds int64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return fmt.Errorf("supply: timestamp is neither RFC 3339 nor epoch seconds: %w", err)
	}
	*e = EpochSeconds(seconds)
	return nil
}

// Time renders the timestamp as a time.Time at UTC.
func (e EpochSeconds) Time() time.Time { return time.Unix(int64(e), 0).UTC() }

// RulesRule is the frozen rule element. It reproduces the legacy rule struct
// exactly, including the parse-only `command`/`subcommand`/`verbs`/`targets`
// fields with their legacy value types: only Confidence is a pointer, so a
// document that omits confidence keeps it omitted instead of emitting a
// default. The superset rule type in pkg/filter is never used here.
type RulesRule struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"`
	Pattern       string   `json:"pattern,omitempty"`
	Keywords      []string `json:"keywords,omitempty"`
	Action        string   `json:"action"`
	Confidence    *float64 `json:"confidence,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	Allowlist     []string `json:"allowlist,omitempty"`
	Command       string   `json:"command,omitempty"`
	Subcommand    string   `json:"subcommand,omitempty"`
	Verbs         []string `json:"verbs,omitempty"`
	Targets       []string `json:"targets,omitempty"`
}

// RulesPackPayload is the frozen rules-pack payload. The envelope fields come
// first in the payload order, then the content; Detectors is a map, which
// encoding/json marshals with sorted keys, so the projection is deterministic
// without canonicalization.
type RulesPackPayload struct {
	Channel            string          `json:"channel"`
	SchemaVersion      int             `json:"schema_version"`
	MinBinaryVersion   string          `json:"min_binary_version"`
	Serial             uint64          `json:"serial"`
	KeyID              string          `json:"key_id"`
	NotBefore          EpochSeconds    `json:"not_before"`
	Expires            EpochSeconds    `json:"expires"`
	Detectors          map[string]bool `json:"detectors,omitempty"`
	DisabledCategories []string        `json:"disabled_categories,omitempty"`
	Allowlist          []string        `json:"allowlist,omitempty"`
	Blocklist          []string        `json:"blocklist,omitempty"`
	Rules              []RulesRule     `json:"rules,omitempty"`

	// Signature is carried by the document so a decoded payload can be
	// verified. It is never part of the signed payload: every projection
	// strips it before marshaling.
	Signature string `json:"signature,omitempty"`
}

// RulesManifestPayload is the frozen rules-manifest payload: a signed pointer
// to the current pack. schema_version is the OD-4 gate input.
type RulesManifestPayload struct {
	Channel          string       `json:"channel"`
	SchemaVersion    int          `json:"schema_version"`
	MinBinaryVersion string       `json:"min_binary_version"`
	Serial           uint64       `json:"serial"`
	KeyID            string       `json:"key_id"`
	NotBefore        EpochSeconds `json:"not_before"`
	Expires          EpochSeconds `json:"expires"`
	BundleSHA256     string       `json:"bundle_sha256"`
	Bundle           string       `json:"bundle"`
	RevokedSerials   []uint64     `json:"revoked_serials,omitempty"`

	// Signature is carried by the document so a decoded payload can be
	// verified. It is never part of the signed payload: every projection
	// strips it before marshaling.
	Signature string `json:"signature,omitempty"`
}

// RulesRevocationsPayload is the frozen independent rules revocation payload.
// RevokedSerials carries no omitempty: the published document always renders
// the list, and an empty list must marshal as `[]`, never as `null`.
type RulesRevocationsPayload struct {
	Channel        string       `json:"channel"`
	Serial         uint64       `json:"serial"`
	KeyID          string       `json:"key_id"`
	NotBefore      EpochSeconds `json:"not_before"`
	Expires        EpochSeconds `json:"expires"`
	RevokedSerials []uint64     `json:"revoked_serials"`

	// Signature is carried by the document so a decoded payload can be
	// verified. It is never part of the signed payload: every projection
	// strips it before marshaling.
	Signature string `json:"signature,omitempty"`
}

// RulesPackSigningInput returns the exact bytes a pack signature covers: the
// domain tag followed by the SHA-256 of the frozen payload JSON, computed from
// the payload as decoded, with no defaults applied.
func RulesPackSigningInput(p RulesPackPayload) []byte {
	p.Signature = ""
	return rulesSigningInput(DomainRulesPack, p)
}

// RulesManifestSigningInput returns the exact bytes a rules-manifest signature
// covers. Revoked serials are sorted so issuer and verifier agree without JSON
// canonicalization.
func RulesManifestSigningInput(p RulesManifestPayload) []byte {
	p.Signature = ""
	p.RevokedSerials = sortedSerials(p.RevokedSerials)
	return rulesSigningInput(DomainRulesManifest, p)
}

// RulesRevocationsSigningInput returns the exact bytes a rules-revocations
// signature covers. The list is normalized to a non-nil sorted slice so an
// empty list renders `[]`, matching the issuer's document.
func RulesRevocationsSigningInput(p RulesRevocationsPayload) []byte {
	p.Signature = ""
	p.RevokedSerials = sortedSerialsNonNil(p.RevokedSerials)
	return rulesSigningInput(DomainRulesRevocations, p)
}

// rulesSigningInput renders the hash-based projection every rules document
// shares: domain + "\n" + hex(sha256(json.Marshal(payload))).
func rulesSigningInput(domain string, payload any) []byte {
	body, err := json.Marshal(payload)
	if err != nil {
		// Unreachable: every field of the payload structs is JSON
		// marshalable and EpochSeconds.MarshalJSON cannot fail. Fail closed
		// with the domain alone rather than emit bytes that could never
		// verify.
		return []byte(domain + "\n")
	}
	sum := sha256.Sum256(body)
	return []byte(domain + "\n" + hex.EncodeToString(sum[:]))
}
