package redact

import (
	"bytes"
	"sort"
	"strings"
)

// knownSecretPair is one (secret, placeholder) mapping copied out of the engine
// under the lock, so the scan that follows can run without holding e.mu.
type knownSecretPair struct {
	secret      string
	placeholder string
}

// knownSecretSnapshot copies every non-empty secret currently mapped, paired
// with its placeholder, out of the engine under e.mu.
//
// bySecret keys are the sanitised type, a NUL separator and the secret:
// sanitizePlaceholderType can never emit NUL, so splitting on the first NUL
// recovers the secret exactly — including secrets that contain NUL themselves.
// Empty secrets are skipped: an empty needle would match every buffer, and an
// empty mapping carries no secret material anyway.
func (e *PlaceholderEngine) knownSecretSnapshot() []knownSecretPair {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.bySecret) == 0 {
		return nil
	}
	out := make([]knownSecretPair, 0, len(e.bySecret))
	for key, placeholder := range e.bySecret {
		_, secret, found := strings.Cut(key, "\x00")
		if !found || secret == "" {
			continue // separator is an engine invariant; empty secrets never match
		}
		out = append(out, knownSecretPair{secret: secret, placeholder: placeholder})
	}
	return out
}

// KnownSecrets returns a snapshot copy of every distinct secret currently
// mapped by the engine, ordered lexicographically by secret bytes. A secret
// mapped under more than one finding type appears once, and an empty mapping is
// omitted (it carries no secret material and, as a needle, would match every
// buffer).
//
// This is a read-only view for callers that must reason about the secrets the
// engine knows: the outbound (post-redaction) re-check asks whether a request
// still carries any of them, and the encoding normaliser needs the raw bytes to
// build candidates. It never writes — secrets enter the engine only through
// Placeholder during redaction, and any force-redaction write path is owned by
// that flow, not here.
//
// Every returned slice is a fresh copy, so mutating the result cannot corrupt
// engine state, and a later mapping addition cannot alter a snapshot already
// handed out. A nil engine returns none.
func (e *PlaceholderEngine) KnownSecrets() [][]byte {
	if e == nil {
		return nil
	}
	snapshot := e.knownSecretSnapshot()
	if len(snapshot) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(snapshot))
	out := make([][]byte, 0, len(snapshot))
	for _, pair := range snapshot {
		if _, dup := seen[pair.secret]; dup {
			continue
		}
		seen[pair.secret] = struct{}{}
		out = append(out, []byte(pair.secret))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// ContainsKnownSecret reports whether any secret currently mapped by the engine
// occurs as a substring of b; nil or empty input never matches.
//
// It is the membership test for the outbound re-check: after redaction, the
// request body is inspected for anything the engine just mapped, which would
// mean a placeholder was decoded back to plaintext and is being smuggled
// upstream. The check is read-only: it never creates, changes or drops a
// mapping.
//
// The second return value is the matched secret's placeholder token, never the
// plaintext. Auditing this decision needs an identifier for the finding, and
// the audit invariant forbids plaintext in logs and audit rows (docs/security.md);
// returning the placeholder keeps the membership check from becoming a new
// plaintext source. KnownSecrets remains the only way to obtain raw bytes.
//
// When several mapped secrets occur in b the longest match is reported (ties
// broken deterministically by secret bytes, then placeholder), so the result
// never depends on map iteration order. Empty secrets are never matched, since
// an empty needle would match every buffer. A nil engine reports no match.
func (e *PlaceholderEngine) ContainsKnownSecret(b []byte) (bool, string) {
	if e == nil || len(b) == 0 {
		return false, ""
	}
	snapshot := e.knownSecretSnapshot()
	if len(snapshot) == 0 {
		return false, ""
	}
	var best knownSecretPair
	for _, pair := range snapshot {
		if !bytes.Contains(b, []byte(pair.secret)) {
			continue
		}
		switch {
		case len(pair.secret) > len(best.secret):
			best = pair
		case len(pair.secret) == len(best.secret) && pair.secret < best.secret:
			best = pair
		case len(pair.secret) == len(best.secret) && pair.secret == best.secret &&
			pair.placeholder < best.placeholder:
			best = pair
		}
	}
	if best.secret == "" {
		return false, ""
	}
	return true, best.placeholder
}
