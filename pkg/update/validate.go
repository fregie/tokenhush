// Field-level validation shared by every signed update document. These
// helpers never echo the offending value, so error text is safe to surface.
package update

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// checkField bounds a text field: non-empty, within maxFieldLen, and free of
// control characters that could forge a signing-input line.
func checkField(s string) error {
	if s == "" {
		return errors.New("update: required field is empty")
	}
	if len(s) > maxFieldLen {
		return errors.New("update: field exceeds length limit")
	}
	if strings.ContainsAny(s, "\r\n\x00") {
		return errors.New("update: field contains control characters")
	}
	return nil
}

// checkURL requires an absolute https URL. Plain http is refused so a network
// attacker cannot redirect an update download to an unauthenticated origin.
func checkURL(raw string) error {
	if err := checkField(raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("update: url must be an absolute https URL")
	}
	return nil
}

// checkSHA256 requires exactly 64 hex characters.
func checkSHA256(s string) error {
	if len(s) != 64 {
		return errors.New("update: sha256 must be 64 hex characters")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return errors.New("update: sha256 must be hex")
		}
	}
	return nil
}

// checkWindow requires both bounds and a strictly positive window.
func checkWindow(notBefore, expires time.Time) error {
	if notBefore.IsZero() || expires.IsZero() {
		return errors.New("update: not_before and expires are required")
	}
	if !expires.After(notBefore) {
		return errors.New("update: expires must be after not_before")
	}
	return nil
}

// checkRevoked bounds the revocation lists and each version string.
func checkRevoked(serials []uint64, versions []string) error {
	if len(serials) > maxRevokedEntries || len(versions) > maxRevokedEntries {
		return errors.New("update: too many revoked entries")
	}
	for _, v := range versions {
		if err := checkField(v); err != nil {
			return err
		}
	}
	return nil
}

// normalizeVersion strips a SemVer pre-release ("-...") or build-metadata
// ("+...") suffix so a dev or pre-release build still compares on its numeric
// core: "0.4.0-rc1" -> "0.4.0", "0.0.0-dev" -> "0.0.0". Plain numeric versions
// are unchanged. A value with no numeric core (e.g. "dev") still fails parsing.
func normalizeVersion(s string) string {
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		return s[:i]
	}
	return s
}

// parseVersion parses 1-3 dot-separated numeric components ("1", "1.2",
// "1.2.3") after normalizing away a SemVer pre-release/build-metadata suffix,
// padding missing components with zero. Input with no numeric core is
// ErrMalformed.
func parseVersion(s string) ([3]uint64, error) {
	var out [3]uint64
	parts := strings.Split(normalizeVersion(s), ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, ErrMalformed
	}
	for i, p := range parts {
		if p == "" {
			return out, ErrMalformed
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return out, ErrMalformed
		}
		out[i] = n
	}
	return out, nil
}
