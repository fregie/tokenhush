package filter

// options.go owns the typed per-rule options carried by a decoded rule
// document and the canonicalization of operator-declared email suffixes.
// Options are a typed sub-object per parameterizable detector, never a
// free-form map, so strict decode stays exhaustive and a compiled rule only
// ever reads canonical values. This file deliberately does not consult the
// built-in suffix table: effectiveEmailSuffixes is the single owner of that
// union.

import (
	"fmt"
	"strings"
)

// MaxEmailSuffixes bounds the suffixes one email rule may declare. Decode
// rejects a longer list with ErrBoundExceeded so normalization stays linear in
// a bounded input and a hostile document cannot make the effective-suffix set
// unbounded.
const MaxEmailSuffixes = 256

// RuleOptions is the typed options object of one rule, one sub-object field per
// parameterizable detector. A future detector adds a field here instead of a
// free-form map, so unknown keys keep failing strict decode by name and each
// detector reads only the options it declared.
type RuleOptions struct {
	Email *EmailOptions `json:"email,omitempty"`
}

// EmailOptions parameterizes the email detector. An absent or additive
// Suffixes list extends the built-in suffix set; Replace swaps the built-ins
// for Suffixes only and is permitted for a non-remote local document. Each
// entry is canonicalized by normalizeEmailSuffix before it reaches the matcher.
type EmailOptions struct {
	Suffixes []string `json:"suffixes,omitempty"`
	Replace  bool     `json:"replace,omitempty"`
}

// normalizeEmailSuffix canonicalizes one operator-declared email suffix into
// the form the suffix matcher compares against: surrounding whitespace
// trimmed, lowercased, exactly one leading dot, and the labels otherwise
// untouched, so "Corp.COM", ".com" and "co.uk" all land on one canonical form.
// A single label is legal: the matcher does not require an inner dot.
//
// It rejects malformed input with ErrInvalidValue (empty after trim, internal
// whitespace, a non-ASCII byte, a ".." run in the canonical form) and an
// over-length canonical form with ErrBoundExceeded. The returned errors are
// sentinel-wrapped without a FieldError path: the strict decoder owns the
// document path and adds it at the call site.
func normalizeEmailSuffix(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%w: email suffix is empty after trimming whitespace", ErrInvalidValue)
	}
	s = strings.ToLower(s)
	// TrimPrefix drops the prefix at most once: exactly one leading dot.
	s = strings.TrimPrefix(s, ".")
	canonical := "." + s

	// Check the bound first so every message below is emitted for a bounded
	// value and the canonical length is compared in exactly one place.
	if len(canonical) > MaxLiteralBytes {
		return "", fmt.Errorf("%w: email suffix of %d bytes is above the %d-byte bound", ErrBoundExceeded, len(canonical), MaxLiteralBytes)
	}
	if strings.Contains(canonical, "..") {
		return "", fmt.Errorf("%w: email suffix contains a .. run", ErrInvalidValue)
	}
	if i := strings.IndexAny(canonical, " \t\n\v\f\r"); i >= 0 {
		return "", fmt.Errorf("%w: email suffix contains whitespace at byte %d", ErrInvalidValue, i)
	}
	for i := 0; i < len(canonical); i++ {
		if canonical[i] >= 0x80 {
			return "", fmt.Errorf("%w: email suffix contains a non-ASCII byte at offset %d", ErrInvalidValue, i)
		}
	}
	return canonical, nil
}
