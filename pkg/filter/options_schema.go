package filter

// options_schema.go owns strict decode and validation of the typed per-rule
// options object: unknown option keys are rejected by name, a present
// sub-object must match its rule's type, and email suffixes are bounds-checked
// and canonicalized in place before any compiled rule can read them. The file
// also carries the two schema helpers relocated from schema.go by pure move, so
// schema.go stays under the 250-pure-LOC ceiling.

import (
	"encoding/json"
	"errors"
	"fmt"
)

// optionsFields and emailOptionFields are the complete allowed key sets of the
// options object and of its email sub-object; every other key is rejected by
// name with ErrUnknownField. A future detector extends these maps only
// alongside a schema_version bump; this change bumps nothing.
var optionsFields = map[string]bool{"email": true}

var emailOptionFields = map[string]bool{"suffixes": true, "replace": true}

// strictDecodeRuleOptions strictly decodes the raw value of a rule's `options`
// key: the options object and each present sub-object are checked for unknown
// keys by document path, and a non-object value is rejected. It receives ONLY
// that raw value, never the whole rule object, so it stays a pure key check;
// the typed struct is already filled by the document unmarshal that preceded
// it, and the strict check still governs rejection of unknown nested keys.
func strictDecodeRuleOptions(rawOptions json.RawMessage, path string) error {
	fields, err := strictObject(rawOptions, optionsFields, path+".options")
	if err != nil {
		return err
	}
	if rawEmail, ok := fields["email"]; ok {
		if _, err := strictObject(rawEmail, emailOptionFields, path+".options.email"); err != nil {
			return err
		}
	}
	return nil
}

// validateRuleOptions enforces the typed half of the options contract on an
// already-decoded rule: nil options are allowed; a present email sub-object
// requires an email rule, so options are rejected on every other type including
// command; the suffix list is bounds-checked and every entry is replaced by its
// normalizeEmailSuffix canonical form, so downstream only ever sees canonical
// suffixes. An explicit empty options object declares no settings and is
// accepted on every rule type. The caller runs this before the command
// early-return, so a parse-only rule cannot smuggle settings either.
func validateRuleOptions(rule *RuleDoc, path string) error {
	if rule.Options == nil || rule.Options.Email == nil {
		return nil
	}
	if rule.Type != TypeEmail {
		return fieldError(ErrInvalidValue, path+".options.email", "email options are only valid on an email rule, got type %q", rule.Type)
	}
	email := rule.Options.Email
	if err := checkLiterals(email.Suffixes, MaxEmailSuffixes, path+".options.email.suffixes"); err != nil {
		return err
	}
	for i, suffix := range email.Suffixes {
		canonical, err := normalizeEmailSuffix(suffix)
		if err != nil {
			// normalizeEmailSuffix wraps a sentinel without a document path;
			// keep its kind (so a malformed suffix stays ErrInvalidValue and an
			// over-length one stays ErrBoundExceeded) and add the
			// index-named path here.
			kind := ErrInvalidValue
			if errors.Is(err, ErrBoundExceeded) {
				kind = ErrBoundExceeded
			}
			return fieldError(kind, fmt.Sprintf("%s.options.email.suffixes[%d]", path, i), "%v", err)
		}
		email.Suffixes[i] = canonical
	}
	return nil
}

// checkLiterals enforces the entry-count bound and the per-literal byte bound.
func checkLiterals(values []string, maxEntries int, path string) error {
	if len(values) > maxEntries {
		return fieldError(ErrBoundExceeded, path, "%d entries exceed the %d-entry bound", len(values), maxEntries)
	}
	for i, value := range values {
		if len(value) > MaxLiteralBytes {
			return fieldError(ErrBoundExceeded, fmt.Sprintf("%s[%d]", path, i), "literal is %d bytes, above the %d-byte bound", len(value), MaxLiteralBytes)
		}
	}
	return nil
}

func fieldError(kind error, path, format string, args ...any) error {
	return &FieldError{Kind: kind, Path: path, Problem: fmt.Sprintf(format, args...)}
}
