package rules

// Typed errors. Every load/compile failure wraps one of these, so callers
// classify with errors.Is; none of them is a sentinel to compare directly.

import "errors"

var (
	// ErrParse reports a document that is not valid JSON, is outside the
	// strict YAML subset, has an unknown field, a duplicate key or a value of
	// the wrong type.
	ErrParse = errors.New("rules: invalid config document")
	// ErrUnknownField reports a JSON/YAML key outside the schema. It always
	// also matches ErrParse.
	ErrUnknownField = errors.New("rules: unknown config field")
	// ErrSchemaVersion reports a missing or unsupported schema_version.
	ErrSchemaVersion = errors.New("rules: unsupported schema version")
	// ErrNoRules reports a config that declares neither a rule nor a
	// blocklist entry (an allowlist alone can never suppress anything).
	ErrNoRules = errors.New("rules: config declares no rules or blocklist")
	// ErrInvalidRule reports an invalid rule definition or cross-rule
	// conflict (bad id, duplicate id, bad action, wrong fields for the rule
	// type, ...).
	ErrInvalidRule = errors.New("rules: invalid rule")
	// ErrInvalidRegex reports a regex Pattern that does not compile or can
	// match the empty string.
	ErrInvalidRegex = errors.New("rules: invalid regular expression")
	// ErrInvalidLiteral reports an allow/block literal that is empty, padded,
	// too long, control-bearing or duplicated.
	ErrInvalidLiteral = errors.New("rules: invalid literal")
	// ErrTooManyMatches reports a document whose inspection exceeded the
	// per-document finding bound. The interpreter fails loudly instead of
	// truncating findings silently.
	ErrTooManyMatches = errors.New("rules: match limit exceeded")
)
