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

	// ErrPackReplayed reports a rule manifest whose serial is below the
	// persisted high-water mark, i.e. a rollback attempt. A serial equal to
	// the mark is an identical re-fetch and is reported separately.
	ErrPackReplayed = errors.New("rules: rule serial at or below high-water mark")
	// ErrPackRevoked reports a rule pack whose serial appears on the signed
	// revocation list. A revoked pack is never activated.
	ErrPackRevoked = errors.New("rules: rule pack revoked")
	// ErrChannelMismatch reports a validly signed document for a different
	// channel than the one requested.
	ErrChannelMismatch = errors.New("rules: document channel does not match the requested channel")
	// ErrBundleHashMismatch reports a bundle whose sha256 differs from the
	// bundle_sha256 the signed manifest points at.
	ErrBundleHashMismatch = errors.New("rules: bundle sha256 does not match the signed manifest")
	// ErrHTTPStatus reports a non-200 response from the rule service.
	ErrHTTPStatus = errors.New("rules: unexpected HTTP status from the rule service")
	// ErrClientConfig reports an incomplete rule-client configuration.
	ErrClientConfig = errors.New("rules: incomplete rule client configuration")
	// ErrCacheMiss reports a serial that is not present in the local cache.
	ErrCacheMiss = errors.New("rules: serial not present in cache")
	// ErrNothingToRollback reports a rollback with no active remote pack.
	ErrNothingToRollback = errors.New("rules: no remote rule pack to roll back from")
)
