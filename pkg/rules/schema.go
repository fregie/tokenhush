// Package rules owns the data-driven rule content schema, the interpreter that
// evaluates it, and the non-weakening floor that constrains *remote* rule packs
// (ADR-0020). It is the single implementation shared by the Pro local-rules
// plugin and the signed remote-rule client, so detection semantics can never
// drift between the two.
//
// The content schema is the format formerly implemented privately in
// tokenhush-pro/internal/plugins/customrules (schema_version 1): an optional
// global allowlist/blocklist plus regex/keyword rules. The Pro plugin is now a
// thin wrapper that decodes its local file and delegates evaluation here.
package rules

// SchemaVersion is the only rule-content document version this build accepts.
const SchemaVersion = 1

// Rule type identifiers.
const (
	// RuleRegex compiles Pattern as a Go (RE2) regular expression.
	RuleRegex = "regex"
	// RuleKeyword matches the literal Keywords substrings.
	RuleKeyword = "keyword"
)

// Limits bound a rule document so a malformed or hostile payload cannot make
// compile or inspection unbounded. They are deliberately generous for real
// rule sets and fail loudly when exceeded.
const (
	// MaxConfigBytes bounds a config document read from a local file.
	MaxConfigBytes = 1 << 20 // 1 MiB
	// MaxRules bounds the number of rules in one document.
	MaxRules = 256
	// MaxKeywordsPerRule bounds the keywords of one keyword rule.
	MaxKeywordsPerRule = 64
	// MaxListEntries bounds a global allow/block list.
	MaxListEntries = 256
	// MaxRuleAllowlist bounds a per-rule allowlist.
	MaxRuleAllowlist = 64
	// MaxLiteralLength bounds one literal in bytes.
	MaxLiteralLength = 256
	// MaxPatternLength bounds one regex pattern in bytes.
	MaxPatternLength = 1024
	// MaxMatches bounds findings produced from one document. Inspection fails
	// with ErrTooManyMatches rather than truncating silently.
	MaxMatches = 4096
	// DefaultConfidence is reported when a rule omits confidence.
	DefaultConfidence = 0.9
	// MinRuleIDLen / MaxRuleIDLen bound the rule id grammar.
	MaxRuleIDLen = 64
)

// TypeBlocklist is the finding Type reported for blocklist literals.
const TypeBlocklist = "custom:blocklist"

// DefaultPluginID is the registry id the remote-rule interpreter reports when
// the caller does not override it. The Pro local plugin keeps its historical
// "customrules" id via Options.
const DefaultPluginID = "customrules"

// DefaultPriority runs the interpreter after the core built-ins (priority 0)
// and after the Pro credential expansion (priority 20). Priority only orders
// invocation; the policy engine decides actions.
const DefaultPriority = 30

// Config is a validated rule-content document. Use Compile to turn it into an
// Interpreter, or DecodeConfigJSON/Load* (Pro) to decode one first.
type Config struct {
	// SchemaVersion must equal SchemaVersion.
	SchemaVersion int `json:"schema_version"`
	// Allowlist holds global byte-exact literals: a rule match inside an
	// occurrence is suppressed. Blocklist hits are never suppressed.
	Allowlist []string `json:"allowlist,omitempty"`
	// Blocklist holds global byte-exact literals; every occurrence becomes a
	// Block finding with confidence 1.
	Blocklist []string `json:"blocklist,omitempty"`
	// Rules are the regex/keyword detection rules, in priority-neutral
	// declaration order; findings are ordered by span, not declaration.
	Rules []Rule `json:"rules,omitempty"`
}

// Rule is one detection rule. Every rule carries a RuleID (the JSON/Go id)
// that is stamped into the finding and its Meta, so a hit is auditable back to
// the exact rule that caused it (ADR-0020 §4).
type Rule struct {
	// ID names the rule; findings report Type "custom:<id>". Required,
	// unique, ^[a-z][a-z0-9._-]{0,63}$.
	ID string `json:"id"`
	// Type is RuleRegex or RuleKeyword.
	Type string `json:"type"`
	// Pattern is the RE2 pattern for a regex rule; forbidden for keyword
	// rules. It must not match the empty string.
	Pattern string `json:"pattern,omitempty"`
	// Keywords are the literal substrings for a keyword rule; forbidden for
	// regex rules. At least one is required.
	Keywords []string `json:"keywords,omitempty"`
	// Action is "warn", "redact" or "block".
	Action string `json:"action"`
	// Confidence is reported on every finding; nil defaults to 0.9. A
	// present value must be in (0,1].
	Confidence *float64 `json:"confidence,omitempty"`
	// CaseSensitive disables ASCII case folding for keyword matching. It is
	// only valid for keyword rules and defaults to false (case-insensitive).
	CaseSensitive bool `json:"case_sensitive,omitempty"`
	// Allowlist holds byte-exact literals that suppress this rule's matches
	// (including a block-action rule's matches).
	Allowlist []string `json:"allowlist,omitempty"`
}
