package filter

// schema.go is the strict rule/bundle document schema and its single decoder.
// One document shape covers both a local operator document and a signed remote
// pack: a document is a remote pack exactly when the envelope's serial and
// key_id are both present. Unknown fields are rejected by name, every bound
// fails loudly with a typed error, and a command rule decodes but is marked
// parse-only (pkg/supply owns its activation policy).

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// MaxMatches bounds the findings produced from one document. Inspection fails
// with a typed error rather than truncating silently.
const MaxMatches = 4096

// Document bounds. They are deliberately generous for real rule sets and fail
// loudly with ErrBoundExceeded, so a malformed or hostile document cannot make
// decode or evaluation unbounded. Defaults apply only when the key is absent.
// Each bound is part of the frozen extension API pinned by
// internal/guards/shape_guard_test.go and pkg/filter/external_plugin_test.go.
const (
	MaxRules, MaxKeywordsPerRule                     = 256, 64
	MaxListEntries, MaxRuleAllowlist                 = 256, 64
	MaxLiteralBytes, MaxPatternBytes                 = 256, 1024
	MaxCommandVerbsPerRule, MaxCommandTargetsPerRule = 16, 16
	DefaultPriority, DefaultConfidence               = 100, 0.9
)

// Frozen wire identifiers: rule types, categories, scopes and actions. A value
// outside these sets is rejected at decode time. Every identifier is part of
// the frozen extension API pinned by pkg/filter/external_plugin_test.go and
// docs/plugins.md, and is a valid rule-document value.
const (
	TypeRegex, TypeKeyword, TypePrefix, TypeEmail, TypeLuhn, TypeJWT, TypePEM, TypeEntropy, TypeCommand = "regex", "keyword", "prefix", "email", "luhn", "jwt", "pem", "entropy", "command"

	CategoryAPIKey, CategoryEmail, CategoryCreditCard, CategoryPrivateKey, CategoryJWT, CategoryHighEntropy, CategoryCustom = "api_key", "email", "credit_card", "private_key", "jwt", "high_entropy", "custom"

	ScopeRequest, ScopeResponse, ScopeBoth             Scope  = "request", "response", "both"
	ActionAllow, ActionWarn, ActionRedact, ActionBlock Action = "allow", "warn", "redact", "block"
)

// Scope is the content phase(s) a rule may evaluate in. Only the request phase
// may substitute a placeholder; the direction contract is enforced at compile
// time (W3.4) and at registration (W3.6).
type Scope string

// Action is the decision a rule's finding carries, in ascending precedence
// order.
type Action string

// Span is a half-open byte range [Start, End) inside a leaf.
type Span struct{ Start, End int }

// Rule is the frozen exported rule contract: the shape guard and the public
// registry both assert exactly this method set, so a refactor cannot widen the
// extension point.
type Rule interface {
	ID() string
	Type() string
	Category() string
	Scope() Scope
	Action() Action
	Priority() int
	Confidence() float64
	Inspect(leaf []byte) []Span
}

// Typed schema error kinds. errors.Is matches the sentinel; FieldError names
// the offending document path. They are exported because the registry, compile
// and floor APIs surface them to plugin authors (pinned by
// pkg/filter/external_plugin_test.go and pkg/filter/schema_test.go).
var ErrUnknownField = errors.New("filter: unknown field")

var ErrBoundExceeded = errors.New("filter: bound exceeded")

var ErrInvalidValue = errors.New("filter: invalid value")

// FieldError is one strict-decode failure. Path is the document path of the
// offending value (for example rules[0].keywords), and Unwrap returns the
// sentinel Kind so callers branch with errors.Is.
type FieldError struct {
	Kind    error
	Path    string
	Problem string
}

// Error renders `filter: <path>: <problem>`; a pathless error drops the path.
func (e *FieldError) Error() string {
	if e.Path == "" {
		return "filter: " + e.Problem
	}
	return "filter: " + e.Path + ": " + e.Problem
}

// Unwrap returns the sentinel Kind.
func (e *FieldError) Unwrap() error { return e.Kind }

// defaulted returns value when the key is present in the raw document, and the
// fallback only when the key is absent, so an explicit value always wins.
func defaulted[T any](value T, fields map[string]json.RawMessage, key string, fallback T) T {
	if _, ok := fields[key]; ok {
		return value
	}
	return fallback
}

// Document is one decoded rule document: the optional bundle envelope plus the
// content present in both shapes. RemotePack reports whether serial and key_id
// were both present, which is what makes a document a signed remote pack.
type Document struct {
	Channel            string          `json:"channel"`
	SchemaVersion      int             `json:"schema_version"`
	MinBinaryVersion   string          `json:"min_binary_version"`
	Serial             uint64          `json:"serial"`
	KeyID              string          `json:"key_id"`
	NotBefore          time.Time       `json:"not_before"`
	Expires            time.Time       `json:"expires"`
	Detectors          map[string]bool `json:"detectors,omitempty"`
	DisabledCategories []string        `json:"disabled_categories,omitempty"`
	Allowlist          []string        `json:"allowlist,omitempty"`
	Blocklist          []string        `json:"blocklist,omitempty"`
	// SensitiveKeys is the optional Feature-A block: immediate object member
	// key names whose values are redacted on the request path. It carries no
	// action (the effect is fixed) and is additive: absent means no matcher.
	SensitiveKeys *SensitiveKeysPayload `json:"sensitive_keys,omitempty"`
	Rules         []RuleDoc             `json:"rules,omitempty"`

	// RemotePack is true when both envelope keys were present.
	RemotePack bool `json:"-"`
}

// RuleDoc is one decoded rule. It is the wire superset: the legacy v1 field
// names (pattern, keywords, case_sensitive, command, ...) sit beside the
// rewrite's category/scope/priority extensions, and every field is optional at
// decode time so a real v1 pack decodes unchanged.
type RuleDoc struct {
	ID              string   `json:"id"`
	Type            string   `json:"type"`
	Category        string   `json:"category,omitempty"`
	Scope           Scope    `json:"scope,omitempty"`
	Action          Action   `json:"action"`
	Priority        int      `json:"priority,omitempty"`
	Pattern         string   `json:"pattern,omitempty"`
	Keywords        []string `json:"keywords,omitempty"`
	CaseSensitive   bool     `json:"case_sensitive,omitempty"`
	Confidence      float64  `json:"confidence,omitempty"`
	Allowlist       []string `json:"allowlist,omitempty"`
	MinDigits       int      `json:"min_digits,omitempty"`
	MaxDigits       int      `json:"max_digits,omitempty"`
	Alphabet        string   `json:"alphabet,omitempty"`
	MinLength       int      `json:"min_length,omitempty"`
	MinEntropy      float64  `json:"min_entropy,omitempty"`
	PureHexExcluded bool     `json:"pure_hex_excluded,omitempty"`
	PEMHeaders      []string `json:"pem_headers,omitempty"`

	// Options is the typed per-detector settings object. strictDecodeRuleOptions
	// rejects unknown keys inside it and validateRuleOptions requires a present
	// sub-object to match Type, so a rule carries settings only for its own
	// detector and never an accepted-but-ignored key.
	Options *RuleOptions `json:"options,omitempty"`

	// Legacy command-rule fields: parsed so they can be detected and signalled,
	// never evaluated.
	Command    string   `json:"command,omitempty"`
	Subcommand string   `json:"subcommand,omitempty"`
	Verbs      []string `json:"verbs,omitempty"`
	Targets    []string `json:"targets,omitempty"`

	// ExcludedFromEvaluation marks a parse-only rule (type command). W3.5 must
	// skip every rule with this set.
	ExcludedFromEvaluation bool `json:"-"`
}

var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

var ruleTypes = map[string]bool{"regex": true, "keyword": true, "prefix": true, "email": true, "luhn": true, "jwt": true, "pem": true, "entropy": true, "command": true}

var categories = map[string]bool{"api_key": true, "email": true, "credit_card": true, "private_key": true, "jwt": true, "high_entropy": true, "custom": true}

var scopeValues = map[string]bool{"request": true, "response": true, "both": true}

var actionValues = map[string]bool{"allow": true, "warn": true, "redact": true, "block": true}

// documentFields and ruleFields are the complete allowed key sets; every other
// key is rejected by name with ErrUnknownField.
var documentFields = map[string]bool{"channel": true, "schema_version": true, "min_binary_version": true, "serial": true, "key_id": true, "not_before": true, "expires": true, "detectors": true, "disabled_categories": true, "allowlist": true, "blocklist": true, "sensitive_keys": true, "rules": true}

var ruleFields = map[string]bool{"id": true, "type": true, "category": true, "scope": true, "action": true, "priority": true, "pattern": true, "keywords": true, "case_sensitive": true, "confidence": true, "allowlist": true, "min_digits": true, "max_digits": true, "alphabet": true, "min_length": true, "min_entropy": true, "pure_hex_excluded": true, "pem_headers": true, "command": true, "subcommand": true, "verbs": true, "targets": true, "options": true}

// DecodeDocument strictly decodes one rule document, local or remote pack. The
// presence of serial and key_id makes a document a remote pack, and the two
// must appear together. Unknown fields, unknown enum values, an empty-matching
// regex and every document bound are rejected with a typed error naming the
// document path.
func DecodeDocument(data []byte) (*Document, error) {
	fields, err := strictObject(data, documentFields, "document")
	if err != nil {
		return nil, err
	}
	_, hasSerial := fields["serial"]
	_, hasKeyID := fields["key_id"]
	if hasSerial != hasKeyID {
		return nil, fieldError(ErrInvalidValue, "serial/key_id", "serial and key_id must be present together")
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fieldError(ErrInvalidValue, "document", "%v", err)
	}
	doc.RemotePack = hasSerial
	if err := validateSensitiveFields(fields); err != nil {
		return nil, err
	}
	if err := finalizeDocument(&doc, fields["rules"]); err != nil {
		return nil, err
	}
	return &doc, nil
}

// strictObject decodes data as a JSON object and rejects every key outside
// allowed, naming the offending key as path.key so nested failures are exact.
func strictObject(data []byte, allowed map[string]bool, path string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fieldError(ErrInvalidValue, path, "expected a JSON object: %v", err)
	}
	if fields == nil {
		return nil, fieldError(ErrInvalidValue, path, "expected a JSON object")
	}
	for key := range fields {
		if !allowed[key] {
			return nil, fieldError(ErrUnknownField, path+"."+key, "unknown field")
		}
	}
	return fields, nil
}

// finalizeDocument walks the raw rules array (rejecting unknown rule fields by
// path and applying the presence-only defaults), then enforces the global list
// bounds, the rule-count bound and every per-rule invariant.
func finalizeDocument(doc *Document, rawRules json.RawMessage) error {
	if len(rawRules) > 0 {
		var items []json.RawMessage
		if err := json.Unmarshal(rawRules, &items); err != nil {
			return fieldError(ErrInvalidValue, "rules", "%v", err)
		}
		for i, item := range items {
			path := fmt.Sprintf("rules[%d]", i)
			fields, err := strictObject(item, ruleFields, path)
			if err != nil {
				return err
			}
			if rawOptions, ok := fields["options"]; ok {
				if err := strictDecodeRuleOptions(rawOptions, path); err != nil {
					return err
				}
			}
			rule := &doc.Rules[i]
			rule.Category = defaulted(rule.Category, fields, "category", CategoryCustom)
			rule.Scope = defaulted(rule.Scope, fields, "scope", ScopeRequest)
			rule.Priority = defaulted(rule.Priority, fields, "priority", DefaultPriority)
			rule.Confidence = defaulted(rule.Confidence, fields, "confidence", DefaultConfidence)
			if rule.Type == TypeCommand {
				rule.ExcludedFromEvaluation = true
			}
		}
	}
	if err := checkLiterals(doc.Allowlist, MaxListEntries, "allowlist"); err != nil {
		return err
	}
	if err := checkLiterals(doc.Blocklist, MaxListEntries, "blocklist"); err != nil {
		return err
	}
	if len(doc.Rules) > MaxRules {
		return fieldError(ErrBoundExceeded, "rules", "%d rules exceed the %d-rule bound", len(doc.Rules), MaxRules)
	}
	ids := make(map[string]bool, len(doc.Rules))
	for i := range doc.Rules {
		if err := validateRule(&doc.Rules[i], i, ids); err != nil {
			return err
		}
	}
	return nil
}

// validateRule checks the id grammar and uniqueness, every enum, every bound
// and the regex empty-match rule. A command rule is parse-only: its four
// command fields are bounded, but its evaluation fields are never required, so
// a legacy command document always decodes. Activation policy is pkg/supply's.
func validateRule(rule *RuleDoc, index int, ids map[string]bool) error {
	path := fmt.Sprintf("rules[%d]", index)
	if !ruleIDPattern.MatchString(rule.ID) || ids[rule.ID] {
		return fieldError(ErrInvalidValue, path+".id", "id %q must match %s and be unique", rule.ID, ruleIDPattern)
	}
	ids[rule.ID] = true
	for _, list := range []struct {
		values     []string
		maxEntries int
		suffix     string
	}{
		{rule.Allowlist, MaxRuleAllowlist, ".allowlist"},
		{rule.Keywords, MaxKeywordsPerRule, ".keywords"},
		{rule.Verbs, MaxCommandVerbsPerRule, ".verbs"},
		{rule.Targets, MaxCommandTargetsPerRule, ".targets"},
		{rule.PEMHeaders, MaxListEntries, ".pem_headers"},
	} {
		if err := checkLiterals(list.values, list.maxEntries, path+list.suffix); err != nil {
			return err
		}
	}
	if len(rule.Pattern) > MaxPatternBytes {
		return fieldError(ErrBoundExceeded, path+".pattern", "pattern is %d bytes, above the %d-byte bound", len(rule.Pattern), MaxPatternBytes)
	}
	if err := validateRuleOptions(rule, path); err != nil {
		return err
	}
	if rule.Type == TypeCommand {
		return nil
	}
	for _, enum := range []struct {
		value   string
		suffix  string
		kind    string
		allowed map[string]bool
	}{
		{rule.Type, ".type", "rule type", ruleTypes},
		{rule.Category, ".category", "category", categories},
		{string(rule.Scope), ".scope", "scope", scopeValues},
		{string(rule.Action), ".action", "action", actionValues},
	} {
		if !enum.allowed[enum.value] {
			return fieldError(ErrInvalidValue, path+enum.suffix, "unknown %s %q", enum.kind, enum.value)
		}
	}
	if rule.Confidence <= 0 || rule.Confidence > 1 {
		return fieldError(ErrInvalidValue, path+".confidence", "confidence %v must be in (0,1]", rule.Confidence)
	}
	if rule.Type != TypeRegex {
		return nil
	}
	if compiled, err := regexp.Compile(rule.Pattern); err != nil {
		return fieldError(ErrInvalidValue, path+".pattern", "invalid regex: %v", err)
	} else if compiled.MatchString("") {
		return fieldError(ErrInvalidValue, path+".pattern", "regex must not match the empty string")
	}
	return nil
}
