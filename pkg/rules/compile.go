package rules

// Validation and compilation of a Config into the immutable Inspector state.

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/fregie/tokenhush/pkg/extension"
)

// Compile validates cfg and returns the compiled, immutable Interpreter. It
// rejects (with errors.Is-testable typed errors) a nil config, a missing or
// unsupported schema_version, a config with no rules or lists, invalid or
// duplicate rules, non-compiling regexes, empty-matching regexes and invalid
// allow/block literals.
//
// opts tune identity and ordering only; rule semantics never depend on them.
func Compile(cfg *Config, opts Options) (*Interpreter, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: nil config", ErrParse)
	}
	if cfg.SchemaVersion == 0 {
		return nil, fmt.Errorf("%w: schema_version is required (want %d)", ErrSchemaVersion, SchemaVersion)
	}
	if cfg.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrSchemaVersion, cfg.SchemaVersion, SchemaVersion)
	}
	if len(cfg.Rules) == 0 && len(cfg.Blocklist) == 0 {
		return nil, fmt.Errorf("%w: declare at least one rule or blocklist entry", ErrNoRules)
	}
	allow, err := compileLiteralList("allowlist", cfg.Allowlist, MaxListEntries)
	if err != nil {
		return nil, err
	}
	blocked, err := compileLiteralList("blocklist", cfg.Blocklist, MaxListEntries)
	if err != nil {
		return nil, err
	}
	if err := checkListConflict(allow, blocked); err != nil {
		return nil, err
	}
	rules, err := compileRules(cfg.Rules)
	if err != nil {
		return nil, err
	}
	canBlock := len(blocked) > 0
	for i := range rules {
		if rules[i].action == extension.Block {
			canBlock = true
		}
	}
	pluginID := opts.PluginID
	if pluginID == "" {
		pluginID = DefaultPluginID
	}
	priority := opts.Priority
	if priority == 0 {
		priority = DefaultPriority
	}
	return &Interpreter{
		rules:     rules,
		allowlist: allow,
		blocklist: blocked,
		canBlock:  canBlock,
		pluginID:  pluginID,
		priority:  priority,
	}, nil
}

// compileRules compiles every rule, rejecting duplicate ids and too many rules.
func compileRules(defs []Rule) ([]compiledRule, error) {
	if len(defs) > MaxRules {
		return nil, fmt.Errorf("%w: %d rules exceed the limit of %d", ErrInvalidRule, len(defs), MaxRules)
	}
	out := make([]compiledRule, 0, len(defs))
	seen := make(map[string]struct{}, len(defs))
	for i := range defs {
		r, err := compileRule(defs[i])
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		if _, dup := seen[r.id]; dup {
			return nil, fmt.Errorf("%w: duplicate rule id %q", ErrInvalidRule, r.id)
		}
		seen[r.id] = struct{}{}
		out = append(out, r)
	}
	return out, nil
}

// compileRule compiles one rule definition.
func compileRule(def Rule) (compiledRule, error) {
	if err := validateRuleID(def.ID); err != nil {
		return compiledRule{}, err
	}
	action, err := parseAction(def.Action)
	if err != nil {
		return compiledRule{}, fmt.Errorf("rule %q: %w", def.ID, err)
	}
	confidence, err := parseConfidence(def.ID, def.Confidence)
	if err != nil {
		return compiledRule{}, err
	}
	allow, err := compileLiteralList(fmt.Sprintf("rule %q allowlist", def.ID), def.Allowlist, MaxRuleAllowlist)
	if err != nil {
		return compiledRule{}, err
	}
	r := compiledRule{
		id:         def.ID,
		finding:    "custom:" + def.ID,
		action:     action,
		confidence: confidence,
		allow:      allow,
	}
	switch def.Type {
	case RuleRegex:
		if err := compileRegexRule(&r, def); err != nil {
			return compiledRule{}, err
		}
	case RuleKeyword:
		if err := compileKeywordRule(&r, def); err != nil {
			return compiledRule{}, err
		}
	default:
		return compiledRule{}, fmt.Errorf("%w: rule %q: type must be %q or %q, got %q",
			ErrInvalidRule, def.ID, RuleRegex, RuleKeyword, def.Type)
	}
	return r, nil
}

// compileRegexRule fills the regex half of r, rejecting invalid patterns and
// patterns that can match the empty string.
func compileRegexRule(r *compiledRule, def Rule) error {
	if def.Pattern == "" {
		return fmt.Errorf("%w: rule %q: pattern is required for a regex rule", ErrInvalidRule, def.ID)
	}
	if len(def.Keywords) > 0 {
		return fmt.Errorf("%w: rule %q: keywords is only valid for a keyword rule", ErrInvalidRule, def.ID)
	}
	if def.CaseSensitive {
		return fmt.Errorf("%w: rule %q: case_sensitive is only valid for a keyword rule", ErrInvalidRule, def.ID)
	}
	if len(def.Pattern) > MaxPatternLength {
		return fmt.Errorf("%w: rule %q: pattern exceeds %d bytes", ErrInvalidRule, def.ID, MaxPatternLength)
	}
	re, err := regexp.Compile(def.Pattern)
	if err != nil {
		return fmt.Errorf("%w: rule %q: %v", ErrInvalidRegex, def.ID, err)
	}
	if re.MatchString("") {
		return fmt.Errorf("%w: rule %q: pattern matches the empty string", ErrInvalidRegex, def.ID)
	}
	r.kind = RuleRegex
	r.re = re
	return nil
}

// compileKeywordRule fills the keyword half of r. Keywords are validated like
// allow/block literals; with case folding enabled they are stored folded and
// duplicates are detected after folding.
func compileKeywordRule(r *compiledRule, def Rule) error {
	if def.Pattern != "" {
		return fmt.Errorf("%w: rule %q: pattern is only valid for a regex rule", ErrInvalidRule, def.ID)
	}
	if len(def.Keywords) == 0 {
		return fmt.Errorf("%w: rule %q: keywords must contain at least one literal", ErrInvalidRule, def.ID)
	}
	if len(def.Keywords) > MaxKeywordsPerRule {
		return fmt.Errorf("%w: rule %q: %d keywords exceed the limit of %d", ErrInvalidRule, def.ID, len(def.Keywords), MaxKeywordsPerRule)
	}
	fold := !def.CaseSensitive
	r.kind = RuleKeyword
	r.fold = fold
	r.keywords = make([][]byte, 0, len(def.Keywords))
	seen := make(map[string]struct{}, len(def.Keywords))
	for _, kw := range def.Keywords {
		b, err := compileLiteral(fmt.Sprintf("rule %q keywords", def.ID), kw)
		if err != nil {
			return err
		}
		key := string(b)
		if fold {
			key = string(asciiFold(b))
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: rule %q: duplicate keyword %q", ErrInvalidLiteral, def.ID, kw)
		}
		seen[key] = struct{}{}
		if fold {
			b = asciiFold(b)
		}
		r.keywords = append(r.keywords, b)
	}
	return nil
}

// parseAction maps a config action to the core action, rejecting unknown ones.
func parseAction(s string) (extension.Action, error) {
	switch extension.Action(s) {
	case extension.Warn, extension.Redact, extension.Block:
		return extension.Action(s), nil
	default:
		return "", fmt.Errorf("%w: action must be warn|redact|block, got %q", ErrInvalidRule, s)
	}
}

// parseConfidence applies the default and enforces (0,1].
func parseConfidence(id string, v *float64) (float64, error) {
	if v == nil {
		return DefaultConfidence, nil
	}
	if math.IsNaN(*v) || *v <= 0 || *v > 1 {
		return 0, fmt.Errorf("%w: rule %q: confidence must be in (0,1], got %v", ErrInvalidRule, id, *v)
	}
	return *v, nil
}

// validateRuleID enforces the lowercase identifier grammar that is stamped
// into the finding type.
func validateRuleID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: id is required", ErrInvalidRule)
	}
	if len(id) > 64 {
		return fmt.Errorf("%w: id %q exceeds 64 bytes", ErrInvalidRule, id)
	}
	if id == "blocklist" {
		return fmt.Errorf("%w: id %q is reserved for the blocklist finding type", ErrInvalidRule, id)
	}
	if id[0] < 'a' || id[0] > 'z' {
		return fmt.Errorf("%w: id %q must start with a lowercase letter", ErrInvalidRule, id)
	}
	for i := 1; i < len(id); i++ {
		c := id[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			return fmt.Errorf("%w: id %q may only contain lowercase letters, digits, '.', '_' and '-'", ErrInvalidRule, id)
		}
	}
	return nil
}

// compileLiteralList validates and copies a list of byte-exact literals,
// rejecting empties, padding, control characters, oversized entries and exact
// duplicates.
func compileLiteralList(where string, items []string, max int) ([][]byte, error) {
	if len(items) > max {
		return nil, fmt.Errorf("%w: %s: %d entries exceed the limit of %d", ErrInvalidLiteral, where, len(items), max)
	}
	out := make([][]byte, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		b, err := compileLiteral(where, item)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[string(b)]; dup {
			return nil, fmt.Errorf("%w: %s: duplicate literal %q", ErrInvalidLiteral, where, item)
		}
		seen[string(b)] = struct{}{}
		out = append(out, b)
	}
	return out, nil
}

// compileLiteral validates one literal.
func compileLiteral(where, lit string) ([]byte, error) {
	if lit == "" {
		return nil, fmt.Errorf("%w: %s: literal must not be empty", ErrInvalidLiteral, where)
	}
	if len(lit) > MaxLiteralLength {
		return nil, fmt.Errorf("%w: %s: literal exceeds %d bytes", ErrInvalidLiteral, where, MaxLiteralLength)
	}
	if strings.TrimSpace(lit) != lit {
		return nil, fmt.Errorf("%w: %s: literal %q must not have leading or trailing whitespace", ErrInvalidLiteral, where, lit)
	}
	for _, rr := range lit {
		if unicode.IsControl(rr) {
			return nil, fmt.Errorf("%w: %s: literal %q must not contain control characters", ErrInvalidLiteral, where, lit)
		}
	}
	return []byte(lit), nil
}

// checkListConflict rejects a config where a blocklist literal and an
// allowlist literal overlap, because the user's intent (allow vs always
// block) would be ambiguous; blocklist hits are otherwise never suppressed.
func checkListConflict(allow, blocked [][]byte) error {
	for _, b := range blocked {
		for _, a := range allow {
			if bytes.Contains(a, b) || bytes.Contains(b, a) {
				return fmt.Errorf("%w: blocklist literal %q conflicts with allowlist literal %q", ErrInvalidRule, b, a)
			}
		}
	}
	return nil
}
