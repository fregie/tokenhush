package filter

// compile.go is the load-time rule compiler: it turns a decoded rule document
// into an immutable, concurrency-safe set. The decoder is the first gate; this
// is the second, so a hand-built document cannot skip a load-time invariant.
// Two contracts are enforced here and nowhere else in the document path: a rule
// carries exactly the fields its detector type needs, and no rule that may
// evaluate in the response phase may redact (the same contract is re-asserted
// for directly-registered rules by the public registry). A command rule is
// parse-only: it never enters the compiled set, but its id stays reachable
// through the W3.2 command signal.

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// ErrCompile is the sentinel every load-time rule rejection matches;
// errors.Is(err, ErrCompile) is the classifier, and every rejection names the
// offending rule id.
var ErrCompile = errors.New("filter: compile error")

// ErrDirection is the direction-contract rejection: a rule whose scope
// includes the response phase may not redact. It wraps ErrCompile.
var ErrDirection = fmt.Errorf("%w: direction contract", ErrCompile)

// CompileError is one load-time rule rejection. RuleID names the offending
// rule and Kind is the sentinel errors.Is matches (ErrCompile, or ErrDirection
// for the direction contract).
type CompileError struct {
	RuleID  string
	Kind    error
	Problem string
}

// Error renders `filter: rule <id>: <problem>`.
func (e *CompileError) Error() string { return "filter: rule " + e.RuleID + ": " + e.Problem }

// Unwrap returns the sentinel Kind.
func (e *CompileError) Unwrap() error { return e.Kind }

func compileError(id string, kind error, format string, args ...any) error {
	return &CompileError{RuleID: id, Kind: kind, Problem: fmt.Sprintf(format, args...)}
}

// compiledTypes is the set of rule types that compile to an evaluable rule.
// "command" is deliberately absent: a command rule is parse-only.
var compiledTypes = map[string]bool{
	TypeRegex: true, TypeKeyword: true, TypePrefix: true, TypeEmail: true,
	TypeLuhn: true, TypeJWT: true, TypePEM: true, TypeEntropy: true,
}

// compiledRule is the immutable, validated form of one rule. Exactly one of re,
// keywords or inspect decides how it matches, selected by the rule type: a
// regex rule carries re, a keyword rule carries keywords, and a primitive rule
// carries the bound matcher compileRule built through primitiveBuilders, which
// captures the set's per-primitive byte budget in the inspect closure. Every
// byte slice is owned by the set, never aliased from the document.
type compiledRule struct {
	id         string
	typ        string
	category   string
	scope      Scope
	action     Action
	priority   int
	confidence float64
	re         *regexp.Regexp
	keywords   [][]byte
	fold       bool
	allow      [][]byte
	inspect    func([]byte) []Span
}

// Compiled is a compiled, immutable rule set. It is safe for concurrent use:
// every field is unexported, nothing is mutated after Compile, and the only
// slices it hands out are copies. Command rules are carried as ids, never
// evaluated.
type Compiled struct {
	rules      []compiledRule
	allowlist  [][]byte
	blocklist  [][]byte
	sensitive  *sensitiveMatcher
	commandIDs []string
	budget     int
}

// Compile turns a decoded rule document into a compiled set with the documented
// default per-primitive byte budget. It is CompileWithBudget with
// PrimitiveByteBudgetBytes.
func Compile(doc *Document) (*Compiled, error) {
	return CompileWithBudget(doc, PrimitiveByteBudgetBytes)
}

// CompileWithBudget turns a decoded rule document into a compiled set that
// re-asserts every load-time invariant the decoder enforces (duplicate ids, bad
// regexes, the field set per rule type) so an in-memory document is checked too.
// Primitive-typed rules scan with the given per-primitive byte budget; a
// non-positive budget falls back to the documented default. Every rejection is
// a *CompileError naming the rule id; a command rule is excluded from
// evaluation but its id stays reachable through Commands.
func CompileWithBudget(doc *Document, budget int) (*Compiled, error) {
	if doc == nil {
		return nil, fieldError(ErrInvalidValue, "document", "nil document")
	}
	budget = normalizeBudget(budget)
	set := &Compiled{budget: budget}
	var err error
	if set.allowlist, err = copyLiterals("allowlist", doc.Allowlist); err != nil {
		return nil, err
	}
	if set.blocklist, err = copyLiterals("blocklist", doc.Blocklist); err != nil {
		return nil, err
	}
	if set.sensitive, err = newSensitiveMatcher(doc.SensitiveKeys, doc.Allowlist); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(doc.Rules))
	for i := range doc.Rules {
		rule := &doc.Rules[i]
		if !ruleIDPattern.MatchString(rule.ID) {
			return nil, compileError(rule.ID, ErrCompile, "invalid rule id %q", rule.ID)
		}
		if seen[rule.ID] {
			return nil, compileError(rule.ID, ErrCompile, "duplicate rule id")
		}
		seen[rule.ID] = true
		if rule.Type == TypeCommand || rule.ExcludedFromEvaluation {
			set.commandIDs = append(set.commandIDs, rule.ID)
			continue
		}
		compiled, err := compileRule(rule, fmt.Sprintf("rules[%d]", i), budget)
		if err != nil {
			return nil, err
		}
		set.rules = append(set.rules, compiled)
	}
	sort.SliceStable(set.rules, func(i, j int) bool {
		if set.rules[i].priority != set.rules[j].priority {
			return set.rules[i].priority < set.rules[j].priority
		}
		return set.rules[i].id < set.rules[j].id
	})
	return set, nil
}

// compileRule validates one non-command rule and builds its immutable form.
// path is the rule's document path, so an options rejection the decoder
// re-asserts here names the same location the decoder names. Absent scope,
// category and confidence fall back to the documented defaults, so an
// in-memory document compiles like a decoded one; priority is kept as written
// because zero is a legal explicit priority. budget becomes the rule's
// per-primitive budget; the caller has already normalized it.
func compileRule(rule *RuleDoc, path string, budget int) (compiledRule, error) {
	if !compiledTypes[rule.Type] {
		return compiledRule{}, compileError(rule.ID, ErrCompile, "unknown detector type %q", rule.Type)
	}
	if rule.Type != TypeRegex && rule.Pattern != "" {
		return compiledRule{}, compileError(rule.ID, ErrCompile, "pattern is only valid for a regex rule")
	}
	if rule.Type != TypeKeyword && len(rule.Keywords) > 0 {
		return compiledRule{}, compileError(rule.ID, ErrCompile, "keywords is only valid for a keyword rule")
	}
	if rule.Type != TypeKeyword && rule.CaseSensitive {
		return compiledRule{}, compileError(rule.ID, ErrCompile, "case_sensitive is only valid for a keyword rule")
	}
	scope := rule.Scope
	if scope == "" {
		scope = ScopeRequest
	}
	category := rule.Category
	if category == "" {
		category = CategoryCustom
	}
	confidence := rule.Confidence
	if confidence == 0 {
		confidence = DefaultConfidence
	}
	for _, enum := range []struct {
		value   string
		kind    string
		allowed map[string]bool
	}{
		{string(scope), "scope", scopeValues},
		{category, "category", categories},
		{string(rule.Action), "action", actionValues},
	} {
		if !enum.allowed[enum.value] {
			return compiledRule{}, compileError(rule.ID, ErrCompile, "unknown %s %q", enum.kind, enum.value)
		}
	}
	if confidence <= 0 || confidence > 1 {
		return compiledRule{}, compileError(rule.ID, ErrCompile, "confidence %v must be in (0,1]", confidence)
	}
	if rule.Action == ActionRedact && scope != ScopeRequest {
		return compiledRule{}, compileError(rule.ID, ErrDirection, "a rule that includes the response phase must not redact")
	}
	// The decoder is the first options gate, but a hand-built document skipped
	// it, so the contract is re-asserted here before any matcher reads options.
	// validateRuleOptions also canonicalizes every declared suffix in place, so
	// a builder only ever sees canonical values.
	if err := validateRuleOptions(rule, path); err != nil {
		return compiledRule{}, compileError(rule.ID, ErrCompile, "%v", err)
	}
	r := compiledRule{
		id:         rule.ID,
		typ:        rule.Type,
		category:   category,
		scope:      scope,
		action:     rule.Action,
		priority:   rule.Priority,
		confidence: confidence,
	}
	var err error
	if r.allow, err = copyLiterals(rule.ID+".allowlist", rule.Allowlist); err != nil {
		return compiledRule{}, err
	}
	switch rule.Type {
	case TypeRegex:
		if rule.Pattern == "" {
			return compiledRule{}, compileError(rule.ID, ErrCompile, "a regex rule requires a pattern")
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return compiledRule{}, compileError(rule.ID, ErrCompile, "invalid regex: %v", err)
		}
		if re.MatchString("") {
			return compiledRule{}, compileError(rule.ID, ErrCompile, "regex must not match the empty string")
		}
		r.re = re
	case TypeKeyword:
		if len(rule.Keywords) == 0 {
			return compiledRule{}, compileError(rule.ID, ErrCompile, "a keyword rule requires at least one keyword")
		}
		r.fold = !rule.CaseSensitive
		if r.keywords, err = copyLiterals(rule.ID+".keywords", rule.Keywords); err != nil {
			return compiledRule{}, err
		}
		if r.fold {
			for i := range r.keywords {
				r.keywords[i] = foldASCII(r.keywords[i])
			}
		}
	default:
		matcher, buildErr := primitiveBuilders[rule.Type](rule.Options, budget)
		if buildErr != nil {
			return compiledRule{}, compileError(rule.ID, ErrCompile, "%v", buildErr)
		}
		r.inspect = matcher
	}
	return r, nil
}

// copyLiterals deep-copies one literal list. An empty entry is rejected: it can
// never match and would make the blocklist scan non-terminating.
func copyLiterals(path string, values []string) ([][]byte, error) {
	out := make([][]byte, 0, len(values))
	for i, value := range values {
		if value == "" {
			return nil, fieldError(ErrCompile, fmt.Sprintf("%s[%d]", path, i), "literal must not be empty")
		}
		out = append(out, []byte(value))
	}
	return out, nil
}

// foldASCII returns a copy of value with ASCII upper-case letters lower-cased.
// The copy has exactly the same length, so match offsets stay valid.
func foldASCII(value []byte) []byte {
	out := make([]byte, len(value))
	for i, b := range value {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		out[i] = b
	}
	return out
}

// Len returns the number of evaluable rules in the set; command rules are
// carried by Commands and never counted here.
func (c *Compiled) Len() int {
	if c == nil {
		return 0
	}
	return len(c.rules)
}

// Budget returns the effective per-primitive byte budget the set compiled
// with: the value normalized at compile time, so it is never zero for a live
// set. A nil set reports 0.
func (c *Compiled) Budget() int {
	if c == nil {
		return 0
	}
	return c.budget
}

// Commands returns a copy of the parse-only command signal: the ids of the
// command rules, in declaration order. The returned slice belongs to the
// caller, so the compiled set stays immutable.
func (c *Compiled) Commands() CommandSignal {
	if c == nil {
		return CommandSignal{}
	}
	return CommandSignal{RuleIDs: append([]string(nil), c.commandIDs...), Count: len(c.commandIDs)}
}
