package filter

// primitive_email.go is the email-address detector: an address matches only
// when its local and domain parts are both non-empty, neither contains a dot
// run, and its domain ends at one of the effective suffixes, so
// "a..b@example.com" and "@example.com" are not addresses and neither is
// "user@example". The suffix set is an explicit parameter of the algorithm:
// the built-in rule matches the package public-suffix table and an
// options-carrying rule matches the effective set effectiveEmailSuffixes
// returns.

import (
	"bytes"
	"regexp"
)

// emailConfidence is the fixed confidence of the email rule: mail addresses
// are frequently legitimate, so it is the lowest of the six.
const emailConfidence = 0.8

// emailPattern requires a local part and a dotted domain ending in a 2+ letter
// TLD, so "user@localhost" and "user@example" never match.
var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// findEmailSpans returns email-shaped spans whose domain matches one of the
// canonical suffixes: a candidate with a dot run anywhere, a candidate whose
// parts cannot be split at one '@', and a candidate whose domain is not under
// any suffix are all rejected and produce no span.
func findEmailSpans(content []byte, suffixes []string) []Span {
	matches := emailPattern.FindAllIndex(content, -1)
	spans := make([]Span, 0, len(matches))
	for _, m := range matches {
		candidate := content[m[0]:m[1]]
		if bytes.Contains(candidate, []byte("..")) {
			continue
		}
		local, domain, ok := splitEmail(candidate)
		if !ok || len(local) == 0 || len(domain) == 0 {
			continue
		}
		if !domainHasSuffix(string(domain), suffixes) {
			continue
		}
		spans = append(spans, Span{Start: m[0], End: m[1]})
	}
	return spans
}

// splitEmail splits candidate at its single '@'. It reports false for an empty
// local or domain part and for a second '@'.
func splitEmail(candidate []byte) (local, domain []byte, ok bool) {
	at := bytes.IndexByte(candidate, '@')
	if at <= 0 || at == len(candidate)-1 {
		return nil, nil, false
	}
	if bytes.IndexByte(candidate[at+1:], '@') >= 0 {
		return nil, nil, false
	}
	return candidate[:at], candidate[at+1:], true
}

// inspectEmailWithSuffixes runs the email algorithm over content truncated to
// budget, gated by the caller's canonical suffix set. It is the one shared
// entry the default rule and every options-carrying matcher run through, so
// budget truncation and the candidate shape checks are identical in both.
func inspectEmailWithSuffixes(content []byte, budget int, suffixes []string) []Span {
	return findEmailSpans(primitiveInput(content, budget), suffixes)
}

// emailRule is the email-address rule. matcher is nil for the default rule,
// whose Inspect path goes straight to inspectEmail and thus reads the package
// public-suffix table at call time; an options-carrying rule stores the
// closure buildEmailMatcher returned over its effective suffix set.
type emailRule struct {
	budget  int
	matcher func([]byte) []Span
}

// NewEmailRule returns the built-in rule that flags email addresses with the
// documented default byte budget.
func NewEmailRule() Rule { return NewEmailRuleBudget(PrimitiveByteBudgetBytes) }

// NewEmailRuleBudget returns the email rule with an explicit per-call byte
// budget.
func NewEmailRuleBudget(budget int) Rule { return emailRule{budget: normalizeBudget(budget)} }

// NewEmailRuleWithOptions returns the email rule matching opts' effective
// suffix set: the built-in table extended by the declared suffixes, or
// replaced by them when opts.Replace is set. A malformed declared suffix is
// returned unchanged and no rule is built, so an invalid option can never
// yield a silently narrower matcher.
func NewEmailRuleWithOptions(opts *EmailOptions, budget int) (Rule, error) {
	matcher, err := buildEmailMatcher(opts, budget)
	if err != nil {
		return nil, err
	}
	return emailRule{budget: normalizeBudget(budget), matcher: matcher}, nil
}

// buildEmailMatcher returns the suffix-gated matcher of one email rule's
// options, or the canonicalization error of the first malformed declared
// suffix. The closure captures the effective set computed once, so a compiled
// rule never rebuilds the union per leaf; a nil or additive opts value keeps
// the built-in table in the set and Replace swaps it out.
func buildEmailMatcher(opts *EmailOptions, budget int) (func([]byte) []Span, error) {
	suffixes, err := effectiveEmailSuffixes(opts)
	if err != nil {
		return nil, err
	}
	budget = normalizeBudget(budget)
	return func(content []byte) []Span {
		return inspectEmailWithSuffixes(content, budget, suffixes)
	}, nil
}

// ID returns the frozen detector id.
func (emailRule) ID() string { return DetectorEmail }

// Type returns the frozen rule type id.
func (emailRule) Type() string { return TypeEmail }

// Category returns the frozen category.
func (emailRule) Category() string { return CategoryEmail }

// Scope returns the request phase: only requests may substitute a placeholder.
func (emailRule) Scope() Scope { return ScopeRequest }

// Action returns redact, the built-in action for an address match.
func (emailRule) Action() Action { return ActionRedact }

// Priority returns the default rule priority.
func (emailRule) Priority() int { return DefaultPriority }

// Confidence returns the fixed detector confidence.
func (emailRule) Confidence() float64 { return emailConfidence }

// inspectEmail runs the precise email algorithm over content truncated to
// budget with the package's built-in suffix table; it is the compiled-document
// entry, where no rule struct is materialised, and it passes the package slice
// value directly so the hot path clones nothing.
func inspectEmail(content []byte, budget int) []Span {
	return inspectEmailWithSuffixes(content, budget, builtinEmailSuffixes)
}

// Inspect returns the spans of email addresses inside leaf. The default rule
// reads the package suffix table through inspectEmail; an options-carrying
// rule runs the matcher captured at construction.
func (r emailRule) Inspect(leaf []byte) []Span {
	if r.matcher != nil {
		return r.matcher(leaf)
	}
	return inspectEmail(leaf, r.budget)
}
