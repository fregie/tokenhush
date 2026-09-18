package filter

// primitive_email_test.go locks the precise email mode: a candidate matches
// only when its domain is, or is a subdomain of, one of the effective public
// suffixes, so the built-in rule matches the package suffix table and an
// options-carrying rule matches its declared set on top of (or instead of) the
// built-ins. Every fixture is a fresh RFC-2606 example.com / example.org
// address and every expected span is computed from len(), never pinned to an
// offset, so no existing fixture literal is touched.

import (
	"errors"
	"testing"
)

// The frozen helper contracts the later compiled-rule todos consume: the
// suffix-parameterized entry point and the options matcher constructor.
var (
	_ func([]byte, int, []string) []Span                    = inspectEmailWithSuffixes
	_ func(*EmailOptions, int) (func([]byte) []Span, error) = buildEmailMatcher
)

// emailSpan asserts that inspect returned exactly the one span covering addr
// inside the canonical "mail " + addr + " end" input.
func emailSpan(t *testing.T, inspect func([]byte) []Span, addr string) {
	t.Helper()
	input := "mail " + addr + " end"
	got := inspect([]byte(input))
	want := Span{Start: 5, End: 5 + len(addr)}
	if len(got) != 1 || got[0] != want {
		t.Errorf("address %q: spans %v, want [%v]", addr, got, want)
	}
}

// noEmailSpan asserts that inspect produced no span for input.
func noEmailSpan(t *testing.T, inspect func([]byte) []Span, input string) {
	t.Helper()
	if got := inspect([]byte(input)); len(got) != 0 {
		t.Errorf("%q: spans %v, want none", input, got)
	}
}

// TestPreciseEmailDefault pins the built-in rule: addresses under the package
// suffix table still match with the exact span, an uppercase domain is lowered
// before the gate, and a dotless domain never matches. The frozen metadata of
// the options constructor is asserted here too, because that is the only path
// a compiled rule takes to build an email matcher.
func TestPreciseEmailDefault(t *testing.T) {
	rule := NewEmailRule()
	for _, addr := range []string{
		"alice@example.com",
		"bob@example.org",
		"carol@MAIL.EXAMPLE.COM",
	} {
		emailSpan(t, rule.Inspect, addr)
	}
	noEmailSpan(t, rule.Inspect, "user@example")

	t.Run("options rule carries the frozen metadata", func(t *testing.T) {
		got, err := NewEmailRuleWithOptions(&EmailOptions{}, PrimitiveByteBudgetBytes)
		if err != nil {
			t.Fatalf("NewEmailRuleWithOptions: %v", err)
		}
		if got.ID() != DetectorEmail || got.Type() != TypeEmail || got.Category() != CategoryEmail {
			t.Errorf("identity = (%q, %q, %q), want (%q, %q, %q)",
				got.ID(), got.Type(), got.Category(), DetectorEmail, TypeEmail, CategoryEmail)
		}
		if got.Scope() != ScopeRequest {
			t.Errorf("Scope() = %v, want %v", got.Scope(), ScopeRequest)
		}
		if got.Action() != ActionRedact {
			t.Errorf("Action() = %v, want %v", got.Action(), ActionRedact)
		}
		if got.Priority() != DefaultPriority {
			t.Errorf("Priority() = %d, want %d", got.Priority(), DefaultPriority)
		}
		if got.Confidence() != emailConfidence {
			t.Errorf("Confidence() = %v, want %v", got.Confidence(), emailConfidence)
		}
	})
}

// TestPreciseEmailSubdomainWildcard pins the label-boundary wildcard: a
// declared .corp.com accepts the bare corporate domain and a deeper subdomain
// of it, an unknown TLD stays outside the effective set, and under a
// replace-mode rule the byte-tail look-alike evilcorp.com is not a match.
func TestPreciseEmailSubdomainWildcard(t *testing.T) {
	rule, err := NewEmailRuleWithOptions(&EmailOptions{Suffixes: []string{"corp.com"}}, PrimitiveByteBudgetBytes)
	if err != nil {
		t.Fatalf("NewEmailRuleWithOptions: %v", err)
	}
	for _, addr := range []string{
		"dana@corp.com",
		"erin@a.corp.com",
		"frank@a.b.corp.com",
	} {
		emailSpan(t, rule.Inspect, addr)
	}
	noEmailSpan(t, rule.Inspect, "felix@evilcorp.zz")

	t.Run("byte-tail look-alike is not a label match", func(t *testing.T) {
		replaced, err := NewEmailRuleWithOptions(&EmailOptions{Suffixes: []string{"corp.com"}, Replace: true}, PrimitiveByteBudgetBytes)
		if err != nil {
			t.Fatalf("NewEmailRuleWithOptions: %v", err)
		}
		emailSpan(t, replaced.Inspect, "erin@a.corp.com")
		noEmailSpan(t, replaced.Inspect, "felix@evilcorp.com")
	})
}

// TestPreciseEmailAdditiveSuffix pins the additive mode: the declared suffix
// joins the built-in table instead of narrowing it, so an address under either
// set still matches.
func TestPreciseEmailAdditiveSuffix(t *testing.T) {
	rule, err := NewEmailRuleWithOptions(&EmailOptions{Suffixes: []string{"corp"}}, PrimitiveByteBudgetBytes)
	if err != nil {
		t.Fatalf("NewEmailRuleWithOptions: %v", err)
	}
	emailSpan(t, rule.Inspect, "alice@example.com")
	emailSpan(t, rule.Inspect, "gina@host.corp")
}

// TestPreciseEmailRejectsNonTLD pins the gate's negative space: a dotless
// domain, a dot-run candidate, an unknown TLD, the reserved TLDs .invalid,
// .test and .localhost, and a replace-mode rule that drops the built-ins all
// produce no span.
func TestPreciseEmailRejectsNonTLD(t *testing.T) {
	rule := NewEmailRule()
	for _, input := range []string{
		"user@example",
		"a..b@example.com",
		"dave@example.zz",
		"eve@example.invalid",
		"frank@example.test",
		"grace@machine.localhost",
	} {
		noEmailSpan(t, rule.Inspect, input)
	}

	replaced, err := NewEmailRuleWithOptions(&EmailOptions{Suffixes: []string{"corp.com"}, Replace: true}, PrimitiveByteBudgetBytes)
	if err != nil {
		t.Fatalf("NewEmailRuleWithOptions: %v", err)
	}
	for _, addr := range []string{
		"henry@example.com",
		"iris@example.org",
	} {
		noEmailSpan(t, replaced.Inspect, addr)
	}
}

// TestEmailRuleWithOptionsRejectsMalformedSuffix proves a malformed declared
// suffix fails construction with the canonicalization sentinel instead of
// building a silently narrower matcher.
func TestEmailRuleWithOptionsRejectsMalformedSuffix(t *testing.T) {
	for _, suffix := range []string{"a..b", "a b.com"} {
		if _, err := NewEmailRuleWithOptions(&EmailOptions{Suffixes: []string{suffix}}, PrimitiveByteBudgetBytes); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("NewEmailRuleWithOptions(suffix %q): err = %v, want ErrInvalidValue", suffix, err)
		}
	}
}
