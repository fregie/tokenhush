package filter

// builtin_test.go pins D11: the six built-in detectors are ordinary rules with
// the frozen wire ids and categories, the default enabled set is the five
// non-entropy detectors, and high_entropy is reachable only through an explicit
// opt-in. The registry path is exercised too, so "built-in" is proven to be a
// provenance — not a second evaluation mechanism.

import (
	"slices"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

func builtinIDs(rules []Rule) []string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID())
	}
	return ids
}

// TestBuiltinRulesCarryFrozenIDsAndCategories pins the frozen table: exactly
// six built-in detectors, each carrying the wire id, rule type and category the
// wire format froze. The pem and entropy ids deliberately differ from their
// type ids (private_key/pem, high_entropy/entropy), so both are asserted.
func TestBuiltinRulesCarryFrozenIDsAndCategories(t *testing.T) {
	want := []struct {
		id       string
		typ      string
		category string
	}{
		{"prefix", "prefix", "api_key"},
		{"email", "email", "email"},
		{"luhn", "luhn", "credit_card"},
		{"jwt", "jwt", "jwt"},
		{"private_key", "pem", "private_key"},
		{"high_entropy", "entropy", "high_entropy"},
	}
	rules := BuiltinDetectors()
	if len(rules) != len(want) {
		t.Fatalf("BuiltinDetectors() returned %d rules, want exactly %d", len(rules), len(want))
	}
	for i, rule := range rules {
		got := [3]string{rule.ID(), rule.Type(), rule.Category()}
		expected := [3]string{want[i].id, want[i].typ, want[i].category}
		if got != expected {
			t.Errorf("rule %d = %v, want %v", i, got, expected)
		}
	}
}

// TestBuiltinDefaultSetExcludesEntropy pins D11: the default enabled set is
// exactly the five non-entropy detectors, and entropy appears only when the
// explicit opt-in flag is set.
func TestBuiltinDefaultSetExcludesEntropy(t *testing.T) {
	defaults := DefaultBuiltinDetectors()
	defaultIDs := builtinIDs(defaults)
	if len(defaults) != 5 {
		t.Fatalf("default set = %v, want exactly the five non-entropy detectors", defaultIDs)
	}
	if slices.Contains(defaultIDs, DetectorHighEntropy) {
		t.Fatalf("default set = %v includes %s; entropy must be an explicit opt-in", defaultIDs, DetectorHighEntropy)
	}

	opted := EnabledBuiltinDetectors(BuiltinConfig{HighEntropy: true})
	optedIDs := builtinIDs(opted)
	if len(opted) != 6 {
		t.Fatalf("opt-in set = %v, want all six detectors", optedIDs)
	}
	if !slices.Contains(optedIDs, DetectorHighEntropy) {
		t.Fatalf("opt-in set = %v is missing %s", optedIDs, DetectorHighEntropy)
	}
}

// Built-in email fixtures are assembled from parts, so no contiguous
// address-shaped literal reaches this source; the constants stay readable and
// the joined address is a real input at run time.
const (
	builtinEmailLocal    = "alice"
	builtinEmailDomain   = "example.com"
	builtinEmailUnlisted = "example.zz"
	builtinEmailReserved = "example.invalid"
	builtinEmailBare     = "example"
)

// builtinEmailRuleOf returns the email rule of the built-in set rules, or fails
// the test naming the ids the set actually carries.
func builtinEmailRuleOf(t *testing.T, rules []Rule) Rule {
	t.Helper()
	for _, rule := range rules {
		if rule.ID() == DetectorEmail {
			return rule
		}
	}
	t.Fatalf("built-in set %v carries no %s rule", builtinIDs(rules), DetectorEmail)
	return nil
}

// TestBuiltinEmailRuleIsPrecise pins the precise email default through the
// built-in table wiring — BuiltinDetectors() and the default enabled set — not
// only through the NewEmailRule constructor: the rule the built-in table builds
// must accept an example.com address with an exact len()-derived span and
// reject an unlisted suffix, a reserved suffix and a TLD-less domain. It
// restates the wiring the precision rests on: six rules in frozen id order, the
// five non-entropy defaults, and the email rule built by NewEmailRuleBudget
// with the documented default budget and no options matcher.
func TestBuiltinEmailRuleIsPrecise(t *testing.T) {
	all := BuiltinDetectors()
	if len(all) != 6 {
		t.Fatalf("BuiltinDetectors() returned %d rules, want exactly 6", len(all))
	}
	wantIDs := []string{DetectorPrefix, DetectorEmail, DetectorLuhn, DetectorJWT, DetectorPrivateKey, DetectorHighEntropy}
	if got := builtinIDs(all); !slices.Equal(got, wantIDs) {
		t.Fatalf("BuiltinDetectors() ids = %v, want frozen order %v", got, wantIDs)
	}
	defaults := EnabledBuiltinDetectors(BuiltinConfig{})
	if len(defaults) != 5 {
		t.Fatalf("EnabledBuiltinDetectors(BuiltinConfig{}) returned %d rules, want the five non-entropy defaults", len(defaults))
	}

	allowed := builtinEmailLocal + "@" + builtinEmailDomain
	content := "reach " + allowed + " today"
	want := Span{Start: len("reach "), End: len("reach ") + len(allowed)}

	for _, tc := range []struct {
		name  string
		rules []Rule
	}{
		{"BuiltinDetectors", all},
		{"EnabledBuiltinDetectors", defaults},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := builtinEmailRuleOf(t, tc.rules)
			builtin, ok := rule.(emailRule)
			if !ok {
				t.Fatalf("built-in %s rule is %T, want the emailRule built by NewEmailRuleBudget", DetectorEmail, rule)
			}
			if builtin.matcher != nil {
				t.Errorf("built-in %s rule carries an options matcher; the default must read the package suffix table", DetectorEmail)
			}
			if builtin.budget != PrimitiveByteBudgetBytes {
				t.Errorf("built-in %s rule budget = %d, want the documented default %d", DetectorEmail, builtin.budget, PrimitiveByteBudgetBytes)
			}

			if got := rule.Inspect([]byte(content)); len(got) != 1 || got[0] != want {
				t.Errorf("Inspect(%q) = %v, want exactly [%v]", content, got, want)
			}
			rejected := map[string]string{
				"unlisted suffix": builtinEmailLocal + "@" + builtinEmailUnlisted,
				"reserved suffix": builtinEmailLocal + "@" + builtinEmailReserved,
				"no TLD":          builtinEmailLocal + "@" + builtinEmailBare,
			}
			for name, address := range rejected {
				if got := rule.Inspect([]byte("reach " + address + " today")); len(got) != 0 {
					t.Errorf("%s: Inspect(%q) = %v, want no span", name, address, got)
				}
			}
		})
	}
}

// TestBuiltinsRegisterThroughTheRegistry proves the built-ins take the same
// registration path as any other rule and that the core stamps OriginBuiltin:
// the default set flags nothing on a high-entropy token because entropy is off,
// while the explicit opt-in flags exactly that token as a built-in.
func TestBuiltinsRegisterThroughTheRegistry(t *testing.T) {
	const sample = "qX9vT2mK4pL8sD3fG7hJ1kQzWxAe5Nb"
	leaves := []protocol.Leaf{leaf(sample)}

	reg := NewRegistry()
	if err := RegisterBuiltins(reg, BuiltinConfig{}); err != nil {
		t.Fatalf("RegisterBuiltins(default) error = %v", err)
	}
	findings, err := reg.Evaluate(leaves, ScopeRequest)
	if err != nil {
		t.Fatalf("default Evaluate() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("default built-ins flagged %v, want none: entropy is opt-in", ruleIDs(findings))
	}

	opted := NewRegistry()
	if err := RegisterBuiltins(opted, BuiltinConfig{HighEntropy: true}); err != nil {
		t.Fatalf("RegisterBuiltins(opt-in) error = %v", err)
	}
	findings, err = opted.Evaluate(leaves, ScopeRequest)
	if err != nil {
		t.Fatalf("opt-in Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("opt-in built-ins flagged %v, want exactly the entropy match", ruleIDs(findings))
	}
	if got := findings[0]; got.RuleID != DetectorHighEntropy || got.Category != CategoryHighEntropy || got.Origin != OriginBuiltin {
		t.Errorf("finding = %+v, want rule %s category %s origin %s",
			got, DetectorHighEntropy, CategoryHighEntropy, OriginBuiltin)
	}
}
