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
