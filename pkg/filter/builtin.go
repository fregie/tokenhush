package filter

// builtin.go is the built-in detector rule set (D11): the six compiled-in
// detectors delivered through the frozen Rule contract, so a built-in, a signed
// remote pack and a third-party plugin all reach the evaluator through the one
// registration path. The default enabled set is the five non-entropy detectors;
// high_entropy is an explicit opt-in because its false-positive rate on
// ordinary text makes a default set noisy, and no default may enable it
// silently. The set itself is only a selection over the frozen table below — a
// built-in needs no abstraction of its own.

// BuiltinConfig selects the built-in detectors to enable. The zero value is the
// documented default: every detector except the opt-in high-entropy pass.
// HighEntropy must be set explicitly; nothing infers or defaults it.
type BuiltinConfig struct {
	HighEntropy bool
}

// builtinTable is the frozen detector table in wire order. BuiltinDetectors,
// the default set and the floor baseline all derive from it, so a detector
// cannot be added to one and forgotten in another. Each entry builds its rule
// with the caller's per-primitive byte budget.
var builtinTable = []struct {
	id    string
	build func(int) Rule
}{
	{DetectorPrefix, NewPrefixRuleBudget},
	{DetectorEmail, NewEmailRuleBudget},
	{DetectorLuhn, NewLuhnRuleBudget},
	{DetectorJWT, NewJWTRuleBudget},
	{DetectorPrivateKey, NewPEMRuleBudget},
	{DetectorHighEntropy, NewEntropyRuleBudget},
}

// BuiltinDetectors returns all six built-in detector rules in frozen table
// order with the documented default per-primitive byte budget. The returned
// slice is fresh, so a caller cannot mutate the table.
func BuiltinDetectors() []Rule {
	return BuiltinDetectorsBudget(PrimitiveByteBudgetBytes)
}

// BuiltinDetectorsBudget returns all six built-in detector rules in frozen
// table order with an explicit per-primitive byte budget. A non-positive budget
// falls back to the documented default. The returned slice is fresh, so a
// caller cannot mutate the table.
func BuiltinDetectorsBudget(budget int) []Rule {
	budget = normalizeBudget(budget)
	rules := make([]Rule, 0, len(builtinTable))
	for _, entry := range builtinTable {
		rules = append(rules, entry.build(budget))
	}
	return rules
}

// DefaultBuiltinDetectors returns the default enabled set: the five
// non-entropy detectors in frozen table order.
func DefaultBuiltinDetectors() []Rule {
	return EnabledBuiltinDetectors(BuiltinConfig{})
}

// EnabledBuiltinDetectors returns the built-in detectors cfg enables: the five
// default detectors, plus high_entropy only when cfg.HighEntropy is set.
func EnabledBuiltinDetectors(cfg BuiltinConfig) []Rule {
	rules := make([]Rule, 0, len(builtinTable))
	for _, entry := range builtinTable {
		if entry.id == DetectorHighEntropy && !cfg.HighEntropy {
			continue
		}
		rules = append(rules, entry.build(PrimitiveByteBudgetBytes))
	}
	return rules
}

// RegisterBuiltins registers the built-in detectors cfg enables into reg with
// the core-stamped OriginBuiltin provenance: exactly the path a compiled remote
// pack (OriginRemotePack) and a third-party rule (OriginPlugin) take. The whole
// set is validated before anything is stored, so a rejected registration leaves
// reg unchanged.
func RegisterBuiltins(reg *Registry, cfg BuiltinConfig) error {
	return reg.RegisterBuiltin(EnabledBuiltinDetectors(cfg)...)
}
