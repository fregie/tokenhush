package filter

// sensitive_gate_invoke_test.go is the F2-3 regression suite for the
// sensitive-key gate: a gated request-phase leaf must be kept away from
// Redact-producing rules BEFORE they are invoked, not after. The gate therefore
// cannot fail the Registered (Registry) or runtime (Policy) paths closed through
// a rule that only misbehaves on a leaf the compiled path statically skips.
// The counter assertion (Inspect never called) is the primary observable; the
// panicking-rule cases pin the fail-closed divergence the static skip removes.

import (
	"errors"
	"sync/atomic"
	"testing"
)

// gateCountingRule is a test-only Rule that counts its own Inspect invocations
// and returns one fixed span. One value stands in for both a Redact-producing and
// a Block-producing rule through its action field.
type gateCountingRule struct {
	id     string
	action Action
	spans  []Span
	calls  *atomic.Int64
}

func (r gateCountingRule) ID() string          { return r.id }
func (r gateCountingRule) Type() string        { return TypeKeyword }
func (r gateCountingRule) Category() string    { return CategoryCustom }
func (r gateCountingRule) Scope() Scope        { return ScopeRequest }
func (r gateCountingRule) Action() Action      { return r.action }
func (r gateCountingRule) Priority() int       { return 0 }
func (r gateCountingRule) Confidence() float64 { return 1 }

func (r gateCountingRule) Inspect([]byte) []Span {
	r.calls.Add(1)
	return r.spans
}

// gatePanicRule is a test-only Redact-producing Rule that panics if it is ever
// invoked. A gated leaf that reaches it would fail the request closed with a
// panic reason, exactly what the static skip prevents.
type gatePanicRule struct{ id string }

func (r gatePanicRule) ID() string          { return r.id }
func (r gatePanicRule) Type() string        { return TypeKeyword }
func (r gatePanicRule) Category() string    { return CategoryCustom }
func (r gatePanicRule) Scope() Scope        { return ScopeRequest }
func (r gatePanicRule) Action() Action      { return ActionRedact }
func (r gatePanicRule) Priority() int       { return 0 }
func (r gatePanicRule) Confidence() float64 { return 1 }

func (r gatePanicRule) Inspect([]byte) []Span {
	panic("a gated redact rule must never be invoked")
}

// gateRegistry builds a registry carrying the sensitive_keys gate plus the given
// plugin rules, so the Registered and runtime paths both see them.
func gateRegistry(t *testing.T, rules ...Rule) *Registry {
	t.Helper()
	reg := NewRegistry()
	if err := reg.RegisterCompiled(compileDoc(t, `{"sensitive_keys":{"keys":["password"]}}`)); err != nil {
		t.Fatalf("RegisterCompiled: %v", err)
	}
	if err := reg.Register(rules...); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return reg
}

// TestSensitiveKeyGateDoesNotInvokeRedactRules pins the F2-3 fix: on a gated
// leaf the gate skips a Redact-producing rule statically, so Inspect is never
// called, the gate still emits its one whole-value finding, and a
// Block-producing rule keeps its precedence. A Redact rule that panics on the
// gated leaf must not fail either path closed.
func TestSensitiveKeyGateDoesNotInvokeRedactRules(t *testing.T) {
	leaves := mustWalkLeaves(t, `{"password":"hunter2"}`)

	t.Run("a Redact rule is never invoked on a gated leaf", func(t *testing.T) {
		var calls atomic.Int64
		rule := gateCountingRule{id: "gate-redact", action: ActionRedact, spans: []Span{{Start: 0, End: 7}}, calls: &calls}
		reg := gateRegistry(t, rule)
		policy := NewPolicy(reg, PolicyConfig{})

		attributed, err := reg.Evaluate(leaves, ScopeRequest)
		if err != nil {
			t.Fatalf("Registry.Evaluate: %v", err)
		}
		decision, err := policy.Decide(leaves, ScopeRequest)
		if err != nil {
			t.Fatalf("Policy.Decide: %v", err)
		}

		if got := calls.Load(); got != 0 {
			t.Errorf("the Redact rule's Inspect ran %d times over a gated leaf, want 0", got)
		}
		got := sensitiveGateAttributed(attributed)
		if len(got) != 1 || got[0].Start != 0 || got[0].End != 7 {
			t.Fatalf("Registry gate findings = %+v, want exactly one whole-value finding [0,7)", got)
		}
		for _, finding := range attributed {
			if finding.RuleID == rule.id {
				t.Errorf("the skipped Redact rule still produced a finding: %+v", finding)
			}
		}
		if got := sensitiveGateAttributed(decision.Findings); len(got) != 1 {
			t.Errorf("Policy gate findings = %+v, want exactly one whole-value finding", got)
		}
	})

	t.Run("a Block rule is still invoked on a gated leaf", func(t *testing.T) {
		var calls atomic.Int64
		rule := gateCountingRule{id: "gate-block", action: ActionBlock, spans: []Span{{Start: 0, End: 7}}, calls: &calls}
		reg := gateRegistry(t, rule)
		policy := NewPolicy(reg, PolicyConfig{})

		attributed, err := reg.Evaluate(leaves, ScopeRequest)
		if err != nil {
			t.Fatalf("Registry.Evaluate: %v", err)
		}
		decision, err := policy.Decide(leaves, ScopeRequest)
		if err != nil {
			t.Fatalf("Policy.Decide: %v", err)
		}

		if got := calls.Load(); got != 2 {
			t.Errorf("the Block rule's Inspect ran %d times, want 2 (once per path)", got)
		}
		blocked := false
		for _, finding := range attributed {
			if finding.RuleID == rule.id && finding.Action == ActionBlock {
				blocked = true
			}
		}
		if !blocked {
			t.Errorf("the Block rule's finding is missing from %+v", attributed)
		}
		if decision.Action != ActionBlock {
			t.Errorf("decision action = %q, want %q: Block keeps its precedence", decision.Action, ActionBlock)
		}
	})

	t.Run("a panicking Redact rule never fails the request closed", func(t *testing.T) {
		reg := gateRegistry(t, gatePanicRule{id: "gate-panic"})
		policy := NewPolicy(reg, PolicyConfig{})

		attributed, err := reg.Evaluate(leaves, ScopeRequest)
		if err != nil {
			if errors.Is(err, ErrRuleFailure) {
				t.Fatalf("a gated Redact rule was invoked and failed the registry path closed: %v", err)
			}
			t.Fatalf("Registry.Evaluate: %v", err)
		}
		if len(sensitiveGateAttributed(attributed)) != 1 {
			t.Fatalf("Registry gate findings = %+v, want exactly one whole-value finding", attributed)
		}
		decision, err := policy.Decide(leaves, ScopeRequest)
		if err != nil {
			t.Fatalf("Policy.Decide: %v", err)
		}
		if decision.Refusal != nil {
			t.Fatalf("a gated Redact rule produced a refusal: %+v", decision.Refusal)
		}
	})
}
