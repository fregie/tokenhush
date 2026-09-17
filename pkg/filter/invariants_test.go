package filter

import (
	"reflect"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// TestInvariant5FailSafe is the named invariant 5 test: a rule that panics,
// times out, exceeds its budget, returns malformed findings, or cannot be
// invoked at all must yield a labelled refusal carrying the right reason —
// never a silent pass and never a crash — and each failure writes exactly one
// metadata-only audit record.
func TestInvariant5FailSafe(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		rule    Rule
		reason  Reason
		timeout time.Duration
	}{
		{"panic", "inv-panic", stubRule{id: "inv-panic", inspect: func([]byte) []Span { panic("invariant 5") }}, ReasonPanic, 0},
		{"timeout", "inv-timeout", stubRule{id: "inv-timeout", inspect: func([]byte) []Span { time.Sleep(2 * time.Second); return nil }}, ReasonTimeout, 20 * time.Millisecond},
		{"budget", "inv-budget", stubRule{id: "inv-budget", inspect: burst(MaxRuleSpans + 1)}, ReasonBudget, 0},
		{"malformed", "inv-malformed", stubRule{id: "inv-malformed", inspect: func([]byte) []Span { return []Span{{Start: 4, End: 2}} }}, ReasonMalformed, 0},
		{"error", "inv-error", (*stubRule)(nil), ReasonError, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			policy, sink := policyFor(t, testCase.timeout, registryEntry{rule: testCase.rule, origin: OriginPlugin, id: testCase.id, rank: 1})
			decision := mustDecide(t, policy, []protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
			if decision.Refusal == nil {
				t.Fatalf("no refusal: a %s rule failure passed silently", testCase.name)
			}
			if decision.Refusal.Reason != testCase.reason {
				t.Errorf("reason = %q, want %q", decision.Refusal.Reason, testCase.reason)
			}
			if decision.Refusal.RuleID != testCase.id {
				t.Errorf("RuleID = %q, want %q", decision.Refusal.RuleID, testCase.id)
			}
			if decision.Action != ActionBlock {
				t.Errorf("action = %q, want block: a refusal is never an allow", decision.Action)
			}
			records := sink.snapshot()
			want := []string{policyFailureTag, testCase.id, string(testCase.reason)}
			if len(records) != 1 || !reflect.DeepEqual(records[0].RuleIDs, want) {
				t.Fatalf("audit records = %+v, want exactly one %v row", records, want)
			}
		})
	}

	t.Run("failure is never a crash", func(t *testing.T) {
		// The panic case above already proves Decide returned a Decision
		// instead of propagating the panic; this control pins that a panic
		// never escapes even with the default timeout.
		policy, _ := policyFor(t, 0, registryEntry{rule: stubRule{id: "boom", inspect: func([]byte) []Span { panic("boom") }}, origin: OriginPlugin, id: "boom", rank: 1})
		decision := mustDecide(t, policy, []protocol.Leaf{leaf("x")}, ScopeRequest)
		if decision.Refusal == nil || decision.Refusal.Reason != ReasonPanic {
			t.Fatalf("decision = %+v, want a labelled panic refusal", decision)
		}
	})

	t.Run("positive control", func(t *testing.T) {
		policy, sink := policyFor(t, 0, entry(matches("healthy", 10, "SECRET", ActionWarn), OriginPlugin))
		decision := mustDecide(t, policy, []protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
		if decision.Refusal != nil {
			t.Fatalf("healthy rule produced a refusal: %+v", decision.Refusal)
		}
		if decision.Action != ActionWarn {
			t.Errorf("action = %q, want warn", decision.Action)
		}
		if records := sink.snapshot(); len(records) != 0 {
			t.Errorf("audit records = %d, want none for a healthy rule", len(records))
		}
	})
}
