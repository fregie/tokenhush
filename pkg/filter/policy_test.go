package filter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/protocol"
)

// captureSink collects the metadata-only audit records the policy writes.
type captureSink struct {
	mu      sync.Mutex
	records []audit.Record
}

func (s *captureSink) Record(_ context.Context, rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

func (s *captureSink) snapshot() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...)
}

// policyFor builds a policy over explicit entries, so a test can inject a rule
// that registration would reject.
func policyFor(t *testing.T, timeout time.Duration, entries ...registryEntry) (*Policy, *captureSink) {
	t.Helper()
	sink := &captureSink{}
	policy := NewPolicy(nil, PolicyConfig{Sink: sink, Timeout: timeout})
	policy.entries = entries
	return policy, sink
}

// entry binds a stub rule to an explicit origin and core-owned id.
func entry(rule stubRule, origin Origin) registryEntry {
	return registryEntry{rule: rule, origin: origin, id: rule.ID(), rank: rule.Priority()}
}

func mustDecide(t *testing.T, policy *Policy, leaves []protocol.Leaf, phase Scope) Decision {
	t.Helper()
	decision, err := policy.Decide(leaves, phase)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	return decision
}

// TestPolicyPrecedence pins the frozen action precedence
// Allow < Warn < Redact < Block and that only the winning findings are kept.
func TestPolicyPrecedence(t *testing.T) {
	cases := []struct {
		name    string
		actions []Action
		want    Action
	}{
		{"none", nil, ActionAllow},
		{"allow only", []Action{ActionAllow}, ActionAllow},
		{"warn over allow", []Action{ActionAllow, ActionWarn}, ActionWarn},
		{"redact over warn", []Action{ActionWarn, ActionRedact}, ActionRedact},
		{"block over redact", []Action{ActionRedact, ActionBlock}, ActionBlock},
		{"all four", []Action{ActionBlock, ActionRedact, ActionWarn, ActionAllow}, ActionBlock},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			entries := make([]registryEntry, 0, len(testCase.actions))
			for i, action := range testCase.actions {
				id := fmt.Sprintf("rule-%d", i)
				entries = append(entries, registryEntry{rule: matches(id, 10+i, "SECRET", action), origin: OriginPlugin, id: id, rank: 10 + i})
			}
			policy, sink := policyFor(t, 0, entries...)
			decision := mustDecide(t, policy, []protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
			if decision.Action != testCase.want {
				t.Fatalf("Action = %q, want %q", decision.Action, testCase.want)
			}
			if decision.Refusal != nil {
				t.Fatalf("Refusal = %v, want nil", decision.Refusal)
			}
			if len(testCase.actions) > 0 && len(decision.Findings) == 0 {
				t.Fatalf("Findings is empty for %q", testCase.want)
			}
			for _, finding := range decision.Findings {
				if finding.Action != testCase.want {
					t.Errorf("finding action %q does not back the decision %q", finding.Action, testCase.want)
				}
			}
			if got := sink.snapshot(); len(got) != 0 {
				t.Errorf("audit records = %d, want none without a failure", len(got))
			}
		})
	}
}

// TestPolicyFailureModesAreLabelled drives each failure mode through Decide and
// asserts a typed reason, a Block action, no findings and one audit record.
func TestPolicyFailureModesAreLabelled(t *testing.T) {
	long := func([]byte) []Span { time.Sleep(2 * time.Second); return nil }
	cases := []struct {
		name    string
		id      string
		rule    Rule
		reason  Reason
		timeout time.Duration
	}{
		{"panic", "panic", stubRule{id: "panic", inspect: func([]byte) []Span { panic("policy") }}, ReasonPanic, 0},
		{"timeout", "timeout", stubRule{id: "timeout", inspect: long}, ReasonTimeout, 20 * time.Millisecond},
		{"budget", "budget", stubRule{id: "budget", inspect: burst(MaxRuleSpans + 1)}, ReasonBudget, 0},
		{"malformed spans", "malformed", stubRule{id: "malformed", inspect: func([]byte) []Span { return []Span{{Start: 0, End: 99}} }}, ReasonMalformed, 0},
		{"malformed metadata", "bad-action", stubRule{id: "bad-action", action: "explode"}, ReasonMalformed, 0},
		{"error", "error", (*stubRule)(nil), ReasonError, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			policy, sink := policyFor(t, testCase.timeout, registryEntry{rule: testCase.rule, origin: OriginRemotePack, id: testCase.id, rank: 1})
			decision := mustDecide(t, policy, []protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
			if decision.Refusal == nil {
				t.Fatalf("Refusal = nil, want a labelled refusal with reason %q", testCase.reason)
			}
			if decision.Refusal.Reason != testCase.reason {
				t.Errorf("Reason = %q, want %q", decision.Refusal.Reason, testCase.reason)
			}
			if decision.Refusal.RuleID != testCase.id || decision.Refusal.Origin != OriginRemotePack {
				t.Errorf("Refusal = %+v, want rule %q / origin %q", decision.Refusal, testCase.id, OriginRemotePack)
			}
			if decision.Action != ActionBlock {
				t.Errorf("Action = %q, want block: a refusal must never read as an allow", decision.Action)
			}
			if len(decision.Findings) != 0 || len(decision.Substitutions) != 0 || len(decision.Warnings) != 0 {
				t.Errorf("refusal carried effects: %+v", decision)
			}
			records := sink.snapshot()
			if len(records) != 1 {
				t.Fatalf("audit records = %d, want exactly one per failure", len(records))
			}
			want := []string{policyFailureTag, testCase.id, string(testCase.reason)}
			if !reflect.DeepEqual(records[0].RuleIDs, want) {
				t.Errorf("audit RuleIDs = %v, want %v", records[0].RuleIDs, want)
			}
			if records[0].Method != policyAuditMethod || records[0].Path != string(ScopeRequest) {
				t.Errorf("audit record = %+v, want method %q / path %q", records[0], policyAuditMethod, ScopeRequest)
			}
		})
	}
}

// TestPolicyStampsProvenance proves the core, not the rule, owns the rule id
// and the origin on every finding.
func TestPolicyStampsProvenance(t *testing.T) {
	set := compileDoc(t, `{"rules":[{"id":"pack","type":"keyword","keywords":["SECRET"],"action":"warn","priority":20}]}`)
	reg := NewRegistry()
	if err := reg.RegisterBuiltin(matches("builtin", 10, "SECRET", ActionWarn)); err != nil {
		t.Fatalf("RegisterBuiltin() error = %v", err)
	}
	if err := reg.RegisterCompiled(set); err != nil {
		t.Fatalf("RegisterCompiled() error = %v", err)
	}
	mustRegister(t, reg, matches("plugin", 30, "SECRET", ActionWarn))
	policy := NewPolicy(reg, PolicyConfig{})

	decision := mustDecide(t, policy, []protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
	want := map[string]Origin{"builtin": OriginBuiltin, "pack": OriginRemotePack, "plugin": OriginPlugin}
	if len(decision.Findings) != len(want) {
		t.Fatalf("findings = %v, want one per origin", ruleIDs(decision.Findings))
	}
	for _, finding := range decision.Findings {
		if got := finding.Origin; got != want[finding.RuleID] {
			t.Errorf("rule %q origin = %q, want %q", finding.RuleID, got, want[finding.RuleID])
		}
	}

	// A rule cannot spoof the core's stamp: the registered id wins over the
	// id the rule claims.
	spoof := registryEntry{rule: matches("liar", 40, "SECRET", ActionWarn), origin: OriginPlugin, id: "core-id", rank: 40}
	policy, _ = policyFor(t, 0, spoof)
	decision = mustDecide(t, policy, []protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
	if got := ruleIDs(decision.Findings); !reflect.DeepEqual(got, []string{"core-id"}) {
		t.Fatalf("findings = %v, want the core-stamped id", got)
	}
}

// TestPolicyRequestRedactRequestsSubstitution pins the only substitution
// request in the system: a request-phase Redact.
func TestPolicyRequestRedactRequestsSubstitution(t *testing.T) {
	rule := matches("proj", 10, "TOKEN", ActionRedact)
	rule.category = CategoryAPIKey
	policy, _ := policyFor(t, 0, entry(rule, OriginPlugin))
	decision := mustDecide(t, policy, []protocol.Leaf{leaf("a TOKEN b")}, ScopeRequest)

	if decision.Action != ActionRedact {
		t.Fatalf("Action = %q, want redact", decision.Action)
	}
	want := []SubstitutionRequest{{RuleID: "proj", Origin: OriginPlugin, LeafIndex: 0, Start: 2, End: 7, Category: CategoryAPIKey}}
	if !reflect.DeepEqual(decision.Substitutions, want) {
		t.Fatalf("Substitutions = %+v, want %+v", decision.Substitutions, want)
	}
	if len(decision.Warnings) != 0 {
		t.Errorf("Warnings = %+v, want none on the request path", decision.Warnings)
	}
}

// TestPolicyResponseBlockIsARuleBlockDecision pins the response-phase Block
// effect: a rule-block decision whose findings name the rule id.
func TestPolicyResponseBlockIsARuleBlockDecision(t *testing.T) {
	rule := matches("resp-block", 10, "TOKEN", ActionBlock)
	rule.scope = ScopeResponse
	policy, sink := policyFor(t, 0, entry(rule, OriginRemotePack))
	decision := mustDecide(t, policy, []protocol.Leaf{leaf("a TOKEN b")}, ScopeResponse)

	if decision.Action != ActionBlock || decision.Refusal != nil {
		t.Fatalf("decision = %+v, want a rule block without a refusal", decision)
	}
	if got := ruleIDs(decision.Findings); !reflect.DeepEqual(got, []string{"resp-block"}) {
		t.Fatalf("Findings = %v, want the blocking rule id", got)
	}
	if len(decision.Substitutions) != 0 || len(decision.Warnings) != 0 {
		t.Errorf("response block carried other effects: %+v", decision)
	}
	if records := sink.snapshot(); len(records) != 0 {
		t.Errorf("audit records = %d, want none for a rule decision", len(records))
	}
}

// TestPolicyResponseWarnIsMetadataOnly pins the response-phase Warn effect: a
// metadata-only warning and no substitution request.
func TestPolicyResponseWarnIsMetadataOnly(t *testing.T) {
	rule := matches("resp-warn", 10, "TOKEN", ActionWarn)
	rule.scope = ScopeResponse
	policy, sink := policyFor(t, 0, entry(rule, OriginBuiltin))
	decision := mustDecide(t, policy, []protocol.Leaf{leaf("a TOKEN b")}, ScopeResponse)

	if decision.Action != ActionWarn || decision.Refusal != nil {
		t.Fatalf("decision = %+v, want a warn without a refusal", decision)
	}
	want := []Warning{{RuleID: "resp-warn", Origin: OriginBuiltin}}
	if !reflect.DeepEqual(decision.Warnings, want) {
		t.Fatalf("Warnings = %+v, want %+v", decision.Warnings, want)
	}
	if len(decision.Substitutions) != 0 {
		t.Errorf("Warnings carried a substitution: %+v", decision.Substitutions)
	}
	if records := sink.snapshot(); len(records) != 0 {
		t.Errorf("audit records = %d, want none for a warn", len(records))
	}
}

// TestPolicyResponseRedactIsImpossible re-asserts the direction contract at the
// policy layer: even a smuggled response-capable redact rule is refused as
// malformed and can never produce a substitution request.
func TestPolicyResponseRedactIsImpossible(t *testing.T) {
	for _, scope := range []Scope{ScopeResponse, ScopeBoth} {
		t.Run(string(scope), func(t *testing.T) {
			rule := matches("smuggled", 10, "TOKEN", ActionRedact)
			rule.scope = scope
			policy, sink := policyFor(t, 0, entry(rule, OriginPlugin))
			decision := mustDecide(t, policy, []protocol.Leaf{leaf("a TOKEN b")}, ScopeResponse)

			if decision.Refusal == nil || decision.Refusal.Reason != ReasonMalformed {
				t.Fatalf("Refusal = %+v, want a malformed refusal", decision.Refusal)
			}
			if decision.Refusal.RuleID != "smuggled" {
				t.Errorf("Refusal.RuleID = %q, want the smuggled rule", decision.Refusal.RuleID)
			}
			if len(decision.Substitutions) != 0 {
				t.Fatalf("Substitutions = %+v, want none on the response path", decision.Substitutions)
			}
			if decision.Action != ActionBlock {
				t.Errorf("Action = %q, want block", decision.Action)
			}
			if records := sink.snapshot(); len(records) != 1 {
				t.Errorf("audit records = %d, want one for the refusal", len(records))
			}
		})
	}
}

// TestPolicyPositiveControl proves a non-failing rule yields no refusal and no
// audit record, and that no findings at all is Allow.
func TestPolicyPositiveControl(t *testing.T) {
	policy, sink := policyFor(t, 20*time.Millisecond, entry(matches("ok", 10, "TOKEN", ActionWarn), OriginPlugin))
	decision := mustDecide(t, policy, []protocol.Leaf{leaf("a TOKEN b")}, ScopeRequest)
	if decision.Refusal != nil || decision.Action != ActionWarn {
		t.Fatalf("decision = %+v, want warn without a refusal", decision)
	}
	if got := ruleIDs(decision.Findings); !reflect.DeepEqual(got, []string{"ok"}) {
		t.Fatalf("Findings = %v, want the healthy rule", got)
	}
	if records := sink.snapshot(); len(records) != 0 {
		t.Fatalf("audit records = %d, want none", len(records))
	}

	empty := mustDecide(t, policy, nil, ScopeRequest)
	if empty.Action != ActionAllow || empty.Refusal != nil || len(empty.Findings) != 0 {
		t.Fatalf("empty decision = %+v, want allow", empty)
	}
}

// TestPolicySnapshotsTheRegistry proves a policy is immune to later
// registration.
func TestPolicySnapshotsTheRegistry(t *testing.T) {
	reg := NewRegistry()
	policy := NewPolicy(reg, PolicyConfig{})
	mustRegister(t, reg, matches("late", 10, "TOKEN", ActionWarn))
	decision := mustDecide(t, policy, []protocol.Leaf{leaf("a TOKEN b")}, ScopeRequest)
	if len(decision.Findings) != 0 || decision.Action != ActionAllow {
		t.Fatalf("decision = %+v, want allow: the rule registered after the snapshot", decision)
	}
}

// TestPolicyRejectsInvalidInput pins the two typed errors Decide can return.
func TestPolicyRejectsInvalidInput(t *testing.T) {
	var nilPolicy *Policy
	if _, err := nilPolicy.Decide(nil, ScopeRequest); !errors.Is(err, ErrNilPolicy) {
		t.Errorf("nil Policy.Decide() error = %v, want ErrNilPolicy", err)
	}
	policy := NewPolicy(nil, PolicyConfig{})
	for _, phase := range []Scope{ScopeBoth, ""} {
		if _, err := policy.Decide(nil, phase); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Decide(phase=%q) error = %v, want ErrInvalidValue", phase, err)
		}
	}
}

// TestPolicyConcurrentRaceFree drives concurrent decisions over one immutable
// policy.
func TestPolicyConcurrentRaceFree(t *testing.T) {
	policy, _ := policyFor(t, 0,
		entry(matches("one", 10, "SECRET", ActionWarn), OriginPlugin),
		entry(matches("two", 20, "SECRET", ActionRedact), OriginBuiltin),
	)
	leaves := []protocol.Leaf{leaf("a SECRET b")}
	baseline := mustDecide(t, policy, leaves, ScopeRequest)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				decision, err := policy.Decide(leaves, ScopeRequest)
				if err != nil {
					t.Errorf("concurrent Decide() error = %v", err)
					return
				}
				if !reflect.DeepEqual(decision, baseline) {
					t.Errorf("concurrent decision = %+v, want %+v", decision, baseline)
					return
				}
			}
		}()
	}
	wg.Wait()
}
