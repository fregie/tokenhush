package filter

// policy.go is the action policy: it aggregates findings under the frozen
// precedence Allow < Warn < Redact < Block, stamps core-owned provenance onto
// every finding, applies the three frozen direction effects, and makes every
// rule failure a labelled refusal (invariant 5). A rule that panics, times out,
// exceeds its span budget, returns malformed output or cannot be invoked at all
// is refused with a typed reason, and the core writes one metadata-only audit
// record per failure, so a failing rule can neither pass silently nor crash the
// data plane. There is deliberately no failure-policy negotiation: the only
// behaviour is fail-closed.

import (
	"context"
	"errors"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/protocol"
)

// Policy audit metadata: one metadata-only Record is written per rule failure,
// with Method naming the policy, Path the phase and RuleIDs encoding
// {plugin_failure, <rule id>, <reason>}. No content is ever recorded.
const (
	policyAuditMethod = "policy"
	policyFailureTag  = "plugin_failure"
)

// ErrNilPolicy is returned by a Policy method on a nil receiver.
var ErrNilPolicy = errors.New("filter: nil policy")

// PolicyConfig configures a Policy. It deliberately has no failure-policy
// field: a failed rule is always refused. A nil Sink means audit.NoopSink{},
// and a Timeout <= 0 means DefaultRuleTimeout.
type PolicyConfig struct {
	Sink    audit.AuditSink
	Timeout time.Duration
}

// SubstitutionRequest is a request-phase Redact effect: replace [Start, End) in
// the named leaf with a placeholder of the named category. It is the only place
// a substitution is ever requested — the response path can never carry one.
type SubstitutionRequest struct {
	RuleID    string
	Origin    Origin
	LeafIndex int
	Start     int
	End       int
	Category  string
}

// Warning is a response-phase Warn effect: metadata only. The response is
// forwarded unchanged and no counter changes.
type Warning struct {
	RuleID string
	Origin Origin
}

// Decision is the core's verdict for one content phase. Action is the highest
// precedence among the findings; Findings holds exactly the findings that back
// Action, in core order, each naming the rule and origin the core stamped.
// Substitutions is populated only for a request-phase Redact (the sole
// substitution request), Warnings only for a response-phase Warn, and a
// response-phase Block is a rule-block decision whose findings name the rule
// id. Refusal is non-nil when a rule failed: the caller must refuse the request
// with the labelled reason, and Action is Block so a refusal can never be read
// as an allow.
type Decision struct {
	Phase         Scope
	Action        Action
	Findings      []AttributedFinding
	Substitutions []SubstitutionRequest
	Warnings      []Warning
	Refusal       *RuleFailure
}

// Policy is the core's action policy over a snapshot of the registry. It is
// safe for concurrent use: the entries are immutable after construction and
// Decide keeps no state.
type Policy struct {
	entries []registryEntry
	sink    audit.AuditSink
	timeout time.Duration
}

// NewPolicy returns a policy over the registry's rules as they are now: later
// registration does not change an existing policy. A nil registry means no
// rules and therefore Allow.
func NewPolicy(reg *Registry, cfg PolicyConfig) *Policy {
	sink := cfg.Sink
	if sink == nil {
		sink = audit.NoopSink{}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultRuleTimeout
	}
	var entries []registryEntry
	if reg != nil {
		entries = append(entries, reg.entries...)
	}
	return &Policy{entries: entries, sink: sink, timeout: timeout}
}

// Decide evaluates the policy's rules over leaves for phase and returns the
// aggregated verdict. A rule failure is a labelled Refusal in the Decision, not
// an error: an error is returned only for a nil policy or an undefined phase.
// The direction effects are populated here and nowhere else, so a response-phase
// Rule can never yield a substitution request.
func (p *Policy) Decide(leaves []protocol.Leaf, phase Scope) (Decision, error) {
	if p == nil {
		return Decision{}, ErrNilPolicy
	}
	if phase != ScopeRequest && phase != ScopeResponse {
		return Decision{}, fieldError(ErrInvalidValue, "phase", "unknown decision phase %q", phase)
	}
	findings, failure := collect(p.entries, leaves, phase, p.timeout)
	decision := Decision{Phase: phase}
	if failure != nil {
		decision.Action = ActionBlock
		decision.Refusal = failure
		p.record(phase, failure)
		return decision, nil
	}
	decision.Action = aggregateAction(findings)
	for i := range findings {
		finding := findings[i]
		if finding.Action != decision.Action {
			continue
		}
		decision.Findings = append(decision.Findings, finding)
		if phase == ScopeRequest && finding.Action == ActionRedact {
			decision.Substitutions = append(decision.Substitutions, SubstitutionRequest{
				RuleID: finding.RuleID, Origin: finding.Origin, LeafIndex: finding.LeafIndex,
				Start: finding.Start, End: finding.End, Category: finding.Category,
			})
			continue
		}
		if phase == ScopeResponse && finding.Action == ActionWarn {
			decision.Warnings = append(decision.Warnings, Warning{RuleID: finding.RuleID, Origin: finding.Origin})
		}
	}
	return decision, nil
}

// record writes one metadata-only audit record for a rule failure. A nil sink
// stays silent by design: the sink is the only persistence seam, and its
// failure must never mask the refusal.
func (p *Policy) record(phase Scope, failure *RuleFailure) {
	if p.sink == nil {
		return
	}
	_ = p.sink.Record(context.Background(), audit.Record{
		Time:    time.Now().UTC(),
		Method:  policyAuditMethod,
		Path:    string(phase),
		RuleIDs: []string{policyFailureTag, failure.RuleID, string(failure.Reason)},
	})
}

// actionRank returns the frozen precedence of an action: Allow < Warn < Redact
// < Block. An unknown action ranks below Allow and can never win.
func actionRank(action Action) int {
	switch action {
	case ActionAllow:
		return 0
	case ActionWarn:
		return 1
	case ActionRedact:
		return 2
	case ActionBlock:
		return 3
	default:
		return -1
	}
}

// aggregateAction returns the highest-precedence action among findings, or
// Allow when there are none.
func aggregateAction(findings []AttributedFinding) Action {
	best := ActionAllow
	for i := range findings {
		if actionRank(findings[i].Action) > actionRank(best) {
			best = findings[i].Action
		}
	}
	return best
}
