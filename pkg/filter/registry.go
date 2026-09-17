package filter

// registry.go is the public rule registry: the single extension entry point of
// the rule abstraction. A third party implements the frozen Rule contract in
// its own package and registers the value here. The core, never the rule,
// stamps the finding's rule id, the action it carries and the provenance origin
// it was registered with, so a rule cannot spoof another rule or its own
// origin. Registration is the security gate: it validates the whole batch
// before it mutates anything, so a rejected registration leaves the registry
// exactly as it was. Ordering is deterministic — ascending Priority, ties
// broken by ID — and identical to the compiled-document path, so a rule cannot
// evaluate in one order as a document and another as a registered value.
// Directly-registered rules are rejected when their scope includes the response
// phase and their action is redact: the same direction contract the compiler
// enforces for documents (W3.4), re-asserted here, and again at evaluation. A
// failing rule fails closed with a labelled reason — never a silent pass, never
// a crash. There is deliberately no capability tier, no gate, no phase beyond
// Scope and no failure-policy negotiation.

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// Origin is the core-owned provenance of a registered rule: where the core
// obtained it, not what the rule claims about itself. It is recorded at
// registration and never changes.
type Origin string

// The three origins: builtin is a rule compiled into the binary, remote_pack
// is a rule that arrived in a compiled document, and plugin is a rule a third
// party registered directly.
const OriginBuiltin, OriginRemotePack, OriginPlugin Origin = "builtin", "remote_pack", "plugin"

// Reason is the core's classification of a rule failure.
type Reason string

// The five failure reasons: budget is a rule that exceeded its span budget,
// timeout a rule that exceeded its wall-clock bound, error a rule the core
// could not invoke at all, panic a rule that panicked, and malformed a rule
// whose metadata or spans violate the contract.
const ReasonBudget, ReasonTimeout, ReasonError, ReasonPanic, ReasonMalformed Reason = "budget", "timeout", "error", "panic", "malformed"

// DefaultRuleTimeout bounds one rule invocation when no timeout is configured.
const DefaultRuleTimeout = 30 * time.Second

// MaxRuleSpans bounds the spans one rule invocation may return. More is a
// budget failure, never a silent truncation.
const MaxRuleSpans = MaxMatches

// ErrInvalidRule rejects a rule that cannot be registered at all:
// errors.Is(err, ErrInvalidRule) classifies the rejection.
var ErrInvalidRule = errors.New("filter: invalid rule")

// ErrDuplicateID rejects a second registration of an id already present.
var ErrDuplicateID = errors.New("filter: duplicate rule id")

// ErrRuleFailure classifies a fail-closed evaluation failure.
var ErrRuleFailure = errors.New("filter: rule failure")

// ErrNilRegistry is returned by a Registry method on a nil receiver.
var ErrNilRegistry = errors.New("filter: nil registry")

// RuleFailure is the fail-closed verdict of one rule invocation: which rule
// failed, the provenance of that rule and the classified reason. The reason is
// always one of the five Reason values. errors.Is(err, ErrRuleFailure)
// classifies the verdict.
type RuleFailure struct {
	RuleID string
	Origin Origin
	Reason Reason
}

// Error renders `filter: rule <id> failed: <reason>`.
func (e *RuleFailure) Error() string {
	return "filter: rule " + e.RuleID + " failed: " + string(e.Reason)
}

// Unwrap returns ErrRuleFailure.
func (e *RuleFailure) Unwrap() error { return ErrRuleFailure }

// AttributedFinding is one core-stamped finding: the embedded Finding names the
// rule, category, action, span and confidence the core accepted, and Origin is
// the provenance the core recorded at registration. A rule supplies spans only.
type AttributedFinding struct {
	Finding
	Origin Origin
}

// registryEntry is one registration. The id and rank are read at registration
// time so ordering and failure reporting never depend on a rule implementation
// that mutates after registration.
type registryEntry struct {
	rule   Rule
	origin Origin
	id     string
	rank   int
}

// Registry holds the rules the core evaluates. Registration is expected before
// evaluation starts; a constructed registry is read-only afterwards, and
// Evaluate keeps no state, so concurrent evaluations are safe.
type Registry struct {
	entries []registryEntry
	ids     map[string]bool
}

// NewRegistry returns an empty, ready registry.
func NewRegistry() *Registry { return &Registry{ids: make(map[string]bool)} }

// Register registers rules as third-party plugins (OriginPlugin): the external
// extension path. The whole batch is validated before any mutation, so a
// rejected registration changes nothing. A duplicate id, an invalid id or
// metadata, and a response-capable redact rule are rejected with a typed error
// naming the rule.
func (r *Registry) Register(rules ...Rule) error { return r.add(OriginPlugin, rules) }

// RegisterBuiltin registers rules compiled into the binary (OriginBuiltin).
func (r *Registry) RegisterBuiltin(rules ...Rule) error { return r.add(OriginBuiltin, rules) }

// RegisterCompiled registers every evaluable rule of a compiled document as a
// remote pack (OriginRemotePack). The registry orders them exactly like the
// compiled set does — ascending Priority, ties broken by ID — and per-rule and
// global allowlists stay in force through the registration.
func (r *Registry) RegisterCompiled(set *Compiled) error {
	if set == nil {
		return fmt.Errorf("%w: nil compiled set", ErrInvalidRule)
	}
	rules := make([]Rule, len(set.rules))
	for i := range set.rules {
		rules[i] = compiledView{set: set, rule: &set.rules[i]}
	}
	return r.add(OriginRemotePack, rules)
}

// Evaluate runs every registered rule whose scope covers phase over every value
// leaf in deterministic (ascending priority, then id) order and returns the
// core-stamped findings sorted by (leaf, start, end). The sort is stable, so an
// exact-span tie keeps the rule invocation order. A rule that is nil, panics,
// times out, exceeds its span budget or returns malformed metadata or spans
// fails closed with a labelled *RuleFailure — never a partial result and never
// a crash.
func (r *Registry) Evaluate(leaves []protocol.Leaf, phase Scope) ([]AttributedFinding, error) {
	if r == nil {
		return nil, ErrNilRegistry
	}
	if phase != ScopeRequest && phase != ScopeResponse {
		return nil, fieldError(ErrInvalidValue, "phase", "unknown evaluation phase %q", phase)
	}
	findings, failure := collect(r.entries, leaves, phase, DefaultRuleTimeout)
	if failure != nil {
		return nil, failure
	}
	return findings, nil
}

// add validates every candidate against the current registry and the rest of
// the batch before it mutates anything: nothing is stored unless every check
// passes. The direction contract is validated here, before any mutation, and
// the first registration of a conflicting id is left untouched.
func (r *Registry) add(origin Origin, rules []Rule) error {
	if r == nil {
		return ErrNilRegistry
	}
	pending := make([]registryEntry, 0, len(rules))
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if isNilRule(rule) {
			return fmt.Errorf("%w: nil rule", ErrInvalidRule)
		}
		id := rule.ID()
		if !ruleIDPattern.MatchString(id) {
			return fmt.Errorf("%w: id %q must match %s", ErrInvalidRule, id, ruleIDPattern)
		}
		if r.ids[id] || seen[id] {
			return fmt.Errorf("%w: rule %q", ErrDuplicateID, id)
		}
		scope, action := rule.Scope(), rule.Action()
		if !scopeValues[string(scope)] {
			return fmt.Errorf("%w: rule %q declares unknown scope %q", ErrInvalidRule, id, scope)
		}
		if !actionValues[string(action)] {
			return fmt.Errorf("%w: rule %q declares unknown action %q", ErrInvalidRule, id, action)
		}
		if (scope == ScopeResponse || scope == ScopeBoth) && action == ActionRedact {
			return fmt.Errorf("%w: rule %q: a rule that includes the response phase must not redact", ErrDirection, id)
		}
		if confidence := rule.Confidence(); !(confidence > 0 && confidence <= 1) {
			return fmt.Errorf("%w: rule %q has confidence %v outside (0,1]", ErrInvalidRule, id, confidence)
		}
		seen[id] = true
		pending = append(pending, registryEntry{rule: rule, origin: origin, id: id, rank: rule.Priority()})
	}
	if r.ids == nil {
		r.ids = make(map[string]bool, len(pending))
	}
	for i := range pending {
		r.entries = append(r.entries, pending[i])
		r.ids[pending[i].id] = true
	}
	sort.SliceStable(r.entries, func(i, j int) bool {
		if r.entries[i].rank != r.entries[j].rank {
			return r.entries[i].rank < r.entries[j].rank
		}
		return r.entries[i].id < r.entries[j].id
	})
	return nil
}

// compiledView presents one compiled rule as a Rule so a compiled document can
// be registered. Inspect keeps the rule's own and the document's allowlists in
// force, so the registered path suppresses exactly what the document path does.
type compiledView struct {
	set  *Compiled
	rule *compiledRule
}

func (v compiledView) ID() string          { return v.rule.id }
func (v compiledView) Type() string        { return v.rule.typ }
func (v compiledView) Category() string    { return v.rule.category }
func (v compiledView) Scope() Scope        { return v.rule.scope }
func (v compiledView) Action() Action      { return v.rule.action }
func (v compiledView) Priority() int       { return v.rule.priority }
func (v compiledView) Confidence() float64 { return v.rule.confidence }

// Inspect returns the rule's spans with every allowlist-suppressed match
// removed, exactly as the document evaluator would.
func (v compiledView) Inspect(leaf []byte) []Span {
	spans := v.rule.spans(leaf)
	kept := spans[:0]
	for _, span := range spans {
		if allowlistSuppressed(leaf, span, v.set.allowlist, v.rule.allow) {
			continue
		}
		kept = append(kept, span)
	}
	return kept
}

// isNilRule reports whether rule is nil, including a typed-nil pointer stored
// in the interface, whose methods would panic if they were called.
func isNilRule(rule Rule) bool {
	if rule == nil {
		return true
	}
	value := reflect.ValueOf(rule)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

// invocation is one guarded rule call's result.
type invocation struct {
	spans  []Span
	meta   ruleMeta
	reason Reason
}

// ruleMeta is the rule metadata the core read under the guard.
type ruleMeta struct {
	category   string
	scope      Scope
	action     Action
	confidence float64
}

// invoke calls rule.Inspect(leaf) under the core's guard: panic recovery, a
// wall-clock timeout, and the metadata and span contract. It returns the
// accepted spans and metadata, or the labelled reason the rule failed. A rule
// whose scope does not cover phase is never inspected, and a rule that may
// evaluate in the response phase may never redact — that rejection is repeated
// here so no arrival route can bypass it.
func invoke(rule Rule, leaf []byte, phase Scope, timeout time.Duration) invocation {
	if isNilRule(rule) {
		return invocation{reason: ReasonError}
	}
	if timeout <= 0 {
		timeout = DefaultRuleTimeout
	}
	ch := make(chan invocation, 1)
	go func() {
		defer func() {
			if recover() != nil {
				ch <- invocation{reason: ReasonPanic}
			}
		}()
		meta := ruleMeta{rule.Category(), rule.Scope(), rule.Action(), rule.Confidence()}
		if !scopeValues[string(meta.scope)] || !actionValues[string(meta.action)] || !(meta.confidence > 0 && meta.confidence <= 1) ||
			((meta.scope == ScopeResponse || meta.scope == ScopeBoth) && meta.action == ActionRedact) {
			ch <- invocation{meta: meta, reason: ReasonMalformed}
			return
		}
		if meta.scope != phase && meta.scope != ScopeBoth {
			ch <- invocation{meta: meta}
			return
		}
		spans := rule.Inspect(leaf)
		if len(spans) > MaxRuleSpans {
			ch <- invocation{meta: meta, reason: ReasonBudget}
			return
		}
		for _, span := range spans {
			if span.Start < 0 || span.Start >= span.End || span.End > len(leaf) {
				ch <- invocation{meta: meta, reason: ReasonMalformed}
				return
			}
		}
		ch <- invocation{spans: spans, meta: meta}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-ch:
		return result
	case <-timer.C:
		return invocation{reason: ReasonTimeout}
	}
}

// collect runs every entry over every value leaf in deterministic order and
// returns the attributed findings sorted by (leaf, start, end), or the first
// labelled failure. The total is bounded by MaxMatches: more is a budget
// failure, never a truncation. The sort is stable, so an exact-span tie keeps
// the invocation order.
func collect(entries []registryEntry, leaves []protocol.Leaf, phase Scope, timeout time.Duration) ([]AttributedFinding, *RuleFailure) {
	if timeout <= 0 {
		timeout = DefaultRuleTimeout
	}
	var out []AttributedFinding
	for index := range leaves {
		value := leaves[index].Value
		if len(value) == 0 {
			continue
		}
		for i := range entries {
			entry := entries[i]
			result := invoke(entry.rule, value, phase, timeout)
			if result.reason != "" {
				return nil, &RuleFailure{RuleID: entry.id, Origin: entry.origin, Reason: result.reason}
			}
			if result.meta.scope != phase && result.meta.scope != ScopeBoth {
				continue
			}
			if len(out)+len(result.spans) > MaxMatches {
				return nil, &RuleFailure{RuleID: entry.id, Origin: entry.origin, Reason: ReasonBudget}
			}
			for _, span := range result.spans {
				out = append(out, AttributedFinding{
					Finding: Finding{RuleID: entry.id, Category: result.meta.category, Action: result.meta.action, LeafIndex: index, Start: span.Start, End: span.End, Confidence: result.meta.confidence},
					Origin:  entry.origin,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.LeafIndex != b.LeafIndex {
			return a.LeafIndex < b.LeafIndex
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		return a.End < b.End
	})
	return out, nil
}
