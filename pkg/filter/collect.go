package filter

// collect.go houses the shared evaluation loop behind the registered (Registry)
// and runtime (Policy) paths. It was split out of registry.go so both files
// stay under the pure-LOC ceiling once the Feature-A sensitive-key gate became
// part of the loop. The gate is the behaviour the compiled path and this loop
// share: a request-phase leaf whose immediate member key is configured is not
// handed to Redact-producing rules and yields one whole-value finding instead,
// while Block-producing rules keep their precedence.

import (
	"sort"
	"time"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// collect runs every entry over every value leaf in deterministic order and
// returns the attributed findings sorted by (leaf, start, end), or the first
// labelled failure. The total is bounded by MaxMatches: more is a budget
// failure, never a truncation. The sort is stable, so an exact-span tie keeps
// the invocation order. A request-phase leaf whose immediate member key matches
// sensitive is gated: Redact-producing rules are skipped for it and one
// whole-value OriginRemotePack finding is emitted unless an allowlisted literal
// covers the value. A Block-producing rule is still evaluated, so the gate can
// never suppress a block.
func collect(entries []registryEntry, sensitive *sensitiveMatcher, leaves []protocol.Leaf, phase Scope, timeout time.Duration) ([]AttributedFinding, *RuleFailure) {
	if timeout <= 0 {
		timeout = DefaultRuleTimeout
	}
	var out []AttributedFinding
	for index := range leaves {
		value := leaves[index].Value
		if len(value) == 0 {
			continue
		}
		gated := phase == ScopeRequest && sensitive.matches(leaves[index])
		for i := range entries {
			entry := entries[i]
			result := invoke(entry.rule, value, phase, timeout)
			if result.reason != "" {
				return nil, &RuleFailure{RuleID: entry.id, Origin: entry.origin, Reason: result.reason}
			}
			if result.meta.scope != phase && result.meta.scope != ScopeBoth {
				continue
			}
			if gated && result.meta.action == ActionRedact {
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
		if gated && !sensitive.allows(value) {
			if len(out) >= MaxMatches {
				return nil, &RuleFailure{RuleID: sensitiveKeyRuleID, Origin: OriginRemotePack, Reason: ReasonBudget}
			}
			out = append(out, AttributedFinding{Finding: sensitiveKeyFinding(index, value), Origin: OriginRemotePack})
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
