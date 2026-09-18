package cli

// redact_request.go is the outbound substitution seam, split out of cli.go to
// keep that file under the 250-pure-LOC ceiling. It walks the request body,
// reports a leaf that exceeds the effective detector budget (one metadata-only
// stderr line per request, so the residual is never silent), takes the
// request-phase decision and hands the redact spans to
// redact.Backfiller.Substitute, which maps each DECODED span back to the raw
// bytes that spell it (JSON string escaping means the two are not the same
// bytes) and counts only the substitutions that really changed the body. Each
// applied substitution is logged masked (stderr only) and recorded in the
// session backfiller, the only place the reverse mapping exists.

import (
	"fmt"

	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// redactRequest rewrites every request-phase redact span to this session's
// placeholder and reports how many substitutions actually changed bytes, so
// the assembler counts exactly that number. A body the walker cannot read is
// returned unchanged with zero substitutions, because the data plane has
// already refused a declared-JSON body that fails to walk; here it can only be
// legitimate non-JSON traffic. Substitutions whose raw span cannot be located
// are dropped by Substitute without minting a placeholder, so the reverse map
// never holds a placeholder for a secret that was never sent.
func (g *gateway) redactRequest(body []byte) ([]byte, int, error) {
	leaves, err := protocol.Walk(body)
	if err != nil {
		return body, 0, nil
	}
	g.reportBudgetExceeded(leaves)
	decision, err := g.policy.Decide(leaves, filter.ScopeRequest)
	if err != nil {
		return nil, 0, err
	}
	if decision.Refusal != nil || decision.Action == filter.ActionBlock {
		// Never client-visible: the data plane answers 403 before the body
		// reaches the forwarder, so this only fires outside the plane.
		return nil, 0, errBlocked
	}
	if decision.Action != filter.ActionRedact {
		return body, 0, nil
	}
	subs := make([]redact.Substitution, 0, len(decision.Substitutions))
	for _, request := range decision.Substitutions {
		if request.LeafIndex < 0 || request.LeafIndex >= len(leaves) {
			continue
		}
		subs = append(subs, redact.Substitution{
			Leaf: leaves[request.LeafIndex], Start: request.Start, End: request.End, Category: request.Category,
		})
	}
	out, applied, err := g.backfiller.Substitute(g.writer, body, subs)
	if err != nil {
		return nil, 0, err
	}
	for _, a := range applied {
		if !g.logRedactions || g.stderr == nil {
			continue
		}
		sub := subs[a.Index]
		secret := sub.Leaf.Value[sub.Start:sub.End]
		fmt.Fprintf(g.stderr, "tokenhush: redacted request %s (len=%d) %s\n", a.Category, a.Length, maskSecret(string(secret), a.Category))
	}
	return out, len(applied), nil
}

// reportBudgetExceeded emits at most one metadata-only stderr line per request
// when the longest leaf exceeds the effective detector budget. The line names
// only lengths, never rule ids or secret bytes, and no status key moves: the
// budget residual is observable, not counted.
func (g *gateway) reportBudgetExceeded(leaves []protocol.Leaf) {
	if g.budget <= 0 || g.stderr == nil {
		return
	}
	longest := 0
	for i := range leaves {
		if len(leaves[i].Value) > longest {
			longest = len(leaves[i].Value)
		}
	}
	if longest > g.budget {
		fmt.Fprintf(g.stderr, "tokenhush: detector budget exceeded leaf=%d budget=%d\n", longest, g.budget)
	}
}
