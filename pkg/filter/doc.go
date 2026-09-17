// Package filter is tokenhush's single rule abstraction: the rule and bundle
// document schema, the compiler, the evaluator, the public rule registry, the
// action policy, and the six built-in detector algorithms delivered as rule
// types.
//
// The registry is the one extension point. A third party implements Rule in
// its own package and registers the value; nothing else has to be exported,
// wrapped or negotiated. There are deliberately no capability tiers, no gates,
// no phases beyond Scope and no failure-policy negotiation: a registered rule
// is evaluated in ascending Priority order (ties broken by ID), and a rule that
// panics, times out, exceeds its budget or returns malformed output fails
// closed with a labelled reason instead of passing silently.
//
// A minimal external rule:
//
//	package myrules
//
//	import (
//		"bytes"
//
//		"github.com/fregie/tokenhush/pkg/filter"
//	)
//
//	type TicketRule struct{}
//
//	func (TicketRule) ID() string            { return "ticket" }
//	func (TicketRule) Type() string          { return filter.TypePrefix }
//	func (TicketRule) Category() string      { return filter.CategoryCustom }
//	func (TicketRule) Scope() filter.Scope   { return filter.ScopeRequest }
//	func (TicketRule) Action() filter.Action { return filter.ActionRedact }
//	func (TicketRule) Priority() int         { return 10 }
//	func (TicketRule) Confidence() float64   { return 0.95 }
//
//	func (TicketRule) Inspect(leaf []byte) []filter.Span {
//		at := bytes.Index(leaf, []byte("TICKET-"))
//		if at < 0 {
//			return nil
//		}
//		return []filter.Span{{Start: at, End: at + 7}}
//	}
//
// Registering and evaluating it:
//
//	reg := filter.NewRegistry()
//	if err := reg.Register(TicketRule{}); err != nil {
//		return err
//	}
//	findings, err := reg.Evaluate(leaves, filter.ScopeRequest)
//
// The direction contract is the one restriction a rule author must know:
// request content may be redacted, response content may only be blocked or
// warned. A rule whose Scope is response or both is rejected at registration
// when its Action is redact — the same rejection the compiler applies to a
// document rule — and no arrival route may request a substitution on the
// response path.
package filter
