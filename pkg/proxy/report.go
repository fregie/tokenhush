package proxy

import (
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// Redaction action labels for RedactionEvent.Action.
const (
	// RedactionActionRedact marks a value that was replaced with a placeholder.
	RedactionActionRedact = "redact"
	// RedactionActionBlock marks content the policy rejected before egress.
	RedactionActionBlock = "block"
	// RedactionActionResponseWalkFailed marks a client-bound buffered response
	// body the response-path walker could not parse. Nothing is blocked: the
	// body is still forwarded (and backfilled). See transformResponse.
	RedactionActionResponseWalkFailed = "response_walk_failed"
	// RedactionActionSSEWalkFailed marks an SSE payload whose emit-time walk
	// failed (the desync guard in ssebackfill_rewrite.go). Nothing is blocked:
	// the original event bytes are written verbatim.
	RedactionActionSSEWalkFailed = "sse_walk_failed"
	// RedactionActionEgressBlocked marks an outbound request the W2.3 egress
	// re-check blocked: after redaction the body still carried a secret the
	// engine had mapped to a placeholder, so forwarding it would have restored
	// the plaintext upstream. The event carries the matched placeholder token
	// in Placeholder and nothing else.
	RedactionActionEgressBlocked = "egress_blocked"
	// RedactionActionMutationChannelBlocked marks one client-bound tool call
	// whose arguments reached the C8 mutation channel and were rewritten to the
	// refusal notice (W6.3, buffered response path). The response itself is
	// still delivered per tool call, so this is not a RedactionActionBlock. The
	// event carries only the matched channel class in Type — never the
	// arguments, a JSON path or any byte of the refused content. It is the
	// metadata hook W6.5 turns into an audit row and a status counter.
	RedactionActionMutationChannelBlocked = "mutation_channel_blocked"
)

// Redaction directions for RedactionEvent.Direction.
const (
	// RedactionDirectionRequest is the outbound direction: the pipeline
	// redacts and blocks there.
	RedactionDirectionRequest = "request"
	// RedactionDirectionResponse is the client-bound direction. Inbound data is
	// only backfilled, so no redact or block event uses it; it reports the
	// response/SSE bodies the walker could not parse (observability only — an
	// unparseable body is still forwarded byte-identically).
	RedactionDirectionResponse = "response"
)

// RedactionEvent describes one content decision for a human log. It carries no
// content beyond a masked preview, and deliberately has no JSON path: object
// keys are attacker-controlled and are not redacted, so logging a path could
// leak un-redacted content. The two walk-failure actions report even less: a
// skipped body must never surface its bytes, keys or paths, so Type, Length
// and Masked stay empty for them.
type RedactionEvent struct {
	// Action is RedactionActionRedact, RedactionActionBlock,
	// RedactionActionResponseWalkFailed, RedactionActionSSEWalkFailed or
	// RedactionActionEgressBlocked.
	Action string
	// Direction is RedactionDirectionRequest or RedactionDirectionResponse.
	Direction string
	// Phase is the content phase label (for example "request_content" or
	// "response_content").
	Phase string
	// Type is the detector type (for example "api_key").
	Type string
	// Length is the byte length of the matched value; 0 for a block.
	Length int
	// Masked is the redact.MaskSecret form; empty for a block.
	Masked string
	// Placeholder is the matched secret's placeholder token, set only for
	// RedactionActionEgressBlocked. It is a placeholder token by construction,
	// never plaintext: the membership check that produces it returns the
	// engine's token (W2.1). It is the only content-bearing field this action
	// populates — Type, Length and Masked stay empty for it — and every other
	// action leaves it empty.
	Placeholder string
}

// RedactionReporter receives one event per replaced span (Redact), per blocked
// finding (Block), per response/SSE body the walker could not parse (the two
// walk-failure actions), and per blocked egress finding (EgressBlocked). The
// pipeline invokes it from request goroutines, so an implementation must be
// safe for concurrent use and must not block or call back into the pipeline.
type RedactionReporter func(RedactionEvent)

// SetRedactionReporter installs the reporter that observes redaction and block
// decisions. Call it before the gateway starts serving: the reporter is held in
// an atomic pointer, so a reporter set once before Run is read race-free by
// every request goroutine. A nil reporter disables reporting.
func (p *Pipeline) SetRedactionReporter(reporter RedactionReporter) {
	if p == nil {
		return
	}
	if reporter == nil {
		p.reporter.Store(nil)
		return
	}
	p.reporter.Store(&reporter)
}

// report delivers one event when a reporter is installed. It runs on the hot
// path, so it returns immediately when none is set.
func (p *Pipeline) report(ev RedactionEvent) {
	if p == nil {
		return
	}
	if r := p.reporter.Load(); r != nil {
		(*r)(ev)
	}
}

// reportSpans emits one event per span the rewrite will replace. It recomputes
// the same merge ApplyPlaceholders applies, so a logged span and a replaced
// span always agree, and it reads only the terminal leaf's decoded content —
// exactly the bytes ApplyPlaceholders receives.
func (p *Pipeline) reportSpans(walked []protocol.Leaf, spans map[int][]redact.Redaction) {
	if p.reporter.Load() == nil {
		return
	}
	terminal := terminalLeaves(walked)
	for i := 0; i < len(terminal); i++ {
		rs := spans[i]
		if len(rs) == 0 {
			continue
		}
		content := []byte(terminal[i].Content)
		for _, r := range redact.NormalizeRedactions(rs, len(content)) {
			value := string(content[r.Start:r.End])
			p.report(RedactionEvent{
				Action:    RedactionActionRedact,
				Direction: RedactionDirectionRequest,
				Phase:     extension.RequestContent.String(),
				Type:      r.Type,
				Length:    len(value),
				Masked:    redact.MaskSecret(value, r.Type),
			})
		}
	}
}

// reportBlock emits one metadata-only event per blocked finding. A block aborts
// before egress, so no matched value is reported: only the detector type(s) that
// triggered the refusal. A synthetic fail-closed finding carries no span, so
// this path never reads content.
func (p *Pipeline) reportBlock(decision extension.Decision) {
	if p.reporter.Load() == nil {
		return
	}
	for _, f := range decision.Findings {
		p.report(RedactionEvent{
			Action:    RedactionActionBlock,
			Direction: RedactionDirectionRequest,
			Phase:     decision.Phase.String(),
			Type:      f.Type,
		})
	}
}

// noteResponseWalkFailure records one client-bound body the response-path
// walker could not parse: it increments ResponseWalkFailures and emits one
// metadata-only event. The response path deliberately does not fail closed
// (see transformResponse), so this counter and event are the only signal that
// a body was skipped — and they carry no body bytes, keys or paths, because
// object keys are attacker-controlled and un-redacted. action distinguishes
// the buffered path from the SSE desync guard.
func (p *Pipeline) noteResponseWalkFailure(action string) {
	if p == nil {
		return
	}
	p.responseWalkFailures.Add(1)
	p.report(RedactionEvent{
		Action:    action,
		Direction: RedactionDirectionResponse,
		Phase:     extension.ResponseContent.String(),
	})
}

// reportMutationChannelBlock emits one metadata-only event for a tool call the
// C8 guard rewrote to the refusal notice. W6.5 consumes this event for its
// audit row and status counter; W6.3 adds no counter of its own. The matched
// channel class is metadata, and no arguments, path or content byte is
// reported.
func (p *Pipeline) reportMutationChannelBlock(class string) {
	if p == nil {
		return
	}
	p.report(RedactionEvent{
		Action:    RedactionActionMutationChannelBlocked,
		Direction: RedactionDirectionResponse,
		Phase:     extension.ResponseContent.String(),
		Type:      class,
	})
}
