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
)

// RedactionDirectionRequest is the only direction the pipeline reports: it
// redacts on the outbound request path. Inbound data is only backfilled.
const RedactionDirectionRequest = "request"

// RedactionEvent describes one content decision for a human log. It carries no
// content beyond a masked preview, and deliberately has no JSON path: object
// keys are attacker-controlled and are not redacted, so logging a path could
// leak un-redacted content.
type RedactionEvent struct {
	// Action is RedactionActionRedact or RedactionActionBlock.
	Action string
	// Direction is RedactionDirectionRequest.
	Direction string
	// Phase is the content phase label (for example "request_content").
	Phase string
	// Type is the detector type (for example "api_key").
	Type string
	// Length is the byte length of the matched value; 0 for a block.
	Length int
	// Masked is the redact.MaskSecret form; empty for a block.
	Masked string
}

// RedactionReporter receives one event per replaced span (Redact) or per
// blocked finding (Block). The pipeline invokes it from request goroutines, so
// an implementation must be safe for concurrent use and must not block or call
// back into the pipeline.
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
