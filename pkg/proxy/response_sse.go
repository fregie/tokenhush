package proxy

// response_sse.go is the streaming, client-bound half of invariant 8. The
// reassembly itself -- the single bounded accumulator (one
// protocol.BackfillWriter over the frozen placeholder grammar), one persistent
// protocol.Decoder and the lag-by-one-event release rule -- lives in
// pkg/redact's SSEBackfiller, the canonical owner. This file is the policy
// layer over it: the handler injects the response-scoped evaluation as
// redact's event observer, so the first whole event decides before any of its
// bytes are released.
//
// A response-scoped Block cannot be a 502 here: once headers and earlier
// deltas are on the wire the status cannot change and emitted bytes cannot be
// recalled. The decision is therefore taken at the FIRST whole-event
// evaluation -- the stream is held until it decides -- and a Block aborts the
// reassembler, which drops every held byte and returns exactly one SSE error
// record naming the rule id. Deltas already emitted before the decision point
// are unrecoverable, and docs/security.md states this.
//
// The response path can hold no forward-only placeholder writer: the only
// substitution seam reachable from here is the injected Backfiller, and the
// reassembler routes one complete token through Backfill(token). The reverse
// map and the exclusion set stay in pkg/redact.

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// ErrSSEClosed reports a Write after Flush or a Block terminated the stream.
var ErrSSEClosed = errors.New("proxy: sse stream closed")

// SSEResponseConfig wires the SSE handler's injectable seams. A nil Evaluator
// means no evaluation, a nil Backfiller is the identity transform, a nil
// Counters reads as zero and ignores increments, a nil WarningWriter drops
// warnings and a nil Context means context.Background().
type SSEResponseConfig struct {
	Context    context.Context
	Evaluator  Evaluator
	Backfiller Backfiller
	Counters   *Counters
	Warnings   WarningWriter
}

// SSEHandler incrementally restores placeholders in one client-bound SSE
// stream. It owns no accumulator of its own: redact.SSEBackfiller is the
// stream's single bounded accumulator and decoder, and this handler only
// decides, counts and warns.
//
// SSEHandler is stateful and not safe for concurrent use: it serves exactly one
// response. Write returns the bytes that are final now; Flush finalizes.
type SSEHandler struct {
	ctx       context.Context
	evaluator Evaluator
	counters  *Counters
	warnings  WarningWriter

	stream  *redact.SSEBackfiller
	decided bool
}

// NewSSEHandler returns a handler over the configured seams. Nil seams take
// their documented inert defaults, so a handler always exists.
func NewSSEHandler(cfg SSEResponseConfig) *SSEHandler {
	h := &SSEHandler{ctx: cfg.Context, evaluator: cfg.Evaluator, counters: cfg.Counters, warnings: cfg.Warnings}
	if h.ctx == nil {
		h.ctx = context.Background()
	}
	h.stream = redact.NewSSEBackfiller(cfg.Backfiller, h.observe)
	return h
}

// Write accepts the next upstream chunk and returns the bytes that are final
// now: the released prefix of the reassembler's segment queue. A chunk may
// split records at any byte boundary. After Flush or a Block it returns
// ErrSSEClosed.
func (h *SSEHandler) Write(chunk []byte) ([]byte, error) {
	if h.stream.Closed() {
		return nil, ErrSSEClosed
	}
	return h.stream.Write(chunk), nil
}

// Flush finalizes the stream: the reassembler's trailing record and held tail
// are released in order. It is idempotent: a second call returns nothing.
func (h *SSEHandler) Flush() ([]byte, error) { return h.stream.Flush(), nil }

// Held reports how many bytes the single bounded accumulator is holding back,
// never more than protocol.SSEBackfillHoldbackBytes.
func (h *SSEHandler) Held() int { return h.stream.Held() }

// closed reports whether Flush or a Block terminated the stream.
func (h *SSEHandler) closed() bool { return h.stream.Closed() }

// observe is the reassembler's event observer and deliberately the only
// evaluation: the decision is taken once, when the first whole event exists.
// It returns the single SSE error record on a Block, which aborts the
// reassembler; on Warn it writes one metadata-only warning line, on an
// evaluator error it counts a walk skip, and otherwise it returns nil.
func (h *SSEHandler) observe(ev protocol.Event) []byte {
	if h.decided {
		return nil
	}
	h.decided = true
	if h.evaluator == nil {
		return nil
	}
	decision, err := h.evaluator.EvaluateResponse(h.ctx, ev.Data)
	switch {
	case err != nil:
		h.counters.countWalkSkip()
	case decision.Action == ResponseWarn:
		h.warn(decision.RuleIDs)
	case decision.Action == ResponseAllow:
	default:
		h.counters.countContentPolicyBlock()
		h.counters.countRuleBlock()
		return blockedRecord(primaryRule(decision.RuleIDs))
	}
	return nil
}

// warn writes one metadata-only warning line per rule that backed a Warn
// decision; the rule id is quoted, so a hostile id cannot inject a line.
func (h *SSEHandler) warn(ruleIDs []string) {
	if h.warnings == nil {
		return
	}
	if len(ruleIDs) == 0 {
		h.warnings.Warn(warningPrefix)
		return
	}
	for _, id := range ruleIDs {
		h.warnings.Warn(warningPrefix + " rule=" + strconv.Quote(id))
	}
}

// sseErrorHead opens the single SSE error record a response-scoped Block emits
// once the first whole-event evaluation decides.
const sseErrorHead = "event: error\ndata: "

// blockedRecord renders that record: one error event whose data is the
// metadata-only refusal document naming the rule id. It carries no content.
func blockedRecord(ruleID string) []byte {
	body, _ := json.Marshal(refusal{Error: refusalRuleBlocked, RuleID: ruleID})
	return append(append([]byte(sseErrorHead), body...), '\n', '\n')
}
