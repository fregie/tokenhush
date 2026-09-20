package proxy

// response_sse.go is the streaming, client-bound half of invariant 8. The
// reassembly itself -- the single bounded accumulator (one
// protocol.BackfillWriter over the frozen placeholder grammar), one persistent
// protocol.Decoder and the lag-by-one-event release rule -- lives in
// pkg/redact's SSEBackfiller, the canonical owner. This file is the transport
// layer over it and nothing more: the handler restores placeholders and never
// decides. Response-scoped evaluation moved to the whole-response buffered path
// in response_sse_buffered.go, so a response-scoped Block is a clean 502 before
// any byte is committed and no production path emits an in-stream error record.
//
// The response path can hold no forward-only placeholder writer: the only
// substitution seam reachable from here is the injected Backfiller, and the
// reassembler routes one complete token through Backfill(token). The reverse
// map and the exclusion set stay in pkg/redact.

import (
	"context"
	"errors"

	"github.com/fregie/tokenhush/pkg/redact"
)

// ErrSSEClosed reports a Write after Flush terminated the stream.
var ErrSSEClosed = errors.New("proxy: sse stream closed")

// SSEResponseConfig wires the SSE handler's injectable seams. Evaluator,
// Counters and Warnings are retained for API compatibility but are INERT: this
// handler does not evaluate, so no production path can emit an in-stream block
// record. Response-scoped decisions belong to the whole-response buffered path
// (HandleBufferedSSE). A nil Backfiller is the identity transform and a nil
// Context means context.Background().
type SSEResponseConfig struct {
	Context    context.Context
	Evaluator  Evaluator
	Backfiller Backfiller
	Counters   *Counters
	Warnings   WarningWriter
}

// SSEHandler incrementally restores placeholders in one client-bound SSE
// stream. It owns no accumulator of its own: redact.SSEBackfiller is the
// stream's single bounded accumulator and decoder. It evaluates nothing.
//
// SSEHandler is stateful and not safe for concurrent use: it serves exactly one
// response. Write returns the bytes that are final now; Flush finalizes.
type SSEHandler struct {
	stream *redact.SSEBackfiller
}

// NewSSEHandler returns a handler over the configured seams. Nil seams take
// their documented inert defaults, so a handler always exists. Evaluator,
// Counters and Warnings are accepted and ignored: the field set is kept only so
// existing callers keep compiling.
func NewSSEHandler(cfg SSEResponseConfig) *SSEHandler {
	return &SSEHandler{stream: redact.NewSSEBackfiller(cfg.Backfiller, nil)}
}

// Write accepts the next upstream chunk and returns the bytes that are final
// now: the released prefix of the reassembler's segment queue. A chunk may
// split records at any byte boundary. After Flush it returns ErrSSEClosed.
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

// closed reports whether Flush terminated the stream.
func (h *SSEHandler) closed() bool { return h.stream.Closed() }
