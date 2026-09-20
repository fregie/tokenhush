package proxy

// response_sse_buffered.go is the whole-response text/event-stream half of the
// client-bound path. Unlike the incremental SSEHandler, the gateway buffers the
// entire upstream SSE response before it commits, so a response-scoped Block is
// a clean 502 with nothing already sent. This file owns two passes -- evaluate
// every event whose joined Data is valid JSON (the frozen B-FD6 counter
// matrix), then restore placeholders and emit -- plus the Content-Encoding
// decode; internal/cli only classifies the response and commits the returned
// verdict.
//
// Decode, evaluation and restore all live here because the normalization guard
// allows compress/gzip|flate only in direct children of pkg/proxy, never in
// internal/cli. Decoded bytes are evaluated, never fed to a detector Inspect:
// there is no normalization pass and a decoded value never reaches detection.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// HandleBufferedSSE buffers one upstream text/event-stream response and returns
// the status, headers and body to commit to the client. It decodes every
// declared Content-Encoding, evaluates each event whose joined Data is valid
// JSON (a JSON event whose Walk fails counts exactly one walk skip, a non-JSON
// event none), aggregates any response-scoped Block into a 502 before any byte
// is committed, and restores session placeholders in a final pass. It reads
// upstream.Body to EOF without closing it: the caller owns it.
func (h *ResponseHandler) HandleBufferedSSE(upstream *http.Response) (int, http.Header, []byte, error) {
	if upstream == nil {
		return 0, nil, nil, ErrNilResponse
	}
	raw, err := readAll(upstream)
	if err != nil {
		return refuse(http.StatusBadGateway, refusalUnreadable, "")
	}
	codings, ok := declaredCodings(upstream.Header.Values("Content-Encoding"))
	if !ok {
		return refuse(http.StatusBadGateway, refusalUndecodable, "")
	}
	body, ok := decodeAll(raw, codings)
	if !ok {
		return refuse(http.StatusBadGateway, refusalUndecodable, "")
	}
	if h.evaluator != nil {
		decision, blocked := h.evaluateSSE(clientContext(upstream), body)
		if blocked {
			return refuse(http.StatusBadGateway, refusalRuleBlocked, primaryRule(decision.RuleIDs))
		}
	}
	body = restoreSSE(body, h.backfiller)
	header := make(http.Header, len(upstream.Header))
	copyEndToEndHeaders(header, upstream.Header)
	if len(codings) > 0 {
		header.Del("Content-Encoding")
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return upstream.StatusCode, header, body, nil
}

// evaluateSSE is pass 1: it runs the frozen B-FD6 counter matrix over a decoded
// SSE body. Every event whose joined Data is valid JSON is evaluated -- the
// single-canonical-data-line DataSpans condition is not the evaluation gate, it
// only serves restore -- so a multi-data-line event is evaluated too. A JSON
// event whose Walk fails counts exactly one walk skip; a non-JSON Data value,
// [DONE], ping/comment, comment-only and zero-leaf event count none. The
// verdicts aggregate: any Block wins, else any Warn, else Allow; the counters,
// warning lines and named rule move exactly once, deduped and sorted. The
// second return is true only for a Block, which the caller turns into a 502.
func (h *ResponseHandler) evaluateSSE(ctx context.Context, body []byte) (ResponseDecision, bool) {
	var blockIDs, warnIDs []string
	blocked := false
	for _, ev := range decodeSSE(body) {
		if !json.Valid(ev.Data) {
			continue
		}
		decision, err := h.evaluator.EvaluateResponse(ctx, ev.Data)
		if err != nil {
			h.counters.countWalkSkip()
			continue
		}
		switch decision.Action {
		case ResponseWarn:
			warnIDs = append(warnIDs, decision.RuleIDs...)
		case ResponseAllow:
		default:
			// ResponseBlock, and any undefined action, fails closed exactly
			// as the non-SSE buffered path's evaluation does.
			blocked = true
			blockIDs = append(blockIDs, decision.RuleIDs...)
		}
	}
	if blocked {
		h.counters.countContentPolicyBlock()
		h.counters.countRuleBlock()
		return ResponseDecision{Action: ResponseBlock, RuleIDs: sortedRuleIDs(blockIDs)}, true
	}
	if len(warnIDs) > 0 {
		rules := sortedRuleIDs(warnIDs)
		h.warn(rules)
		return ResponseDecision{Action: ResponseWarn, RuleIDs: rules}, false
	}
	return ResponseDecision{Action: ResponseAllow}, false
}

// decodeSSE returns every record of a fully buffered SSE body in order,
// including the trailing record the decoder flushes on Close. SSE has no
// malformed input, so the decoder's only error is ErrClosed, which cannot occur
// here; a decode problem can never fail a response closed.
func decodeSSE(body []byte) []protocol.Event {
	dec := protocol.NewDecoder()
	events, _ := dec.Feed(body)
	tail, _ := dec.Close()
	return append(events, tail...)
}

// restoreSSE is pass 2: the whole decoded body goes through one
// redact.SSEBackfiller, so a placeholder split across events is restored
// exactly once, in the completing event, and every emitted envelope stays
// byte-exact. A nil backfiller mints nothing and the stream round-trips
// byte-identically.
func restoreSSE(body []byte, backfiller Backfiller) []byte {
	stream := redact.NewSSEBackfiller(backfiller, nil)
	return append(stream.Write(body), stream.Flush()...)
}

// sortedRuleIDs returns ids deduplicated and sorted, so an aggregate writes one
// warning line per distinct rule and names the first deterministically. It
// returns nil for no ids.
func sortedRuleIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
