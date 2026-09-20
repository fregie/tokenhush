package proxy

// response_sse_buffered.go is the whole-response text/event-stream half of the
// client-bound path. Unlike the incremental SSEHandler, the gateway buffers the
// entire upstream SSE response before it commits, so a response-scoped Block is
// a clean 502 with nothing already sent. This file owns two passes -- evaluate
// every event whose joined Data is valid JSON, then restore placeholders and
// emit -- plus the Content-Encoding decode; internal/cli only classifies the
// response and commits the returned verdict.
//
// PROVISIONAL (todo 5): HandleBufferedSSE is a compile-only skeleton that lets
// the Wave-1 regression tests in response_sse_buffered_test.go compile and fail
// on their assertions. It deliberately does not decode, evaluate or restore;
// todo 18 implements the documented behavior and turns those reds green.

import "net/http"

// HandleBufferedSSE buffers one upstream text/event-stream response and returns
// the status, headers and body to commit to the client. It decodes every
// declared Content-Encoding, evaluates each event whose joined Data is valid
// JSON (a JSON event whose Walk fails counts exactly one walk skip, a non-JSON
// event none), aggregates a response-scoped Block into a 502 before any byte is
// committed, and restores session placeholders in a final pass. It reads
// upstream.Body to EOF without closing it: the caller owns it.
//
// TODO(todo 18): implement the documented behavior. This stub returns the
// upstream status and headers with an empty body and moves no counter.
func (h *ResponseHandler) HandleBufferedSSE(upstream *http.Response) (int, http.Header, []byte, error) {
	if upstream == nil {
		return 0, nil, nil, ErrNilResponse
	}
	return upstream.StatusCode, upstream.Header.Clone(), []byte{}, nil
}
