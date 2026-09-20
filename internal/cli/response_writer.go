package cli

// response_writer.go is the client-bound half of the whole-response buffering
// rewrite (B-FD1). The writer intercepts the forwarder's response so the entire
// body is buffered and evaluated before the client sees a byte:
//
//   - WriteHeader records the status and headers only and never commits, for a
//     buffered body and for an event stream alike.
//   - Write appends to the buffer and enforces response_buffer_bytes; on
//     exceed it flags the cap and returns a sentinel that stops the upstream
//     copy.
//   - finish() is the single commit point. It runs after the forwarder
//     returns, decides the status (cap beats timeout) and commits exactly once:
//     the ordinary buffered response through ResponseHandler.Handle, an event
//     stream through ResponseHandler.HandleBufferedSSE.
//
// A locally generated response is marked through the proxy.ResponseRecorder
// seam (MarkLocal) and committed verbatim, never evaluated. The local marker is
// explicit rather than a status-code check on purpose: an upstream may
// legitimately answer with JSON 400/502/504, which must still be evaluated.
// RecordCopyError records the error that ended the upstream body copy, so a
// context.DeadlineExceeded becomes a 504 instead of a truncated 200.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/fregie/tokenhush/pkg/proxy"
)

// errResponseBufferExceeded is the sentinel Write returns once the buffered
// body would pass response_buffer_bytes. io.Copy stops on it and finish()
// maps the recorded flag to a 502 before any commit.
var errResponseBufferExceeded = errors.New("cli: response buffer cap exceeded")

// responseWriter intercepts the forwarder's client-bound response. It buffers
// every response whole; classification by Content-Type decides which response
// path finish() runs. It implements proxy.ResponseRecorder so the forwarder can
// mark its own error paths and report the copy error through a named seam.
type responseWriter struct {
	dst         http.ResponseWriter
	gate        *gateway
	req         *http.Request
	buf         bytes.Buffer
	status      int
	wroteStatus bool
	local       bool
	capExceeded bool
	timedOut    bool
	done        bool
}

// responseWriter implements the forwarder's optional recording seam.
var _ proxy.ResponseRecorder = (*responseWriter)(nil)

// Header implements http.ResponseWriter.
func (w *responseWriter) Header() http.Header { return w.dst.Header() }

// WriteHeader implements http.ResponseWriter. The status is recorded and never
// committed, so a cap or deadline refusal can still replace it before finish.
func (w *responseWriter) WriteHeader(status int) {
	if w.wroteStatus {
		return
	}
	w.wroteStatus, w.status = true, status
}

// Write implements http.ResponseWriter: the body accumulates in the buffer and
// is capped at response_buffer_bytes. Exceeding the cap flags the response and
// returns the sentinel, which stops the forwarder's io.Copy rather than
// draining the upstream.
func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wroteStatus {
		w.WriteHeader(http.StatusOK)
	}
	if w.capExceeded {
		return 0, errResponseBufferExceeded
	}
	if limit := w.gate.responseBufferBytes; limit > 0 && int64(w.buf.Len())+int64(len(p)) > limit {
		w.capExceeded = true
		return 0, errResponseBufferExceeded
	}
	return w.buf.Write(p)
}

// MarkLocal implements proxy.ResponseRecorder: the response about to be written
// is locally generated (415, 400, 500, 502, 504), so finish() commits it
// verbatim and excludes it from response evaluation.
func (w *responseWriter) MarkLocal() { w.local = true }

// RecordCopyError implements proxy.ResponseRecorder: a copy that ended on the
// request context's deadline is a response timeout, mapped to a 504 in finish.
func (w *responseWriter) RecordCopyError(err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		w.timedOut = true
	}
}

// finish completes the response after the forwarder returns. It is the single
// commit point and commits exactly once. The cap wins over the timeout, both
// are decided before any byte is committed, and a local response is committed
// verbatim without evaluation.
func (w *responseWriter) finish() {
	if w.done {
		return
	}
	w.done = true
	if !w.wroteStatus {
		w.wroteStatus, w.status = true, http.StatusOK
	}
	switch {
	case w.capExceeded:
		w.refuseLocal(http.StatusBadGateway)
	case w.timedOut:
		w.refuseLocal(http.StatusGatewayTimeout)
	case w.local:
		w.commitLocal()
	case streamingSSE(w.Header()):
		w.commitSSE()
	default:
		w.commitBuffered()
	}
}

// commitLocal writes a locally generated response exactly as the forwarder
// produced it, headers and body untouched.
func (w *responseWriter) commitLocal() {
	w.dst.WriteHeader(w.status)
	_, _ = w.dst.Write(w.buf.Bytes())
}

// commitBuffered runs the ordinary buffered response path: decode, evaluate,
// backfill, then commit the verdict.
func (w *responseWriter) commitBuffered() {
	status, header, body, err := w.gate.responses.Handle(w.upstreamResponse())
	if err != nil {
		w.refuseLocal(http.StatusBadGateway)
		return
	}
	w.commit(status, header, body)
}

// commitSSE runs the whole-response event-stream path: decode, evaluate,
// restore, then commit the verdict (B-FD2).
func (w *responseWriter) commitSSE() {
	status, header, body, err := w.gate.responses.HandleBufferedSSE(w.upstreamResponse())
	if err != nil {
		w.refuseLocal(http.StatusBadGateway)
		return
	}
	w.commit(status, header, body)
}

// refuseLocal replaces the client response with a locally generated refusal.
// It clears every header the forwarder copied from the upstream first: the
// stdlib http.Error deliberately keeps Content-Encoding, so a refusal after a
// Content-Encoding: gzip upstream would otherwise advertise its plain-text body
// as gzip and the client would mis-decode it.
func (w *responseWriter) refuseLocal(status int) {
	clear(w.dst.Header())
	http.Error(w.dst, http.StatusText(status), status)
}

// upstreamResponse adapts the recorded status, headers and buffer into the
// http.Response the response handlers consume.
func (w *responseWriter) upstreamResponse() *http.Response {
	return &http.Response{
		StatusCode: w.status, Header: w.Header().Clone(), Body: io.NopCloser(&w.buf), Request: w.req,
	}
}

// commit replaces the client headers with the processed set and writes the
// status and body once.
func (w *responseWriter) commit(status int, header http.Header, body []byte) {
	dst := w.dst.Header()
	clear(dst)
	for key, values := range header {
		dst[key] = values
	}
	w.dst.WriteHeader(status)
	_, _ = w.dst.Write(body)
}

// streamingSSE reports whether a response is a text/event-stream, classified by
// Content-Type alone. Tying the decision to a declared Content-Encoding would
// route an encoded event stream to the ordinary buffered path, where the whole
// stream is evaluated as one JSON document and placeholders are not
// reassembled across events; pkg/proxy's HandleBufferedSSE decodes every
// declared coding itself. It is classification only: it decides which buffered
// response path finish() runs, and commits nothing.
func streamingSSE(header http.Header) bool {
	media := strings.TrimSpace(strings.SplitN(header.Get("Content-Type"), ";", 2)[0])
	return strings.EqualFold(media, "text/event-stream")
}
