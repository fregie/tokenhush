package proxy

import (
	"errors"
	"io"
	"net/http"
)

// errBodyTooLarge is the shared read seam's overflow sentinel: the request body
// exceeded the configured cap, so nothing was read in full and nothing may be
// forwarded. It is kept distinct from an ordinary read error, because overflow
// is an explicit refusal while any other failure stays the 400 unreadable-body
// path.
var errBodyTooLarge = errors.New("proxy: request body exceeds max_body_bytes")

// readRequestBody consumes the whole client body under the cap. The cap is a
// memory guard, not a walk budget: multimodal LLM requests carry large base64
// payloads, so the default cap sits well above the per-leaf scan budget and a
// body exactly at the cap is read whole. A declared Content-Length over the cap
// is refused without reading a single byte; otherwise the body is read through
// http.MaxBytesReader, which reports a typed *http.MaxBytesError on overflow
// and asks the server to close the connection. Overflow is always an explicit
// refusal -- never a silent truncation, so a body whose first cap bytes form a
// complete document is refused rather than forwarded in part. Any other read
// error is returned unchanged.
func readRequestBody(w http.ResponseWriter, r *http.Request, cap int64) ([]byte, error) {
	if r.ContentLength > cap {
		return nil, errBodyTooLarge
	}
	if r.Body == nil {
		return []byte{}, nil
	}
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cap))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	return body, nil
}

// refuseBodyTooLarge writes the one structured 403 refusal both read paths
// share, so an over-cap body gets the identical shape whether it declares JSON
// or not. HTTP 413 was considered and rejected: every other gateway refusal is
// a 403 carrying the dataPlaneRefusal document, and a second status would make
// this the only refusal a client could not classify by shape. The response is
// locally generated, so it is marked through the optional ResponseRecorder seam
// before anything is written.
func refuseBodyTooLarge(w http.ResponseWriter, recorder ResponseRecorder) {
	markLocal(recorder)
	writeDataPlaneRefusal(w, http.StatusForbidden, dataPlaneRefusal{Error: refusalBodyTooLarge})
}
