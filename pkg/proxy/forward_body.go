package proxy

import (
	"io"
	"net/http"
)

// readRequestBody consumes the whole client body. Reading is intentionally
// unbounded: multimodal LLM requests carry large base64 payloads and the
// listener is loopback-only behind the Host allowlist, so a cap here would
// break real traffic without changing the local threat model. A truncated or
// otherwise broken body is a 400.
func readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(r.Body)
}
