package cli

// response_writer_refusal_test.go is the F2-2 regression suite: when finish()
// replaces an upstream response with a locally generated refusal (an over-cap
// 502 or a timed-out 504) it must clear every header the forwarder copied
// first. The stdlib http.Error deliberately keeps Content-Encoding, so without
// the clear a gzip-advertised upstream response would be re-labelled as a gzip
// plain-text refusal the client mis-decodes.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// assertRefusalHeadersClean pins that a locally generated refusal carries no
// upstream end-to-end header: Content-Encoding above all, so the client never
// mis-decodes the plain-text body.
func assertRefusalHeadersClean(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want it cleared on the local refusal", got)
	}
	if got := rec.Header().Get("X-Upstream"); got != "" {
		t.Errorf("X-Upstream = %q, want every upstream header cleared on the refusal", got)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want the locally generated text/plain refusal", got)
	}
}

// TestResponseBufferCapRefusalClearsUpstreamHeaders pins F2-2 for the cap: an
// over-cap gzip-advertised upstream response is a 502 with no Content-Encoding.
func TestResponseBufferCapRefusalClearsUpstreamHeaders(t *testing.T) {
	srv := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Upstream", "leak")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), 4096))
	})
	cfg := redConfig(srv.URL)
	cfg.ResponseBufferBytes = 64
	gw := redGateway(t, cfg)

	rec := redRoute(t, gw, "/v1/chat/completions")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when the response exceeds response_buffer_bytes", rec.Code)
	}
	assertRefusalHeadersClean(t, rec)
}

// TestResponseBufferTimeoutRefusalClearsUpstreamHeaders pins F2-2 for the
// timeout: a stalled gzip-advertised upstream response is a 504 with no
// Content-Encoding.
func TestResponseBufferTimeoutRefusalClearsUpstreamHeaders(t *testing.T) {
	srv := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Upstream", "leak")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	})
	cfg := redConfig(srv.URL)
	cfg.ResponseTimeout = 100 * time.Millisecond
	gw := redGateway(t, cfg)

	rec := redRoute(t, gw, "/v1/chat/completions")
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504 when the response stalls past response_timeout", rec.Code)
	}
	assertRefusalHeadersClean(t, rec)
}
