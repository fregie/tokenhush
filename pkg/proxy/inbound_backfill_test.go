package proxy

// Failing-first regressions for three inbound gaps in the redaction pipeline:
//
//	R1 — a placeholder split across several SSE `data:` events never appears as
//	     a contiguous `__PII_` in the raw byte stream, so the streaming backfill
//	     cannot match it (TestPipelineSSEBackfillAcrossDeltas).
//	R2 — a response with a non-identity Content-Encoding is marked modeOpaque,
//	     skipping both backfill and (non-streaming) response inspection
//	     (TestPipelineGzipResponseBackfilled, TestPipelineGzipResponseInspected,
//	     TestPipelineUndecodableEncodingFailsClosed).
//	R3 — a request body carrying Content-Encoding fails open: the body is
//	     forwarded unchanged and redaction is bypassed
//	     (TestPipelineCompressedRequestBodyFailsClosed).
//
// Every placeholder is derived at runtime with engine.Placeholder(secret,
// "api_key") and then split by byte offset: the HMAC digest is per-session, so a
// hardcoded token could never be recognised by the backfill function.
//
// Each test is written to fail on the current code and turn green once the
// SSE-aware backfill, outbound Accept-Encoding strip, and non-identity
// fail-closed work lands (plan T2–T5). None may be skipped or weakened.

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// w45Gzip encodes plain as a genuine gzip stream and asserts the result carries
// the gzip magic bytes, so a mis-built fixture can never make a gzip assertion
// vacuous (the body truly is compressed).
func w45Gzip(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	out := buf.Bytes()
	if len(out) < 2 || out[0] != 0x1f || out[1] != 0x8b {
		t.Fatalf("gzip fixture is not gzip-framed (magic % x)", out)
	}
	return out
}

// w45Zlib encodes plain as a genuine zlib (RFC 1950) stream and asserts the
// result is zlib-framed (CMF=0x78 with a valid FCHECK), so a mis-built fixture
// can never make the decodable assertion vacuous. `deflate` is used instead of
// gzip because Go's transport never auto-decompresses deflate, so a deflate
// response reaches the pipeline still encoded and genuinely enters the
// decodable branch.
func w45Zlib(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	out := buf.Bytes()
	if len(out) < 2 || out[0] != 0x78 || (int(out[0])<<8|int(out[1]))%31 != 0 {
		t.Fatalf("zlib fixture is not zlib-framed (header % x)", out[:2])
	}
	return out
}

// w45DeltaChunk is the minimal delta.content frame shape a streaming chat model
// emits: {"delta":{"content":"..."}}.
type w45DeltaChunk struct {
	Delta struct {
		Content string `json:"content"`
	} `json:"delta"`
}

// w45DeltaEvent renders one framed SSE `data:` record whose payload is a
// delta.content-shaped JSON object, terminated by a blank line.
func w45DeltaEvent(t *testing.T, fragment string) string {
	t.Helper()
	var chunk w45DeltaChunk
	chunk.Delta.Content = fragment
	payload, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal delta chunk: %v", err)
	}
	return "data: " + string(payload) + "\n\n"
}

// w45ResponseBlocker is a ResponseContent Block inspector. It never reads
// content, so it only needs CanBlock, mirroring w45BlockInspector.
type w45ResponseBlocker struct{}

func (w45ResponseBlocker) ID() string { return "w45-response-blocker" }

func (w45ResponseBlocker) Capabilities() extension.Capabilities {
	return extension.Capabilities{Phases: []extension.Phase{extension.ResponseContent}, CanBlock: true}
}

func (w45ResponseBlocker) Inspect(*extension.Document) ([]extension.Finding, error) {
	return []extension.Finding{{
		LeafIndex: 0, Start: 0, End: 1, Type: "blocked",
		Confidence: 1, Action: extension.Block, PluginID: "w45-response-blocker",
	}}, nil
}

// TestPipelineSSEBackfillAcrossDeltas reproduces R1: the derived placeholder is
// spread across four `data:` events whose JSON is a delta.content object, so the
// raw stream never contains a contiguous `__PII_`. A raw-bytes backfill cannot
// match; an SSE-aware one must restore the secret, keep the event count, the
// `data: ` prefix, the `\n\n` terminator and the trailing `[DONE]`.
func TestPipelineSSEBackfillAcrossDeltas(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	placeholder := engine.Placeholder(secret, "api_key")
	if len(placeholder) < 16 {
		t.Fatalf("placeholder too short to split across events: %q", placeholder)
	}
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	// Split by byte offset. The first cut lands before the `__PII_` opening
	// completes, so even the raw bytes across event boundaries cannot match.
	fragments := []string{
		placeholder[:4],
		placeholder[4:12],
		placeholder[12:20],
		placeholder[20:],
	}
	events := make([]string, 0, len(fragments)+1)
	for _, frag := range fragments {
		events = append(events, w45DeltaEvent(t, frag))
	}
	events = append(events, "data: [DONE]\n\n")
	wantEvents := len(events)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		for _, event := range events {
			_, _ = io.WriteString(w, event)
			_ = rc.Flush()
		}
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}

	if !bytes.Contains(body, []byte(secret)) {
		t.Errorf("SSE backfill did not restore the secret across deltas: %q", body)
	}
	if bytes.Contains(body, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("SSE stream still contains a placeholder: %q", body)
	}
	if got := strings.Count(string(body), "\n\n"); got != wantEvents {
		t.Errorf("SSE event count = %d, want %d (framing changed): %q", got, wantEvents, body)
	}
	segments := strings.Split(strings.TrimSuffix(string(body), "\n\n"), "\n\n")
	for i, segment := range segments {
		if !strings.HasPrefix(segment, "data: ") {
			t.Errorf("SSE event %d lost its `data: ` prefix: %q", i, segment)
		}
	}
	if !bytes.HasSuffix(body, []byte("data: [DONE]\n\n")) {
		t.Errorf("SSE stream lost its [DONE] terminator: %q", body)
	}
}

// TestPipelineGzipResponseBackfilled reproduces R2 for backfill: an upstream
// gzip response (with the placeholder inside) must reach the client as the
// secret, never as a placeholder — the body is not opaque to backfill.
func TestPipelineGzipResponseBackfilled(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	placeholder := engine.Placeholder(secret, "api_key")
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	plain := fmt.Appendf(nil, `{"echo":%q,"nested":{"x":%q}}`, placeholder, placeholder)
	gz := w45Gzip(t, plain)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gz)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json", strings.NewReader(`{"input":"hi"}`))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %q", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(secret)) {
		t.Errorf("gzip response was not backfilled to the secret: %q", body)
	}
	if bytes.Contains(body, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("gzip response still carries a placeholder: %q", body)
	}
}

// TestPipelineGzipResponseInspected reproduces R2 for inspection: a gzip
// response must still reach a ResponseContent Block inspector. Only that
// inspector is registered, and the expected outcome is 403 — proof the body was
// decoded, inspected and blocked rather than passed through opaquely.
func TestPipelineGzipResponseInspected(t *testing.T) {
	engine := w45Engine(t)
	placeholder := engine.Placeholder(w45Secret(), "api_key")
	reg := w45Registry(t, w45ResponseBlocker{})
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine})

	plain := fmt.Appendf(nil, `{"echo":%q}`, placeholder)
	gz := w45Gzip(t, plain)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gz)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json", strings.NewReader(`{"input":"hi"}`))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("gzip response was not inspected/blocked: status = %d, want 403; body %q", resp.StatusCode, body)
	}
}

// TestPipelineStripAcceptEncodingOutbound reproduces the outbound half of R2:
// the client's Accept-Encoding must not be forwarded verbatim, or the upstream
// may compress the response past the pipeline. The upstream-received header must
// drop the client's `deflate` and `br`; `gzip` may remain because Go's transport
// injects it.
func TestPipelineStripAcceptEncodingOutbound(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	var mu sync.Mutex
	var seen string
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		seen = r.Header.Get("Accept-Encoding")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages", strings.NewReader(`{"input":"hi"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	// Vacuity guard: the assertions below are only meaningful if the upstream
	// was actually dialed. Without this, a forwarder that never dispatched the
	// request (recorded header empty) would satisfy "contains neither deflate
	// nor br" trivially.
	if hits.Load() < 1 {
		t.Fatalf("upstream never received the request; Accept-Encoding assertions would be vacuous")
	}

	mu.Lock()
	got := seen
	mu.Unlock()
	if strings.Contains(got, "deflate") {
		t.Errorf("outbound Accept-Encoding still advertises deflate: %q", got)
	}
	if strings.Contains(got, "br") {
		t.Errorf("outbound Accept-Encoding still advertises br: %q", got)
	}
}

// TestPipelineCompressedRequestBodyFailsClosed reproduces R3: a request body
// carrying Content-Encoding must fail closed (415) instead of being forwarded
// un-redacted. The upstream must never be dialed.
func TestPipelineCompressedRequestBodyFailsClosed(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	reg := w45Registry(t, redact.NewPrefixDetector())
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine})

	gz := w45Gzip(t, w45RequestBody(secret))

	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages", bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("compressed request body status = %d, want 415; body %q", resp.StatusCode, body)
	}
	if hits.Load() != 0 {
		t.Errorf("upstream was dialed %d time(s) for a compressed request body", hits.Load())
	}
}

// TestPipelineUndecodableEncodingFailsClosed reproduces the response half of R2
// for an encoding the core cannot decode: `br` must become a 502 with the
// Content-Encoding header removed and no upstream byte leaked through.
func TestPipelineUndecodableEncodingFailsClosed(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	upstreamBody := []byte("br-encoded-payload-that-must-not-reach-the-client")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("undecodable encoding status = %d, want 502; body %q", resp.StatusCode, body)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("fail-closed response kept Content-Encoding = %q, want it removed", enc)
	}
	if bytes.Contains(body, upstreamBody) {
		t.Errorf("fail-closed response leaked upstream bytes: %q", body)
	}
}

// TestPipelineDecodableResponseInspected is the failure-first coverage of T3's
// decodable response branch. The upstream answers Content-Encoding: deflate,
// which Go's transport never auto-decompresses (unlike gzip), so the response
// reaches the pipeline still encoded and must be decoded, inspected and
// blocked. Before T3 a non-identity body was passed through opaquely, so the
// ResponseContent Block inspector never ran and the client saw 200.
func TestPipelineDecodableResponseInspected(t *testing.T) {
	engine := w45Engine(t)
	placeholder := engine.Placeholder(w45Secret(), "api_key")
	reg := w45Registry(t, w45ResponseBlocker{})
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine})

	plain := fmt.Appendf(nil, `{"echo":%q}`, placeholder)
	zl := w45Zlib(t, plain)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "deflate")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zl)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json", strings.NewReader(`{"input":"hi"}`))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("deflate response was not inspected/blocked: status = %d, want 403; body %q", resp.StatusCode, body)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("inspected response kept Content-Encoding = %q, want it removed", enc)
	}
	if bytes.Contains(body, zl) {
		t.Errorf("response leaked the still-compressed upstream bytes: %q", body)
	}
}
