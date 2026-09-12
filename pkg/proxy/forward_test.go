package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// forwardTestAuth is an obviously fake credential used to prove auth headers
// cross the forwarder byte-for-byte and opaque. It is never a real key.
const forwardTestAuth = "Bearer sk-ant-fake-w33-not-a-secret"

// startForwardServer builds a Forwarder for upstream and serves it on an
// ephemeral httptest server, so tests exercise the real HTTP wiring. The
// Forwarder is returned too, for tests that invoke ServeHTTP directly with
// request shapes an http.Client refuses to generate.
func startForwardServer(t *testing.T, upstream string, transform BodyTransform, opts ...ForwardOption) (*httptest.Server, *Forwarder) {
	t.Helper()
	fwd, err := NewForwarder(upstream, transform, opts...)
	if err != nil {
		t.Fatalf("NewForwarder(%q): %v", upstream, err)
	}
	srv := httptest.NewServer(fwd)
	t.Cleanup(srv.Close)
	return srv, fwd
}

// hangingUpstream returns an upstream whose handler never writes a response
// until the forwarding client disconnects (or a 10s safety valve fires), plus
// a channel closed when the handler returns. The handler drains the request
// body first: net/http only starts its client-disconnect background read once
// the body is consumed, and the leak receipt depends on that detection.
func hangingUpstream(t *testing.T) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		defer close(done)
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	return srv, done
}

// TestForwardRoundTrip is the W3.3 acceptance test: method, path, query,
// headers and body reach the upstream, and the upstream's status, selected
// headers and body reach the client unchanged.
func TestForwardRoundTrip(t *testing.T) {
	type observed struct {
		method, path, query string
		header              http.Header
		body                []byte
	}
	var mu sync.Mutex
	var got observed
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "upstream read body", http.StatusInternalServerError)
			return
		}
		mu.Lock()
		got = observed{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, header: r.Header.Clone(), body: body}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Marker", "w3.3-marker")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, `{"echo":"ok"}`)
	}))
	t.Cleanup(upstream.Close)

	srv, _ := startForwardServer(t, upstream.URL, nil)
	reqBody := []byte(`{"model":"claude-sonnet-4-5","input":"hello"}`)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages?beta=true", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", forwardTestAuth)
	req.Header.Set("x-api-key", "sk-ant-fake-api-key")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxied response: %v", err)
	}

	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want %d (upstream status must be preserved)", resp.StatusCode, http.StatusTeapot)
	}
	if mark := resp.Header.Get("X-Upstream-Marker"); mark != "w3.3-marker" {
		t.Errorf("X-Upstream-Marker = %q, want w3.3-marker", mark)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if string(respBody) != `{"echo":"ok"}` {
		t.Errorf("response body = %q, want %q", respBody, `{"echo":"ok"}`)
	}

	mu.Lock()
	seen := got
	mu.Unlock()
	if seen.method != http.MethodPost {
		t.Errorf("upstream method = %q, want POST", seen.method)
	}
	if seen.path != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", seen.path)
	}
	if seen.query != "beta=true" {
		t.Errorf("upstream query = %q, want beta=true", seen.query)
	}
	if !bytes.Equal(seen.body, reqBody) {
		t.Errorf("upstream body = %q, want %q", seen.body, reqBody)
	}
	for name, want := range map[string]string{
		"Authorization":  forwardTestAuth,
		"x-api-key":      "sk-ant-fake-api-key",
		"anthropic-beta": "oauth-2025-04-20",
		"Content-Type":   "application/json",
	} {
		if have := seen.header.Get(name); have != want {
			t.Errorf("upstream %s = %q, want opaque %q", name, have, want)
		}
	}
}

// TestForwardTransformReadsFullBodyBeforeDispatch locks the docs/architecture.md
// ordering invariant: the *entire* outbound body is read and transformed
// before any byte is dispatched upstream. The planted secret sits at the very
// end of a 1 MiB body, so a forward that starts streaming before the tail has
// been transformed would carry it upstream.
func TestForwardTransformReadsFullBodyBeforeDispatch(t *testing.T) {
	const tail = "SECRET_AT_THE_VERY_END"
	body := append(bytes.Repeat([]byte("a"), 1<<20), tail...)

	var mu sync.Mutex
	var order []string
	var transformCalls int
	var transformSaw []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		order = append(order, "upstream")
		mu.Unlock()
		upstreamBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		if bytes.Contains(upstreamBody, []byte(tail)) {
			http.Error(w, "raw secret reached upstream", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	transform := func(in []byte) ([]byte, error) {
		mu.Lock()
		order = append(order, "transform")
		transformCalls++
		transformSaw = append([]byte(nil), in...)
		mu.Unlock()
		return bytes.ReplaceAll(in, []byte(tail), []byte("__REDACTED__")), nil
	}

	srv, _ := startForwardServer(t, upstream.URL, transform)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %q; upstream rejected the forwarded body", resp.StatusCode, respBody)
	}

	mu.Lock()
	defer mu.Unlock()
	if transformCalls != 1 {
		t.Errorf("transform calls = %d, want exactly 1", transformCalls)
	}
	if len(transformSaw) != len(body) || !bytes.Equal(transformSaw, body) {
		t.Errorf("transform saw %d bytes, want the complete %d-byte body", len(transformSaw), len(body))
	}
	if len(order) != 2 || order[0] != "transform" || order[1] != "upstream" {
		t.Errorf("call order = %v, want [transform upstream]", order)
	}
}

// TestForwardTransformErrorFailsClosed proves a redaction failure never
// silently forwards the un-transformed body: the request is answered locally
// and the upstream is never dialed.
func TestForwardTransformErrorFailsClosed(t *testing.T) {
	var hits atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	wantErr := errors.New("redactor unavailable")
	srv, _ := startForwardServer(t, upstream.URL, func([]byte) ([]byte, error) { return nil, wantErr })
	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json", strings.NewReader(`{"input":"hi"}`))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (fail closed)", resp.StatusCode)
	}
	if hits.Load() {
		t.Error("un-transformed body reached the upstream after a transform error")
	}
}

// TestForwardUpstream500 pins the error-mapping rule that a non-2xx upstream
// response is passed through with its status and body intact.
func TestForwardUpstream500(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "upstream exploded")
	}))
	t.Cleanup(upstream.Close)

	srv, _ := startForwardServer(t, upstream.URL, nil)
	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	if string(body) != "upstream exploded" {
		t.Errorf("body = %q, want %q", body, "upstream exploded")
	}
}

// TestForwardUpstreamTimeout proves a stalled upstream is bounded by the
// client transport and surfaces as 504 instead of hanging, and that the
// timed-out upstream request is released (no leaked handler goroutine).
func TestForwardUpstreamTimeout(t *testing.T) {
	upstream, handlerDone := hangingUpstream(t)
	client := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 150 * time.Millisecond}}
	srv, _ := startForwardServer(t, upstream.URL, nil, WithHTTPClient(client))

	start := time.Now()
	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("proxy dropped the connection instead of answering: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", resp.StatusCode)
	}
	if elapsed > 3*time.Second {
		t.Errorf("forward took %v, want it bounded by the 150ms response-header timeout", elapsed)
	}
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Error("upstream handler still running: timed-out forward leaked the upstream goroutine")
	}
}

// TestForwardClientContextCancel proves cancelling the inbound request context
// aborts the in-flight upstream call and returns promptly with a non-200.
func TestForwardClientContextCancel(t *testing.T) {
	upstream, handlerDone := hangingUpstream(t)
	fwd, err := NewForwarder(upstream.URL, nil)
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/messages", strings.NewReader(`{"input":"hi"}`))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	returned := make(chan struct{})
	go func() {
		fwd.ServeHTTP(rec, req)
		close(returned)
	}()
	time.Sleep(100 * time.Millisecond) // let the upstream request get in flight
	cancel()

	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("ServeHTTP did not return after the client context was canceled")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Error("upstream handler still running: canceled forward leaked the upstream goroutine")
	}
}

// TestForwardDeadUpstream proves a refused upstream connection becomes an
// immediate 502, not a hang.
func TestForwardDeadUpstream(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}

	fwd, err := NewForwarder(fmt.Sprintf("http://127.0.0.1:%d", port), nil)
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	rec := httptest.NewRecorder()
	start := time.Now()
	fwd.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/v1/messages", nil))
	elapsed := time.Since(start)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if elapsed > 2*time.Second {
		t.Errorf("connection-refused forward took %v, want immediate", elapsed)
	}
}

// opaqueReader hides the concrete reader type from http.NewRequest so the
// client cannot precompute a Content-Length and must send the body chunked.
type opaqueReader struct{ r io.Reader }

func (o opaqueReader) Read(p []byte) (int, error) { return o.r.Read(p) }

// TestForwardUnknownLengthBody proves a chunked (unknown-length) inbound body
// is fully buffered and re-declared with a correct Content-Length upstream.
func TestForwardUnknownLengthBody(t *testing.T) {
	const payload = "chunked-body-with-no-content-length"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Upstream-Content-Length", strconv.FormatInt(r.ContentLength, 10))
		_, _ = w.Write(body)
	}))
	t.Cleanup(upstream.Close)

	srv, _ := startForwardServer(t, upstream.URL, nil)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages", opaqueReader{strings.NewReader(payload)})
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if req.ContentLength != 0 {
		t.Fatalf("test setup: client ContentLength = %d, want 0 (unknown/chunked)", req.ContentLength)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := resp.Header.Get("X-Upstream-Content-Length"); got != strconv.Itoa(len(payload)) {
		t.Errorf("upstream Content-Length = %q, want %d (proxy buffers then declares)", got, len(payload))
	}
	if string(body) != payload {
		t.Errorf("echoed body = %q, want %q", body, payload)
	}
}

// TestForwardLargeBody exercises the malformed_input/huge-body boundary: an
// 8 MiB body must round-trip bit-for-bit without truncation or timeout.
func TestForwardLargeBody(t *testing.T) {
	const size = 8 << 20
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("fill payload: %v", err)
	}
	want := sha256.Sum256(payload)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		got := sha256.Sum256(body)
		_, _ = fmt.Fprintf(w, "%x %d", got, len(body))
	}))
	t.Cleanup(upstream.Close)

	srv, _ := startForwardServer(t, upstream.URL, nil)
	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	wantText := fmt.Sprintf("%x %d", want, size)
	if string(body) != wantText {
		t.Errorf("upstream digest = %q, want %q", body, wantText)
	}
}

// TestNewForwarderRejectsInvalidUpstream verifies construction-time validation
// so a malformed base URL can never become a live route.
func TestNewForwarderRejectsInvalidUpstream(t *testing.T) {
	invalid := []string{
		"", "   ", "example.com/v1", "/v1/messages", "ftp://api.example.com",
		"http://", "https://", "http://user:pass@api.example.com",
		"http://api.example.com/v1?x=1", "http://api.example.com/v1#frag",
		"http://[::1", "://api.example.com",
	}
	for _, raw := range invalid {
		fwd, err := NewForwarder(raw, nil)
		if !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("NewForwarder(%q) error = %v, want ErrInvalidUpstream", raw, err)
		}
		if fwd != nil {
			t.Errorf("NewForwarder(%q) returned a non-nil Forwarder", raw)
		}
	}
	valid := []string{"http://127.0.0.1:8080", "https://api.anthropic.com", "http://127.0.0.1:8080/gateway/"}
	for _, raw := range valid {
		if _, err := NewForwarder(raw, nil); err != nil {
			t.Errorf("NewForwarder(%q) = %v, want nil", raw, err)
		}
	}
}

// TestForwardJoinsBasePathAndPreservesEscape proves a base path prefix is
// prepended (single-slash rule) and an escaped request path keeps its %2F
// distinct from a real slash all the way upstream.
func TestForwardJoinsBasePathAndPreservesEscape(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotRawPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath, gotRawPath = r.URL.Path, r.URL.EscapedPath()
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	srv, _ := startForwardServer(t, upstream.URL+"/gateway/", nil)
	resp, err := srv.Client().Get(srv.URL + "/v1/messages%2Fbeta?beta=true")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}

	mu.Lock()
	path, rawPath := gotPath, gotRawPath
	mu.Unlock()
	if path != "/gateway/v1/messages/beta" {
		t.Errorf("upstream path = %q, want /gateway/v1/messages/beta", path)
	}
	if rawPath != "/gateway/v1/messages%2Fbeta" {
		t.Errorf("upstream escaped path = %q, want /gateway/v1/messages%%2Fbeta", rawPath)
	}
}

// TestForwardStripsConnectionScopedHeaders proves hop-by-hop headers and any
// header named by Connection never cross the proxy, while Authorization does.
func TestForwardStripsConnectionScopedHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	_, fwd := startForwardServer(t, upstream.URL, nil)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Connection", "x-drop-me")
	req.Header.Set("X-Drop-Me", "must-not-cross")
	req.Header.Set("Authorization", forwardTestAuth)
	rec := httptest.NewRecorder()
	fwd.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	mu.Lock()
	headers := got
	mu.Unlock()
	if have := headers.Get("Authorization"); have != forwardTestAuth {
		t.Errorf("upstream Authorization = %q, want opaque %q", have, forwardTestAuth)
	}
	if have := headers.Get("X-Drop-Me"); have != "" {
		t.Errorf("upstream saw Connection-named header X-Drop-Me = %q, want it stripped", have)
	}
	if have := headers.Get("Connection"); have != "" {
		t.Errorf("upstream saw Connection header = %q, want it stripped", have)
	}
}

// TestForwardStreamsResponse proves the response is streamed frame by frame:
// the client receives the first SSE event while the upstream is still holding
// the second one back, which a buffer-until-EOF implementation cannot do.
func TestForwardStreamsResponse(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseUpstream()

	var timedOut atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: one\n\n")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			timedOut.Store(true)
		}
		_, _ = io.WriteString(w, "data: two\n\n")
		_ = http.NewResponseController(w).Flush()
	}))
	t.Cleanup(upstream.Close)

	srv, _ := startForwardServer(t, upstream.URL, nil)
	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read first SSE frame: %v", err)
	}
	if first != "data: one\n" {
		t.Fatalf("first SSE frame = %q, want %q", first, "data: one\n")
	}
	// The first frame crossed the proxy before the upstream was allowed to
	// emit the second: the forwarder streams instead of buffering to EOF.
	releaseUpstream()
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read rest of stream: %v", err)
	}
	if !strings.Contains(string(rest), "data: two") {
		t.Errorf("stream tail = %q, want it to contain data: two", rest)
	}
	if timedOut.Load() {
		t.Error("first frame never reached the client before the upstream timeout: response was buffered")
	}
}

// TestForwardMaxHeaderBytes proves the exported MaxHeaderBytes cap is the one
// an http.Server must apply: headers beyond it are rejected before the handler
// (and therefore before any upstream dial).
func TestForwardMaxHeaderBytes(t *testing.T) {
	var hits atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	fwd, err := NewForwarder(upstream.URL, nil)
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	srv := httptest.NewUnstartedServer(fwd)
	srv.Config.MaxHeaderBytes = MaxHeaderBytes
	srv.Start()
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// net/http allows 4096 bytes of slack above MaxHeaderBytes; overshoot it.
	req.Header.Set("X-Huge", strings.Repeat("a", MaxHeaderBytes+8192))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("server should answer 431, got transport error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("status = %d, want 431 when headers exceed MaxHeaderBytes", resp.StatusCode)
	}
	if hits.Load() {
		t.Error("oversized-header request reached the forward handler")
	}
}
