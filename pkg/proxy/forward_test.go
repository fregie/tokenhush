package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// upstreamRequest is what the fake upstream observed on the wire.
type upstreamRequest struct {
	method  string
	path    string
	query   string
	headers http.Header
	body    []byte
}

// fakeUpstream serves exactly one plain-HTTP request over loopback and records
// it, so a test can assert what the forwarder really put on the wire.
type fakeUpstream struct {
	listener net.Listener
	requests chan upstreamRequest
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	upstream := &fakeUpstream{listener: listener, requests: make(chan upstreamRequest, 1)}
	go upstream.serveOne()
	t.Cleanup(func() { _ = listener.Close() })
	return upstream
}

func (u *fakeUpstream) serveOne() {
	conn, err := u.listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	body, readErr := io.ReadAll(request.Body)
	if readErr != nil {
		return
	}
	u.requests <- upstreamRequest{
		method:  request.Method,
		path:    request.URL.Path,
		query:   request.URL.RawQuery,
		headers: request.Header.Clone(),
		body:    body,
	}
	payload := `{"ok":true}`
	response := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}, "X-Upstream": {"fake"}},
		Body:          io.NopCloser(strings.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}
	_ = response.Write(conn)
}

// dialRecorder wraps a dial function and records every address it was asked to
// dial, so a test can assert a refused request opened zero upstream dials.
type dialRecorder struct {
	mu    sync.Mutex
	addrs []string
	inner DialFunc
}

func (r *dialRecorder) dial() DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		r.mu.Lock()
		r.addrs = append(r.addrs, addr)
		r.mu.Unlock()
		if r.inner == nil {
			return nil, errors.New("test: no upstream should be dialled")
		}
		return r.inner(ctx, network, addr)
	}
}

func (r *dialRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.addrs)
}

// dialTo returns a DialFunc that ignores the requested address and dials addr.
func dialTo(addr string) DialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, addr)
	}
}

// recordedForwarder builds a forwarder whose base is http://upstream.test and
// whose dials are recorded; when upstream is non-nil every dial is redirected
// to it. A nil upstream makes any dial an error, so the recorder doubles as a
// "no dial may happen" tripwire.
func recordedForwarder(t *testing.T, upstream *fakeUpstream, transform BodyTransform) (*Forwarder, *dialRecorder) {
	t.Helper()
	recorder := &dialRecorder{}
	if upstream != nil {
		recorder.inner = dialTo(upstream.listener.Addr().String())
	}
	forwarder, err := NewForwarder("http://upstream.test", transform, WithDialFunc(recorder.dial()))
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	return forwarder, recorder
}

// countingBody counts the bytes read from it, so a test can prove a refused
// request body was never touched.
type countingBody struct {
	mu   sync.Mutex
	data []byte
	read int
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.read >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.read:])
	b.read += n
	return n, nil
}

func (b *countingBody) bytesRead() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.read
}

// TestForwarderForwardsTransformedBody is the happy path: the upstream sees the
// transformed bytes, the method, path and query, and every end-to-end header
// byte-for-byte, and the upstream response is relayed.
func TestForwarderForwardsTransformedBody(t *testing.T) {
	upstream := newFakeUpstream(t)
	transform := func(body []byte) ([]byte, error) {
		return bytes.ToUpper(body), nil
	}
	forwarder, recorder := recordedForwarder(t, upstream, transform)

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions?stream=true", strings.NewReader("hello secret"))
	request.Header.Set("Authorization", "Bearer sk-test")
	request.Header.Set("X-Api-Key", "key-123")
	request.Header.Set("Anthropic-Beta", "prompt-caching-2024-07-31")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Trace", "trace-1")

	response := httptest.NewRecorder()
	forwarder.ServeHTTP(response, request)

	if got := recorder.count(); got != 1 {
		t.Fatalf("dial count = %d, want exactly 1", got)
	}
	seen := <-upstream.requests
	if seen.method != http.MethodPost {
		t.Errorf("upstream method = %q, want POST", seen.method)
	}
	if seen.path != "/v1/chat/completions" {
		t.Errorf("upstream path = %q, want /v1/chat/completions", seen.path)
	}
	if seen.query != "stream=true" {
		t.Errorf("upstream query = %q, want stream=true", seen.query)
	}
	if got, want := string(seen.body), "HELLO SECRET"; got != want {
		t.Errorf("upstream body = %q, want the transformed %q", got, want)
	}
	for name, want := range map[string]string{
		"Authorization":  "Bearer sk-test",
		"X-Api-Key":      "key-123",
		"Anthropic-Beta": "prompt-caching-2024-07-31",
		"Content-Type":   "application/json",
		"X-Trace":        "trace-1",
	} {
		if got := seen.headers.Get(name); got != want {
			t.Errorf("upstream header %s = %q, want %q", name, got, want)
		}
	}
	if response.Code != http.StatusOK {
		t.Errorf("client status = %d, want 200", response.Code)
	}
	if got, want := response.Body.String(), `{"ok":true}`; got != want {
		t.Errorf("client body = %q, want %q", got, want)
	}
	if got := response.Header().Get("X-Upstream"); got != "fake" {
		t.Errorf("relayed header X-Upstream = %q, want fake", got)
	}
}

// TestForwarderStripsAcceptEncoding pins that the client's Accept-Encoding
// never reaches the upstream, so the upstream is asked for bytes the response
// path can classify.
func TestForwarderStripsAcceptEncoding(t *testing.T) {
	upstream := newFakeUpstream(t)
	forwarder, _ := recordedForwarder(t, upstream, nil)

	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	request.Header.Set("Accept-Encoding", "br, zstd")

	response := httptest.NewRecorder()
	forwarder.ServeHTTP(response, request)

	seen := <-upstream.requests
	if got := seen.headers.Get("Accept-Encoding"); got != "" {
		t.Errorf("upstream saw Accept-Encoding %q, want the header stripped", got)
	}
	if response.Code != http.StatusOK {
		t.Errorf("client status = %d, want 200", response.Code)
	}
}

// TestForwarderIdentityEncodingsForward pins the accepted side of invariant 7:
// an absent Content-Encoding and an explicit "identity" both forward normally.
func TestForwarderIdentityEncodingsForward(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
	}{
		{"absent", ""},
		{"identity", "identity"},
		{"Identity", "Identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newFakeUpstream(t)
			forwarder, recorder := recordedForwarder(t, upstream, nil)

			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
			if tc.encoding != "" {
				request.Header.Set("Content-Encoding", tc.encoding)
			}

			response := httptest.NewRecorder()
			forwarder.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.Code)
			}
			if recorder.count() != 1 {
				t.Fatalf("dial count = %d, want exactly 1", recorder.count())
			}
			seen := <-upstream.requests
			if got, want := string(seen.body), `{"model":"m"}`; got != want {
				t.Errorf("upstream body = %q, want %q", got, want)
			}
		})
	}
}

// TestForwarderContentEncodingFailClosed pins the refusal side: any
// non-identity Content-Encoding yields 415 with zero dials and an unread body.
func TestForwarderContentEncodingFailClosed(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
	}{
		{"gzip", "gzip"},
		{"deflate", "deflate"},
		{"br", "br"},
		{"zstd", "zstd"},
		{"list-with-identity", "gzip, identity"},
		{"upper-case-gzip", "GZIP"},
		{"empty-value", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forwarder, recorder := recordedForwarder(t, nil, nil)
			body := &countingBody{data: []byte(`{"api_key":"secret"}`)}
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
			request.Header["Content-Encoding"] = []string{tc.encoding}

			response := httptest.NewRecorder()
			forwarder.ServeHTTP(response, request)

			if response.Code != http.StatusUnsupportedMediaType {
				t.Errorf("status = %d, want 415", response.Code)
			}
			if got := recorder.count(); got != 0 {
				t.Errorf("refused request opened %d dials, want 0", got)
			}
			if got := body.bytesRead(); got != 0 {
				t.Errorf("refused request read %d body bytes, want 0", got)
			}
		})
	}
}

// TestForwarderTransformErrorFailsClosed pins the fail-closed transform seam:
// a transform error answers 500 locally and nothing is dialled, so
// untransformed bytes can never reach the upstream.
func TestForwarderTransformErrorFailsClosed(t *testing.T) {
	forwarder, recorder := recordedForwarder(t, nil, func([]byte) ([]byte, error) {
		return nil, errors.New("transform refused")
	})

	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader("payload"))
	response := httptest.NewRecorder()
	forwarder.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", response.Code)
	}
	if got := recorder.count(); got != 0 {
		t.Errorf("failed transform opened %d dials, want 0", got)
	}
}

// TestForwarderTransportFailureIsBadGateway pins that a refused connection is
// a 502, never a hang and never a 2xx.
func TestForwarderTransportFailureIsBadGateway(t *testing.T) {
	recorder := &dialRecorder{inner: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}
	forwarder, err := NewForwarder("http://upstream.test", nil, WithDialFunc(recorder.dial()))
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}

	response := httptest.NewRecorder()
	forwarder.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`)))

	if response.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", response.Code)
	}
}

// TestNewForwarderRejectsInvalidUpstream pins the construction-time validation
// of the configured base URL, so a malformed target can never become a route.
func TestNewForwarderRejectsInvalidUpstream(t *testing.T) {
	for _, base := range []string{
		"",
		"upstream.test",
		"ftp://upstream.test",
		"https://",
		"https://user:pass@upstream.test",
		"https://upstream.test?x=1",
		"https://upstream.test#frag",
	} {
		forwarder, err := NewForwarder(base, nil)
		if !errors.Is(err, ErrInvalidUpstream) {
			t.Errorf("NewForwarder(%q) error = %v, want ErrInvalidUpstream", base, err)
		}
		if forwarder != nil {
			t.Errorf("NewForwarder(%q) returned a forwarder for an invalid base", base)
		}
	}
}
