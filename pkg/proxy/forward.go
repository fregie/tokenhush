package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxHeaderBytes caps the request headers accepted by the proxy's HTTP
// servers. It is net/http's own default (1 MiB) made explicit so run can wire
// http.Server{MaxHeaderBytes: proxy.MaxHeaderBytes} on both loopback
// listeners and tests can pin the cap. net/http bounds header material in
// bytes, not by header or value count.
const MaxHeaderBytes = http.DefaultMaxHeaderBytes

// ErrInvalidUpstream means the configured upstream base URL is unusable: it
// must be an absolute http(s) URL with a host and without userinfo, query or
// fragment. It is a construction-time error, so a malformed base URL can never
// become a live route.
var ErrInvalidUpstream = errors.New("proxy: invalid upstream base URL")

// BodyTransform rewrites the fully-read outbound request body before it is
// forwarded. It is the redaction seam (docs/architecture.md): the handler reads the
// entire body, calls the transform exactly once, and only then dispatches
// upstream, so a transform can never miss a tail fragment. Returning an error
// aborts the request locally (fail closed); the un-transformed body is never
// forwarded. A nil BodyTransform is the identity transform.
type BodyTransform func([]byte) ([]byte, error)

// TransformErrorFunc lets a BodyTransform turn its own error into a
// client-visible response, for example a 403 when the W4.5 content policy
// blocks a request. It returns true once it has written a response; a false
// result (or a nil handler) keeps the forwarder's default fail-closed 500.
type TransformErrorFunc func(w http.ResponseWriter, err error) bool

// ForwardOption configures a Forwarder at construction.
type ForwardOption func(*forwardOptions)

// forwardOptions collects optional Forwarder settings; zero value = defaults.
type forwardOptions struct {
	client           *http.Client
	transformFailure TransformErrorFunc
}

// WithHTTPClient replaces the forwarder's default bounded HTTP client. It is
// intended for tests and future tuning; a nil client is ignored so the
// default is never accidentally removed. The client must be safe for
// concurrent use.
func WithHTTPClient(client *http.Client) ForwardOption {
	return func(o *forwardOptions) {
		if client != nil {
			o.client = client
		}
	}
}

// WithTransformErrorHandler installs a responder for a BodyTransform error. A
// nil handler is ignored, so the default fail-closed 500 is never accidentally
// removed. The W4.5 pipeline uses it to answer a policy Block with 403.
func WithTransformErrorHandler(h TransformErrorFunc) ForwardOption {
	return func(o *forwardOptions) {
		if h != nil {
			o.transformFailure = h
		}
	}
}

// Forwarder forwards requests to a fixed upstream base URL and streams the
// response back. It is an http.Handler and is safe for concurrent use.
//
// Auth headers (Authorization, x-api-key, anthropic-beta, cookies, ...) are
// ordinary end-to-end headers here: they are copied byte-for-byte and never
// parsed, stored or rewritten (docs/architecture.md).
type Forwarder struct {
	base             *url.URL
	client           *http.Client
	transform        BodyTransform
	transformFailure TransformErrorFunc
}

// Forwarder serves HTTP; the assertion keeps the handler contract explicit.
var _ http.Handler = (*Forwarder)(nil)

// NewForwarder returns a Forwarder for the configured upstream base URL. The
// base URL may carry a path prefix (joined with the request path); it must be
// absolute http(s), must have a host and must not carry userinfo, query or
// fragment. A nil transform is the identity transform. Without opts the
// forwarder uses a transport with bounded dial and response-header timeouts
// and does not follow upstream redirects.
func NewForwarder(baseURL string, transform BodyTransform, opts ...ForwardOption) (*Forwarder, error) {
	base, err := parseUpstream(baseURL)
	if err != nil {
		return nil, err
	}
	cfg := forwardOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.client == nil {
		cfg.client = defaultForwardClient()
	}
	return &Forwarder{base: base, client: cfg.client, transform: transform, transformFailure: cfg.transformFailure}, nil
}

// parseUpstream validates and canonicalises an upstream base URL.
func parseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidUpstream, raw, err)
	}
	switch {
	case !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https"):
		return nil, fmt.Errorf("%w: %q: scheme must be http or https", ErrInvalidUpstream, raw)
	case u.Host == "":
		return nil, fmt.Errorf("%w: %q: missing host", ErrInvalidUpstream, raw)
	case u.User != nil:
		return nil, fmt.Errorf("%w: %q: userinfo is not allowed", ErrInvalidUpstream, raw)
	case u.RawQuery != "" || u.ForceQuery:
		return nil, fmt.Errorf("%w: %q: query is not allowed", ErrInvalidUpstream, raw)
	case u.Fragment != "":
		return nil, fmt.Errorf("%w: %q: fragment is not allowed", ErrInvalidUpstream, raw)
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u, nil
}

// ServeHTTP reads the client request body in full, runs the BodyTransform over
// it, forwards method/path/query/headers to the upstream and streams the
// upstream response back. No body byte is dispatched upstream before the
// transform has seen all of it (docs/architecture.md); a transform error answers 500
// locally instead of forwarding un-transformed content. Hop-by-hop headers are
// stripped in both directions, upstream status and end-to-end headers are
// preserved, and transport failures map to 502/504 rather than hanging.
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Request-side fail-closed (decision D4, risk R3): a client that compresses
	// its request body (Content-Encoding: gzip/deflate/br/...) would otherwise
	// bypass redaction, because transformRequest leaf-walks plain JSON and
	// cannot decode a compressed body. The V1 forwarder does not decompress
	// untrusted request bodies, so it rejects them locally with 415 before any
	// body read, transform or upstream dial.
	//
	// This is the only layer that can read the header: BodyTransform takes only
	// []byte, so the check cannot live in transformRequest. A dedicated error
	// type routed through the transform-failure chain would force a body read
	// before the decision and tie a local guard to a mechanism meant for policy
	// errors; a direct http.Error keeps the 415 unconditional and independent of
	// whether a transform is installed.
	if classifyContentEncoding(r.Header) != encodingIdentity {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	body, err := readRequestBody(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if f.transform != nil {
		transformed, err := f.transform(body)
		if err != nil {
			if f.transformFailure != nil && f.transformFailure(w, err) {
				return
			}
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		body = transformed
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, f.target(r).String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	copyRequestHeaders(outReq.Header, r.Header)
	outReq.ContentLength = int64(len(body))

	resp, err := f.client.Do(outReq)
	if err != nil {
		writeTransportError(w, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	copyEndToEndHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	streamBody(w, resp.Body)
}

// readRequestBody consumes the whole client body. Reading is intentionally
// unbounded: multimodal LLM requests carry large base64 payloads, and the V1
// listener is loopback-only behind the Host allowlist, so a body cap would
// break real traffic without materially changing the local threat model. A
// truncated or otherwise broken body is a 400.
func readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(r.Body)
}

// target builds the upstream URL for r: the configured base (scheme, host and
// optional path prefix) plus the request path and query. Userinfo, query and
// fragment were rejected at construction, so the request is the only source of
// query string.
func (f *Forwarder) target(r *http.Request) *url.URL {
	u := *f.base
	u.Path, u.RawPath = joinURLPath(f.base, r.URL)
	u.RawQuery = r.URL.RawQuery
	u.ForceQuery = r.URL.ForceQuery
	return &u
}

// joinURLPath joins a base URL path with a request path the way
// net/http/httputil does: exactly one slash at the seam, and an escaped
// request path (RawPath) stays escaped so %2F is not silently turned into a
// real slash on the way upstream.
func joinURLPath(base, req *url.URL) (path, rawPath string) {
	if base.RawPath == "" && req.RawPath == "" {
		return singleJoiningSlash(base.Path, req.Path), ""
	}
	baseEscaped := base.EscapedPath()
	reqEscaped := req.EscapedPath()
	baseSlash := strings.HasSuffix(baseEscaped, "/")
	reqSlash := strings.HasPrefix(reqEscaped, "/")
	switch {
	case baseSlash && reqSlash:
		return base.Path + req.Path[1:], baseEscaped + reqEscaped[1:]
	case !baseSlash && !reqSlash:
		return base.Path + "/" + req.Path, baseEscaped + "/" + reqEscaped
	default:
		return base.Path + req.Path, baseEscaped + reqEscaped
	}
}

// singleJoiningSlash joins a and b with exactly one slash at the seam.
func singleJoiningSlash(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	default:
		return a + b
	}
}

// hopByHopHeaders are connection-scoped and must not be forwarded by a proxy
// (RFC 7230 §6.1), plus the widely deployed non-standard Proxy-Connection.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// copyEndToEndHeaders copies src into dst, dropping hop-by-hop headers and any
// header named by a Connection header. Auth headers are ordinary end-to-end
// headers: copied byte-for-byte, never parsed.
func copyEndToEndHeaders(dst, src http.Header) {
	skip := make(map[string]bool, len(hopByHopHeaders))
	for _, name := range hopByHopHeaders {
		skip[http.CanonicalHeaderKey(name)] = true
	}
	for _, connection := range src.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			if name = strings.TrimSpace(name); name != "" {
				skip[http.CanonicalHeaderKey(name)] = true
			}
		}
	}
	for name, values := range src {
		key := http.CanonicalHeaderKey(name)
		if skip[key] {
			continue
		}
		dst[key] = append([]string(nil), values...)
	}
}

// copyRequestHeaders copies the client's end-to-end request headers to the
// outbound request and then force-strips Accept-Encoding so the upstream is
// asked for identity.
//
// Why: forwarding the client's Accept-Encoding (for example "gzip, deflate,
// br") lets the upstream answer with Content-Encoding: gzip. The pipeline
// cannot inspect a compressed body, so it marks the response modeOpaque and
// silently skips backfill and non-streaming policy checks (defect R2).
// Removing the header leaves the outbound request without Accept-Encoding, so
// the default transport self-injects "gzip" and transparently decompresses the
// response, also dropping the response Content-Encoding and Content-Length
// before the pipeline ever sees it. The pipeline therefore always sees plain,
// inspectable bytes.
//
// This also explains T3's reachability: after this strip the transport has
// already decompressed gzip responses, so the core's own decodable branch
// stays reachable only for `deflate` or a custom WithHTTPClient that disables
// transparent decompression. DisableCompression is deliberately left unset so
// the default transport keeps that behaviour; hop-by-hop and Connection-listed
// headers are still filtered by copyEndToEndHeaders.
func copyRequestHeaders(dst, src http.Header) {
	copyEndToEndHeaders(dst, src)
	dst.Del("Accept-Encoding")
}

// streamBody copies the upstream body to the client, flushing after every
// chunk so SSE frames and long responses are delivered immediately instead of
// being buffered until EOF. A write error means the client went away and the
// copy stops.
func streamBody(w http.ResponseWriter, src io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return
			}
			// ErrNotSupported is returned by writers that cannot flush (for
			// example a plain io.Writer); it is not fatal.
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

// writeTransportError maps an upstream transport failure to a client-visible
// status: 504 when the failure was a timeout or deadline, 502 otherwise; never
// a hang and never a 2xx. The body is status text only because transport
// errors can embed the upstream URL.
func writeTransportError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		status = http.StatusGatewayTimeout
	}
	http.Error(w, http.StatusText(status), status)
}

// defaultResponseHeaderTimeout bounds time-to-first-byte from the upstream. It
// deliberately does not cover the response body: a long-lived SSE stream may
// stay open for minutes and must not be cut.
const defaultResponseHeaderTimeout = 5 * time.Minute

// defaultDialTimeout bounds establishing the upstream TCP connection.
const defaultDialTimeout = 10 * time.Second

// defaultForwardClient returns the forwarder's outbound HTTP client. The
// transport clones net/http's defaults (including the standard environment
// proxy) with bounded dial, TLS-handshake and response-header timeouts. There
// is deliberately no http.Client.Timeout, because that clock also covers the
// response body and would abort long-lived SSE streams. Redirects are not
// followed: a transparent proxy passes the upstream's 3xx and Location to the
// client. The client is safe for concurrent use.
func defaultForwardClient() *http.Client {
	tr := &http.Transport{}
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = base.Clone()
	}
	tr.DialContext = (&net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 10 * time.Second
	tr.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	tr.ExpectContinueTimeout = 1 * time.Second
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
