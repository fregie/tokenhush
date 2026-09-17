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

// ErrInvalidUpstream means a configured upstream base URL is unusable: it must
// be an absolute http(s) URL with a host and without userinfo, query or
// fragment. It is a construction-time error, so a malformed target can never
// become a live route.
var ErrInvalidUpstream = errors.New("proxy: invalid upstream base URL")

// DialFunc establishes one upstream connection. It is the forwarder's only
// network entry point, so a test can record every dial -- and prove that a
// refused request dialled none.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// BodyTransform rewrites the fully-read outbound request body before it is
// dispatched. It is the redaction seam: the forwarder reads the entire body,
// calls the transform exactly once, and only then opens an upstream
// connection, so a transform can never miss a tail fragment. A nil
// BodyTransform is the identity transform; an error aborts the request locally
// (fail closed) and the untransformed bytes are never forwarded.
type BodyTransform func([]byte) ([]byte, error)

// ForwardOption configures a Forwarder at construction.
type ForwardOption func(*forwardConfig)

// forwardConfig collects the optional construction settings.
type forwardConfig struct {
	dial DialFunc
}

// WithDialFunc injects the dial function. A nil dial is ignored so the default
// is never accidentally removed.
func WithDialFunc(dial DialFunc) ForwardOption {
	return func(cfg *forwardConfig) {
		if dial != nil {
			cfg.dial = dial
		}
	}
}

// Forwarder forwards requests to one fixed upstream base URL and relays the
// response. It implements http.Handler and is safe for concurrent use.
type Forwarder struct {
	base      *url.URL
	client    *http.Client
	transform BodyTransform
}

// Forwarder serves HTTP.
var _ http.Handler = (*Forwarder)(nil)

// NewForwarder returns a Forwarder for the configured upstream base URL. The
// base may carry a path prefix, which is joined with the request path; it must
// be absolute http(s), have a host, and carry no userinfo, query or fragment.
// A nil transform is the identity transform. Without opts the forwarder dials
// through the bounded default dialer.
func NewForwarder(baseURL string, transform BodyTransform, opts ...ForwardOption) (*Forwarder, error) {
	base, err := parseUpstream(baseURL)
	if err != nil {
		return nil, err
	}
	cfg := forwardConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.dial == nil {
		dialer := &net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}
		cfg.dial = dialer.DialContext
	}
	return &Forwarder{base: base, client: newForwardClient(cfg.dial), transform: transform}, nil
}

// parseUpstream validates and canonicalises an upstream base URL.
func parseUpstream(raw string) (*url.URL, error) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidUpstream, raw, err)
	}
	switch {
	case !strings.EqualFold(target.Scheme, "http") && !strings.EqualFold(target.Scheme, "https"):
		return nil, fmt.Errorf("%w: %q: scheme must be http or https", ErrInvalidUpstream, raw)
	case target.Host == "":
		return nil, fmt.Errorf("%w: %q: missing host", ErrInvalidUpstream, raw)
	case target.User != nil:
		return nil, fmt.Errorf("%w: %q: userinfo is not allowed", ErrInvalidUpstream, raw)
	case target.RawQuery != "" || target.ForceQuery:
		return nil, fmt.Errorf("%w: %q: query is not allowed", ErrInvalidUpstream, raw)
	case target.Fragment != "":
		return nil, fmt.Errorf("%w: %q: fragment is not allowed", ErrInvalidUpstream, raw)
	}
	target.Fragment = ""
	target.RawFragment = ""
	return target, nil
}

// ServeHTTP enforces invariant 7 in the request direction first: a request
// carrying a non-identity Content-Encoding is refused with 415 BEFORE its body
// is read and BEFORE any upstream connection is opened, because the pipeline
// inspects plain bytes and the gateway never decompresses untrusted request
// content. The body is then read in full, transformed exactly once and
// dispatched; Accept-Encoding is stripped so the upstream answers with bytes
// the response path can classify.
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !identityOnlyEncoding(r.Header) {
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
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		body = transformed
	}

	outbound, err := http.NewRequestWithContext(r.Context(), r.Method, f.target(r).String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	copyRequestHeaders(outbound.Header, r.Header)
	outbound.ContentLength = int64(len(body))

	response, err := f.client.Do(outbound)
	if err != nil {
		writeTransportError(w, err)
		return
	}
	defer func() { _ = response.Body.Close() }()

	copyEndToEndHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

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

// target joins the configured base (scheme, host and optional path prefix)
// with the request path and query. Userinfo, query and fragment were rejected
// at construction, so the request is the only source of query string.
func (f *Forwarder) target(r *http.Request) *url.URL {
	target := *f.base
	target.Path = joinPaths(f.base.Path, r.URL.Path)
	if escaped := joinPaths(f.base.EscapedPath(), r.URL.EscapedPath()); escaped != target.Path {
		target.RawPath = escaped
	} else {
		target.RawPath = ""
	}
	target.RawQuery = r.URL.RawQuery
	target.ForceQuery = r.URL.ForceQuery
	return &target
}

// joinPaths joins two URL path halves with exactly one slash at the seam.
func joinPaths(base, request string) string {
	switch {
	case base == "":
		return request
	case strings.HasSuffix(base, "/") && strings.HasPrefix(request, "/"):
		return base + request[1:]
	case !strings.HasSuffix(base, "/") && !strings.HasPrefix(request, "/"):
		return base + "/" + request
	default:
		return base + request
	}
}

// hopByHopHeaders are connection-scoped and must not be forwarded by a proxy
// (RFC 7230 6.1), plus the widely deployed non-standard Proxy-Connection.
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
// headers: copied byte-for-byte, never parsed or rewritten.
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

// copyRequestHeaders forwards every end-to-end header untouched and then
// strips Accept-Encoding, so the upstream is asked for identity bytes the
// response path can inspect. Compression is disabled on the transport too, so
// no Accept-Encoding is re-added on the wire.
func copyRequestHeaders(dst, src http.Header) {
	copyEndToEndHeaders(dst, src)
	dst.Del("Accept-Encoding")
}

// identityOnlyEncoding reports whether every Content-Encoding token is
// "identity" (case-insensitive). An absent header is identity; a present but
// blank value, a list carrying any other coding and an unknown token all fail
// closed.
func identityOnlyEncoding(header http.Header) bool {
	for _, value := range header.Values("Content-Encoding") {
		for _, token := range strings.Split(value, ",") {
			if !strings.EqualFold(strings.TrimSpace(token), "identity") {
				return false
			}
		}
	}
	return true
}

// defaultDialTimeout bounds establishing the upstream TCP connection.
const defaultDialTimeout = 10 * time.Second

// defaultResponseHeaderTimeout bounds time-to-first-byte from the upstream. It
// deliberately does not cover the response body: a long-lived SSE stream may
// stay open for minutes and must not be cut.
const defaultResponseHeaderTimeout = 5 * time.Minute

// newForwardClient returns the bounded outbound client. Automatic compression
// is disabled so the upstream's Content-Encoding reaches the response path
// untouched instead of being transparently decompressed by the transport;
// redirects are not followed, because a transparent proxy relays the
// upstream's 3xx and Location to the client.
func newForwardClient(dial DialFunc) *http.Client {
	transport := &http.Transport{}
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	}
	transport.DialContext = dial
	transport.DisableCompression = true
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	transport.ExpectContinueTimeout = time.Second
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// writeTransportError maps an upstream transport failure to a client-visible
// status: 504 for a timeout or deadline, 502 otherwise; never a hang and never
// a 2xx. The body is status text only because transport errors can embed the
// upstream URL.
func writeTransportError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		status = http.StatusGatewayTimeout
	}
	http.Error(w, http.StatusText(status), status)
}
