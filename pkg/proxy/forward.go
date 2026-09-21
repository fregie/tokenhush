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

	"github.com/fregie/tokenhush/pkg/config"
)

// ErrInvalidUpstream means a configured upstream base URL is unusable: it must
// be an absolute http(s) URL with a host and without userinfo, query or
// fragment. It is a construction-time error, so a malformed target can never
// become a live route.
var ErrInvalidUpstream = errors.New("proxy: invalid upstream base URL")

// dialFunc establishes one upstream connection. It is the forwarder's only
// network entry point, so a test can record every dial -- and prove that a
// refused request dialled none.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// BodyTransform rewrites the fully-read outbound request body before it is
// dispatched. It is the redaction seam: the forwarder reads the entire body,
// calls the transform exactly once, and only then opens an upstream
// connection, so a transform can never miss a tail fragment. A nil
// BodyTransform is the identity transform; an error aborts the request locally
// (fail closed) and the untransformed bytes are never forwarded.
type BodyTransform func([]byte) ([]byte, error)

// ResponseRecorder is the optional seam a client-bound http.ResponseWriter may
// implement so the forwarder can tell it when it is about to write a locally
// generated error and how the upstream body copy ended. The gateway's buffered
// responseWriter implements it; a plain http.ResponseWriter does not, and every
// call site type-asserts and tolerates a nil implementation.
type ResponseRecorder interface {
	MarkLocal()
	RecordCopyError(error)
}

// forwardOption configures a Forwarder at construction.
type forwardOption func(*forwardConfig)

// forwardConfig collects the optional construction settings.
type forwardConfig struct {
	dial         dialFunc
	maxBodyBytes int64
}

// WithDialFunc injects the dial function. A nil dial is ignored so the default
// is never accidentally removed. The egress guard test
// (internal/guards/egress_guard_test.go) is the production consumer that pins
// this seam: it records every dial and proves a refused request dialled none.
func WithDialFunc(dial dialFunc) forwardOption {
	return func(cfg *forwardConfig) {
		if dial != nil {
			cfg.dial = dial
		}
	}
}

// WithMaxBodyBytes overrides the memory cap on the total request body. A
// non-positive value is ignored, so the pkg/config default can never be
// accidentally removed. The cap itself is enforced in forward_body.go.
func WithMaxBodyBytes(n int64) forwardOption {
	return func(cfg *forwardConfig) {
		if n > 0 {
			cfg.maxBodyBytes = n
		}
	}
}

// Forwarder forwards requests to one fixed upstream base URL and relays the
// response. It implements http.Handler and is safe for concurrent use.
type Forwarder struct {
	base         *url.URL
	client       *http.Client
	transform    BodyTransform
	maxBodyBytes int64
}

// Forwarder serves HTTP.
var _ http.Handler = (*Forwarder)(nil)

// NewForwarder returns a Forwarder for the configured upstream base URL. The
// base may carry a path prefix, which is joined with the request path; it must
// be absolute http(s), have a host, and carry no userinfo, query or fragment.
// A nil transform is the identity transform. Without opts the forwarder dials
// through the bounded default dialer.
func NewForwarder(baseURL string, transform BodyTransform, opts ...forwardOption) (*Forwarder, error) {
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
	if cfg.maxBodyBytes <= 0 {
		cfg.maxBodyBytes = config.MaxBodyBytes
	}
	return &Forwarder{base: base, client: newForwardClient(cfg.dial), transform: transform, maxBodyBytes: cfg.maxBodyBytes}, nil
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
// content. The body is then read in full under the memory cap, transformed
// exactly once and dispatched; a body over the cap is refused with the shared
// 403 body_too_large and never dispatched. Accept-Encoding is stripped so the
// upstream answers with bytes the response path can classify.
func (f *Forwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	recorder, _ := w.(ResponseRecorder)
	if !identityOnlyEncoding(r.Header) {
		refuseLocal(w, recorder, http.StatusUnsupportedMediaType, refusalUnsupportedMediaType)
		return
	}
	body, err := readRequestBody(w, r, f.maxBodyBytes)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			refuseBodyTooLarge(w, recorder)
			return
		}
		refuseLocal(w, recorder, http.StatusBadRequest, refusalUnreadableBody)
		return
	}
	if f.transform != nil {
		transformed, err := f.transform(body)
		if err != nil {
			refuseLocal(w, recorder, http.StatusInternalServerError, refusalTransformError)
			return
		}
		body = transformed
	}

	outbound, err := http.NewRequestWithContext(r.Context(), r.Method, f.target(r).String(), bytes.NewReader(body))
	if err != nil {
		refuseLocal(w, recorder, http.StatusInternalServerError, refusalRequestBuildError)
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
	if _, err := io.Copy(w, response.Body); err != nil && recorder != nil {
		recorder.RecordCopyError(err)
	}
}

// markLocal flags a locally generated response through the optional
// ResponseRecorder seam. A writer that does not implement it is unaffected.
func markLocal(recorder ResponseRecorder) {
	if recorder != nil {
		recorder.MarkLocal()
	}
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
// does not itself bound the response body; the whole-response read is bounded
// separately by the gateway's response_timeout deadline on the request context.
//
// This deliberately reverses the earlier decision to exclude the response body
// from any timeout: token-level streaming is removed and the gateway now
// buffers every response whole, so a wedged upstream body must not hold a
// client forever. An SSE stream that previously stayed open for minutes is now
// bounded by response_timeout too.
const defaultResponseHeaderTimeout = 5 * time.Minute

// newForwardClient returns the bounded outbound client. Automatic compression
// is disabled so the upstream's Content-Encoding reaches the response path
// untouched instead of being transparently decompressed by the transport;
// redirects are not followed, because a transparent proxy relays the
// upstream's 3xx and Location to the client.
func newForwardClient(dial dialFunc) *http.Client {
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
// a 2xx. The response is locally generated, so it goes through the shared
// local-refusal helper, which marks it through the optional ResponseRecorder
// seam and emits its one metadata-only log line before anything is written.
// The body is status text only because transport errors can embed the upstream
// URL.
func writeTransportError(w http.ResponseWriter, err error) {
	status, code := http.StatusBadGateway, refusalBadGateway
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		status, code = http.StatusGatewayTimeout, refusalGatewayTimeout
	}
	recorder, _ := w.(ResponseRecorder)
	refuseLocal(w, recorder, status, code)
}
