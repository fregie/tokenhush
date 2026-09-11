package cli

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// dataPlane is the client-facing handler for proxied traffic. It resolves the
// upstream per request (docs/13 §4.1), applies the content pipeline's outbound
// transform, and forwards through a cached W3.3 Forwarder. It is deliberately
// not wrapped in ControlAuth: the data plane must never require the control
// bearer token.
//
// The body is transformed here, before the forwarder, so the per-request audit
// metadata (redaction count, detector types) can be attributed to exactly one
// request instead of a shared forwarder-wide counter. The forwarder therefore
// carries a nil transform; applying the pipeline twice would redact twice.
//
// One Forwarder is cached per resolved base URL. Each carries the forwarder's
// default bounded HTTP client, and the cache is bounded by the number of
// distinct upstreams a config can express (the built-in provider table plus
// config overrides).
type dataPlane struct {
	resolver *proxy.Resolver
	pipeline *proxy.Pipeline

	requests   atomic.Uint64
	redactions atomic.Uint64

	mu         sync.Mutex
	forwarders map[string]*proxy.Forwarder
}

// newDataPlane builds the handler over the resolved router and pipeline.
func newDataPlane(resolver *proxy.Resolver, pipeline *proxy.Pipeline) *dataPlane {
	return &dataPlane{resolver: resolver, pipeline: pipeline, forwarders: map[string]*proxy.Forwarder{}}
}

// ServeHTTP resolves the request path to an upstream, transforms the outbound
// body, then forwards. An unresolvable path is the resolver's typed rejection
// and becomes a 502; the resolver records the metadata-only audit row. A
// request whose upstream base URL is malformed is also a 502 and never leaves
// the machine. A policy Block becomes 403 without dialing upstream.
func (d *dataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.requests.Add(1)
	stats := requestStatsFrom(r.Context())

	upstream, err := d.resolver.Resolve(&extension.Request{
		Method: r.Method,
		Host:   r.Host,
		Path:   r.URL.Path,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	if stats != nil {
		stats.provider = upstream.Name
		stats.proxied = true
	}

	forwarder, err := d.forwarder(upstream.BaseURL)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	body, err := readClientBody(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if stats != nil {
		stats.reqBytes = len(body)
	}

	transformed, err := d.pipeline.RequestTransform()(body)
	if err != nil {
		if !d.pipeline.TransformErrorHandler()(w, err) {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}
	if stats != nil {
		count, detectors := newPlaceholderStats(body, transformed)
		stats.redactions = count
		stats.detectors = detectors
		if count > 0 {
			d.redactions.Add(uint64(count))
		}
	}

	r.Body = io.NopCloser(bytes.NewReader(transformed))
	forwarder.ServeHTTP(w, r)
}

// forwarder returns the cached forwarder for base, building it on first use.
// The transform is nil because ServeHTTP already ran the pipeline over the
// body; the forwarder only dispatches the already-redacted bytes.
func (d *dataPlane) forwarder(base string) (*proxy.Forwarder, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if forwarder, ok := d.forwarders[base]; ok {
		return forwarder, nil
	}
	forwarder, err := proxy.NewForwarder(base, nil)
	if err != nil {
		return nil, err
	}
	d.forwarders[base] = forwarder
	return forwarder, nil
}

// readClientBody consumes the whole client body, mirroring the forwarder's own
// unbounded read: multimodal LLM requests carry large base64 payloads and the
// listener is loopback-only behind the Host allowlist.
func readClientBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(r.Body)
}

// newPlaceholderStats reports how many placeholders the outbound transform
// introduced and the detector types they encode. Only the token grammar is
// read, never the matched bytes, so the result stays metadata-only.
func newPlaceholderStats(in, out []byte) (int, []string) {
	delta := bytes.Count(out, []byte(protocol.PlaceholderPrefix)) -
		bytes.Count(in, []byte(protocol.PlaceholderPrefix))
	if delta < 0 {
		delta = 0
	}
	before := placeholderTypes(in)
	beforeSet := make(map[string]struct{}, len(before))
	for _, t := range before {
		beforeSet[t] = struct{}{}
	}
	var added []string
	for _, t := range placeholderTypes(out) {
		if _, ok := beforeSet[t]; !ok {
			added = append(added, t)
		}
	}
	return delta, added
}

// placeholderTypes returns the distinct detector types encoded in the
// __PII_<type>_<digest>__ tokens of body, sorted for determinism.
func placeholderTypes(body []byte) []string {
	seen := map[string]struct{}{}
	for len(body) > 0 {
		i := bytes.Index(body, []byte(protocol.PlaceholderPrefix))
		if i < 0 {
			break
		}
		rest := body[i+len(protocol.PlaceholderPrefix):]
		j := bytes.Index(rest, []byte("__"))
		if j < 0 {
			break
		}
		token := rest[:j]
		body = rest[j+2:]
		if t, ok := placeholderType(token); ok {
			seen[t] = struct{}{}
		}
	}
	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// placeholderType splits a placeholder body (<type>_<digest>) into its type,
// rejecting anything that does not match the redaction layer's grammar.
func placeholderType(token []byte) (string, bool) {
	i := bytes.LastIndexByte(token, '_')
	if i <= 0 || i == len(token)-1 {
		return "", false
	}
	typ, digest := token[:i], token[i+1:]
	if len(digest) < 8 || !isLowerHex(digest) {
		return "", false
	}
	if typ[0] < 'a' || typ[0] > 'z' {
		return "", false
	}
	for _, c := range typ {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return "", false
		}
	}
	return string(typ), true
}

// isLowerHex reports whether every byte is a lowercase hexadecimal digit.
func isLowerHex(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
