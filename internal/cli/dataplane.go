package cli

import (
	"bytes"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// dataPlane is the client-facing handler for proxied traffic. It resolves the
// upstream per request (docs/13 §4.1) and forwards through a cached W3.3
// Forwarder wired to the W4.5 pipeline's request transform and block responder.
// It is deliberately not wrapped in ControlAuth: the data plane must never
// require the control bearer token.
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

// ServeHTTP resolves the request path to an upstream, then forwards. An
// unresolvable path is the resolver's typed rejection and becomes a 502; the
// resolver records the metadata-only audit row. A request whose upstream base
// URL is malformed is also a 502 and never leaves the machine.
func (d *dataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.requests.Add(1)
	upstream, err := d.resolver.Resolve(&extension.Request{
		Method: r.Method,
		Host:   r.Host,
		Path:   r.URL.Path,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	forwarder, err := d.forwarder(upstream.BaseURL)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	forwarder.ServeHTTP(w, r)
}

// forwarder returns the cached forwarder for base, building it on first use
// with the pipeline's request transform and 403 block responder.
func (d *dataPlane) forwarder(base string) (*proxy.Forwarder, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if forwarder, ok := d.forwarders[base]; ok {
		return forwarder, nil
	}
	forwarder, err := proxy.NewForwarder(base, d.transform(),
		proxy.WithTransformErrorHandler(d.pipeline.TransformErrorHandler()))
	if err != nil {
		return nil, err
	}
	d.forwarders[base] = forwarder
	return forwarder, nil
}

// transform returns the outbound BodyTransform: the pipeline's redaction step
// plus a best-effort session counter of placeholders introduced on the wire.
// The count is metadata only; it never inspects or stores the secret itself.
func (d *dataPlane) transform() proxy.BodyTransform {
	inner := d.pipeline.RequestTransform()
	prefix := []byte(protocol.PlaceholderPrefix)
	return func(body []byte) ([]byte, error) {
		out, err := inner(body)
		if err != nil {
			return nil, err
		}
		if delta := bytes.Count(out, prefix) - bytes.Count(body, prefix); delta > 0 {
			d.redactions.Add(uint64(delta))
		}
		return out, nil
	}
}
