package gateway

import (
	"bytes"
	"io"
	"net/http"
	"sync"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// dataPlane is the client-facing handler for proxied traffic. It resolves the
// upstream per request, applies the content pipeline's outbound transform, and
// forwards through a cached Forwarder. It is deliberately never wrapped in
// ControlAuth: the data plane must never require the control bearer token.
//
// The body is transformed here, before the forwarder, so the per-request
// metadata (redaction count, detector types) can be attributed to exactly one
// request instead of a shared forwarder-wide counter. The forwarder therefore
// carries a nil transform; applying the pipeline twice would redact twice.
//
// One Forwarder is cached per resolved base URL. Each carries the forwarder's
// default bounded HTTP client, and the cache is bounded by the number of
// distinct upstreams a config can express (the built-in provider table plus
// config overrides).
type dataPlane struct {
	router   extension.Router
	pipeline *proxy.Pipeline
	costSink extension.CostSink
	deps     *Deps

	mu         sync.Mutex
	forwarders map[string]*proxy.Forwarder
}

// newDataPlane builds the handler over the injected router and pipeline. A nil
// Router falls back to the default path resolver built from Core.Upstreams and
// the caller's Sink, preserving the "unknown path is a typed rejection" rule.
func newDataPlane(opts Options, deps *Deps) *dataPlane {
	router := opts.Router
	if router == nil {
		router = proxy.NewResolver(opts.Core.Upstreams, opts.Sink)
	}
	return &dataPlane{
		router:     router,
		pipeline:   opts.Pipeline,
		costSink:   opts.CostSink,
		deps:       deps,
		forwarders: map[string]*proxy.Forwarder{},
	}
}

// ServeHTTP resolves the request path to an upstream, transforms the outbound
// body, then forwards. An unresolvable path is the resolver's typed rejection
// and becomes a 502; the resolver records the metadata-only audit row. A
// request whose upstream base URL is malformed is also a 502 and never leaves
// the machine. A policy Block becomes 403 without dialing upstream.
func (d *dataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.deps.Requests.Add(1)
	stats := StatsFrom(r.Context())

	upstream, err := d.router.Pick(&extension.Request{
		Method: r.Method,
		Host:   r.Host,
		Path:   r.URL.Path,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	if stats != nil {
		stats.Provider = upstream.Name
		stats.Proxied = true
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
		stats.ReqBytes = len(body)
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
		stats.Redactions = count
		stats.Detectors = detectors
		if count > 0 {
			d.deps.Redactions.Add(uint64(count))
		}
	}

	r.Body = io.NopCloser(bytes.NewReader(transformed))

	// 只有配置了真实 CostSink 时才 tee 响应；nil 即默认 no-op，此时不产生
	// 任何额外开销。转发发出的始终是上面脱敏后的 transformed，绝不回填。
	if d.costSink != nil {
		recorder := &costRecorder{dst: w}
		forwarder.ServeHTTP(recorder, r)
		d.recordCost(r, transformed, recorder)
		return
	}
	forwarder.ServeHTTP(w, r)
}

// recordCost 在上游响应结束（请求完成）时把请求/响应对交给注入的 CostSink。
// 响应副本捕获于 pipeline 入站回填之前，因此携带占位符而非被还原的 secret；
// 请求 JSON 同样来自已脱敏的 transformed。nil 接收器是默认 no-op。
func (d *dataPlane) recordCost(r *http.Request, transformed []byte, rec *costRecorder) {
	if d.costSink == nil {
		return
	}
	d.costSink.Record(
		&extension.Request{
			Method: r.Method,
			Host:   r.Host,
			Path:   r.URL.Path,
			JSON:   parseRequestJSON(transformed),
		},
		rec.response(),
	)
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
