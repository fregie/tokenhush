package gateway

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
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
	fallback extension.Router
	pipeline *proxy.Pipeline
	costSink extension.CostSink
	deps     *Deps

	mu         sync.Mutex
	forwarders map[string]*proxy.Forwarder
}

// newDataPlane builds the handler over the injected router and pipeline. A nil
// Router falls back to the default path resolver built from Core.Upstreams and
// the caller's Sink, preserving the "unknown path is a typed rejection" rule.
// The default resolver is also kept as the fallback for an injected Router that
// returns the zero Upstream with a nil error ("no opinion").
func newDataPlane(opts Options, deps *Deps) *dataPlane {
	defaults := proxy.NewResolver(opts.Core.Upstreams, opts.Sink)
	router := opts.Router
	if router == nil {
		router = defaults
	}
	return &dataPlane{
		router:     router,
		fallback:   defaults,
		pipeline:   opts.Pipeline,
		costSink:   opts.CostSink,
		deps:       deps,
		forwarders: map[string]*proxy.Forwarder{},
	}
}

// pickRequest 构造交给 Router 的协议无关请求视图；它只含 method/host/path，
// 绝不携带 header 或正文，避免凭据或内容经路由接缝外泄。
func pickRequest(r *http.Request) *extension.Request {
	return &extension.Request{Method: r.Method, Host: r.Host, Path: r.URL.Path}
}

// ServeHTTP resolves the request path to an upstream, transforms the outbound
// body, then forwards. An unresolvable path is the resolver's typed rejection
// and becomes a 502; the resolver records the metadata-only audit row. A
// request whose upstream base URL is malformed is also a 502 and never leaves
// the machine. A policy Block becomes 403 without dialing upstream.
//
// 请求体失败策略（W1.3）：pipeline 的 transform 对不可解析的 body 返回原
// body + proxy.ErrUnwalkableBody，不自行裁决。本层是唯一能读 Content-Type
// 的地方，因此在此判定：声明为 JSON（media type 恰为 application/json，或
// 缺失 Content-Type 但 body 有 JSON 征兆）→ 本地 400，上游零字节；显式非
// JSON（含 application/json-seq、application/json-patch+json 等结构化后缀
// 类型）→ 直通原 body（pipeline 文档化的行为）。400 而非 403：坏 JSON 是
// 客户端错误，不是策略裁决；500 会把客户端错误藏成服务端错误。
func (d *dataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.deps.Requests.Add(1)
	stats := StatsFrom(r.Context())

	upstream, err := d.router.Pick(pickRequest(r))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	// 注入的 Router 以“零值 Upstream + nil error”表示无意见：按扩展契约回退到
	// 默认路由。默认 resolver 对未知路径仍返回 typed error，绝不猜测。
	if upstream == (extension.Upstream{}) && d.fallback != nil {
		upstream, err = d.fallback.Pick(pickRequest(r))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
	}
	if upstream == (extension.Upstream{}) {
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
	switch {
	case err == nil:
	case errors.Is(err, proxy.ErrUnwalkableBody) && requestDeclaresJSON(r, body):
		http.Error(w, "request body is not valid JSON", http.StatusBadRequest)
		return
	case errors.Is(err, proxy.ErrUnwalkableBody):
		// 显式非 JSON：使用 pipeline 返回的原 body（逐字节不变）继续直通。
	default:
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

// requestDeclaresJSON 判定一个 transform 无法解析的请求体是否必须 fail-closed
// （W1.3，机制冻结）：Content-Type 的 media type 恰为 `application/json`（大小写
// 不敏感、允许 ;charset=... 参数）→ 是；Content-Type 缺失或为空值 → 由 body 的
// JSON 征兆决定；显式非 JSON（含 `application/json-seq` 等结构化后缀类型）→ 否
// （保持文档化的非 JSON 直通，不得被征兆覆盖）。
//
// 判定只能在这一层：BodyTransform 只拿得到 []byte（与 Forwarder.ServeHTTP 的
// Content-Encoding 415 守卫同一理由：只有 HTTP 层能读 header）。
func requestDeclaresJSON(r *http.Request, body []byte) bool {
	if contentType := r.Header.Get("Content-Type"); strings.TrimSpace(contentType) != "" {
		return isJSONContentType(contentType)
	}
	return jsonSymptoms(body)
}

// isJSONContentType reports whether a Content-Type value declares JSON: the
// media type (parameters such as ;charset=utf-8 stripped) is exactly
// `application/json`, case-insensitively. It is deliberately an equality test,
// not a prefix test: `application/json-seq` (RFC 7464 JSON text sequences) and
// `application/json-patch+json` are different media types whose bodies the
// leaf walker does not parse, and treating them as declared JSON answered a
// json-seq body with 400. They now take the existing non-JSON passthrough.
func isJSONContentType(contentType string) bool {
	mediaType := contentType
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/json")
}

// jsonSymptoms reports whether a body looks like JSON: the first byte that is
// not ASCII whitespace (space, tab, CR, LF) is `{`, `[` or `"`. An empty or
// all-whitespace body has no symptoms. Whether a symptomatic body must be
// parsed at all is not decided here; see requestDeclaresJSON.
func jsonSymptoms(body []byte) bool {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[', '"':
			return true
		default:
			return false
		}
	}
	return false
}
