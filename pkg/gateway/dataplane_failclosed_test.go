package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
)

// W1.3 的 HTTP 层判定测试：不可解析请求体是否 fail-closed，由 dataPlane 依据
// Content-Type 决定（BodyTransform 拿不到 headers，所以判定必须在这一层）。
// 所有断言都驱动真实 dataPlane + 真实 httptest 上游：「上游零字节」是观测到的
// 事实，不是假设。
//
// 上游以 418 + 固定标记应答：任何应当被阻断的请求一旦意外到达上游，客户端
// 状态码会立刻暴露它；0 命中 / 0 字节才是 fail-closed 的正证据。

const (
	w13UpstreamStatus = http.StatusTeapot
	w13UpstreamMarker = `{"w13":"upstream"}`
	w13Path           = "/v1/messages"
)

// w13Upstream 记录命中次数与收到的原始请求体。
type w13Upstream struct {
	mu   sync.Mutex
	body []byte
	hits atomic.Int64
}

func (u *w13Upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.body = body
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(w13UpstreamStatus)
	_, _ = io.WriteString(w, w13UpstreamMarker)
}

func (u *w13Upstream) received() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]byte(nil), u.body...)
}

func (u *w13Upstream) hitCount() int64 { return u.hits.Load() }

// w13UpstreamServer 启动真实 httptest 上游并返回其记录器与 URL。
func w13UpstreamServer(t *testing.T) (*w13Upstream, string) {
	t.Helper()
	rec := &w13Upstream{}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	return rec, srv.URL
}

// w13DataPlane 直接构建 dataPlane（与 router_test.go 的 serveViaRouterDataPlane
// 同层装配：真实 pipeline + 注入 Router 指向真实上游）。
func w13DataPlane(t *testing.T, upstreamURL string) *dataPlane {
	t.Helper()
	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	pipeline, err := BuildPipeline(BuildOptions{
		Detectors: cfg.Detectors.EnabledIDs(),
		Allowlist: cfg.Allowlist,
		Sink:      audit.NoopSink{},
		Tool:      "w1.3-dataplane-test",
	})
	if err != nil {
		t.Fatalf("BuildPipeline: %v", err)
	}
	deps := &Deps{Requests: new(atomic.Uint64), Redactions: new(atomic.Uint64)}
	return newDataPlane(Options{
		Core:     cfg,
		Router:   &routerStub{upstream: extension.Upstream{Name: "w1.3", BaseURL: upstreamURL}},
		Pipeline: pipeline,
		Sink:     audit.NoopSink{},
	}, deps)
}

// w13Do 把一次 POST 直接送进 dataPlane。contentType 为 nil 表示请求不带该
// header（只有缺失分支才会走 body 征兆嗅探）。
func w13Do(t *testing.T, dp *dataPlane, contentType *string, body []byte) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, w13Path, bytes.NewReader(body))
	if contentType != nil {
		req.Header.Set("Content-Type", *contentType)
	}
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("读取响应: %v", err)
	}
	return res.StatusCode, raw
}

// w13Ptr 用于表驱动测试里区分「缺失 header」（nil）与「存在但为空值」。
func w13Ptr[T any](v T) *T { return &v }

// w13DeepNestingBody 构造 10001 层嵌套数组、最内层为数字 1 的文档。不能只叠
// 10001 个 "["：全空嵌套的最内层容器在 depth == MaxNestingDepth 处被接受
// （见 W1.2 记录的 off-by-one），必须让非空元素落在
// depth = MaxNestingDepth+1 才会触发 ErrNestingDepth。
func w13DeepNestingBody() []byte {
	const depth = protocol.MaxNestingDepth + 1
	body := make([]byte, 0, 2*depth+1)
	body = append(body, bytes.Repeat([]byte("["), depth)...)
	body = append(body, '1')
	body = append(body, bytes.Repeat([]byte("]"), depth)...)
	return body
}

// TestDataPlaneJSONDeclaredUnparseableFailsClosed 锁定 fail-closed 分支：
// Content-Type 声明为 application/json 时，walker 不可解析的 body 必须在
// HTTP 层被 400 拒绝，且上游零命中、零字节（400 而非 403：这是「客户端发来的
// JSON 坏了」的客户端错误，不是策略裁决；403 保留给策略阻断路径）。
func TestDataPlaneJSONDeclaredUnparseableFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"invalid_utf8", []byte{0xff, 0xfe, 0x00, 0x01}},
		{"trailing_data", []byte(`{"a":1}garbage`)},
		{"deep_nesting", w13DeepNestingBody()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream, upstreamURL := w13UpstreamServer(t)
			dp := w13DataPlane(t, upstreamURL)
			contentType := "application/json"
			status, respBody := w13Do(t, dp, &contentType, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %q", status, respBody)
			}
			if hits := upstream.hitCount(); hits != 0 {
				t.Fatalf("upstream dialed %d time(s) for an unparseable JSON-declared body", hits)
			}
			if got := upstream.received(); len(got) != 0 {
				t.Fatalf("upstream received %d bytes, want 0: %q", len(got), got)
			}
			t.Logf("status=%d upstream_hits=%d upstream_bytes=%d", status, upstream.hitCount(), len(upstream.received()))
		})
	}
}

// TestDataPlaneNonJSONPassesThrough 锁定保留分支：显式非 JSON 的
// Content-Type 下，不可解析的 body 仍必须逐字节到达上游（pipeline 文档化的
// 非 JSON 直通行为），客户端拿到的是上游自己的状态与响应。
func TestDataPlaneNonJSONPassesThrough(t *testing.T) {
	upstream, upstreamURL := w13UpstreamServer(t)
	dp := w13DataPlane(t, upstreamURL)
	body := []byte("plain text, definitely not JSON\nsecond line \x01\x02")
	contentType := "text/plain; charset=utf-8"
	status, respBody := w13Do(t, dp, &contentType, body)
	if status != w13UpstreamStatus {
		t.Fatalf("status = %d, want the upstream's %d (a local response means no passthrough)", status, w13UpstreamStatus)
	}
	if !bytes.Contains(respBody, []byte(w13UpstreamMarker)) {
		t.Fatalf("响应体 %q 不含上游标记，未证明响应来自上游", respBody)
	}
	if hits := upstream.hitCount(); hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	got := upstream.received()
	if !bytes.Equal(got, body) {
		t.Fatalf("upstream bytes changed:\ngot  %q\nwant %q", got, body)
	}
	t.Logf("status=%d upstream_hits=%d upstream_bytes=%d byte_identical=true", status, upstream.hitCount(), len(got))
}

// TestDataPlaneMissingContentTypeJSONSymptomsFailsClosed 锁定 sniffing 从句：
// Content-Type 缺失但 body 呈现 JSON 征兆（前导 ASCII 空白后首字节为 `{`）且
// 不可解析 → 同样 fail-closed，上游零字节。
func TestDataPlaneMissingContentTypeJSONSymptomsFailsClosed(t *testing.T) {
	upstream, upstreamURL := w13UpstreamServer(t)
	dp := w13DataPlane(t, upstreamURL)
	body := []byte("  \n{\"a\":1}garbage")
	status, respBody := w13Do(t, dp, nil, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %q", status, respBody)
	}
	if hits := upstream.hitCount(); hits != 0 {
		t.Fatalf("upstream dialed %d time(s) for a JSON-symptom body without Content-Type", hits)
	}
	if got := upstream.received(); len(got) != 0 {
		t.Fatalf("upstream received %d bytes, want 0: %q", len(got), got)
	}
	t.Logf("status=%d upstream_hits=%d upstream_bytes=%d", status, upstream.hitCount(), len(upstream.received()))
}

// TestDataPlaneMissingContentTypeNonJSONPassesThrough 锁定 sniffing 的否定面：
// Content-Type 缺失且 body 无 JSON 征兆 → 直通，上游逐字节收到。
func TestDataPlaneMissingContentTypeNonJSONPassesThrough(t *testing.T) {
	upstream, upstreamURL := w13UpstreamServer(t)
	dp := w13DataPlane(t, upstreamURL)
	body := []byte("plain text, no JSON symptom at all")
	status, respBody := w13Do(t, dp, nil, body)
	if status != w13UpstreamStatus {
		t.Fatalf("status = %d, want the upstream's %d; body %q", status, w13UpstreamStatus, respBody)
	}
	if hits := upstream.hitCount(); hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	got := upstream.received()
	if !bytes.Equal(got, body) {
		t.Fatalf("upstream bytes changed:\ngot  %q\nwant %q", got, body)
	}
	t.Logf("status=%d upstream_hits=%d upstream_bytes=%d byte_identical=true", status, upstream.hitCount(), len(got))
}

// TestJSONContentTypeDetection 锁定 isJSONContentType 的表驱动语义：大小写
// 不敏感、允许 `;charset=` 参数、接受 application/json* 前缀（含结构化后缀）；
// 显式非 JSON 一律 false。
func TestJSONContentTypeDetection(t *testing.T) {
	cases := []struct {
		contentType string
		want        bool
	}{
		{"application/json", true},
		{"APPLICATION/JSON", true},
		{"Application/Json", true},
		{"application/json; charset=utf-8", true},
		{" application/json ;charset=UTF-8", true},
		{"application/json-patch+json", true},
		{"text/json", false},
		{"text/plain", false},
		{"application/xml", false},
		{"", false},
		{"; charset=utf-8", false},
	}
	for _, tc := range cases {
		if got := isJSONContentType(tc.contentType); got != tc.want {
			t.Errorf("isJSONContentType(%q) = %v, want %v", tc.contentType, got, tc.want)
		}
	}
}

// TestJSONSymptoms 锁定嗅探规则：跳过前导 ASCII 空白（空格/Tab/CR/LF）后，
// 第一个字节是 `{`、`[` 或 `"` 才算 JSON 征兆；空体、纯空白、其它字节（含
// UTF-8 BOM，它不是 ASCII 空白）都不是。
func TestJSONSymptoms(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want bool
	}{
		{"object", []byte(`{"a":1}`), true},
		{"array_fragment", []byte(`[1,2,`), true},
		{"string", []byte(`"x"`), true},
		{"whitespace_led_object", []byte("\n\t {\"a\":1}"), true},
		{"whitespace_led_array", []byte(" \r\n[1,2,"), true},
		{"leading_x", []byte("x-json"), false},
		{"empty", nil, false},
		{"whitespace_only", []byte(" \t\r\n"), false},
		{"utf8_bom", []byte("\xef\xbb\xbf{\"a\":1}"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jsonSymptoms(tc.body); got != tc.want {
				t.Errorf("jsonSymptoms(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// TestRequestDeclaresJSON 逐格锁定 header 判定矩阵：显式 JSON 声明优先于
// body；显式非 JSON 声明绝不被征兆覆盖；缺失/空值才 sniff。
func TestRequestDeclaresJSON(t *testing.T) {
	cases := []struct {
		name        string
		contentType *string
		body        []byte
		want        bool
	}{
		{"json_header", w13Ptr("application/json"), []byte("not json"), true},
		{"json_header_with_params", w13Ptr("Application/JSON; charset=utf-8"), []byte("not json"), true},
		{"non_json_header_ignores_symptoms", w13Ptr("text/plain"), []byte(`{"a":1`), false},
		{"absent_header_json_symptoms", nil, []byte(`{"a":1`), true},
		{"absent_header_non_json", nil, []byte("plain"), false},
		{"empty_header_treated_as_absent", w13Ptr(""), []byte(`[1,`), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, w13Path, bytes.NewReader(tc.body))
			if tc.contentType != nil {
				req.Header.Set("Content-Type", *tc.contentType)
			}
			if got := requestDeclaresJSON(req, tc.body); got != tc.want {
				t.Errorf("requestDeclaresJSON(contentType=%v, body=%q) = %v, want %v",
					tc.contentType, tc.body, got, tc.want)
			}
		})
	}
}
