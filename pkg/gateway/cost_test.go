package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
)

// 运行时拼装的合成凭证：各片段分开写，树里不出现一个连续的 key 形状字面量
// （gitleaks 干净），拼起来仍匹配内置的 `sk-` 前缀检测器。
const (
	costSecretHead = "sk"
	costSecretA    = "Te5tA1b2"
	costSecretB    = "C3d4E5f6"
	costSecretC    = "G7h8I9j0"
)

func costTestSecret() string {
	return costSecretHead + "-" + "proj" + "-" + costSecretA + costSecretB + costSecretC
}

// costPlaceholderRe 匹配脱敏层写出的占位符 token 语法。
var costPlaceholderRe = regexp.MustCompile(`__PII_[a-z][a-z0-9_]*_[0-9a-f]{8,}__`)

// recordedPair 是 fakeCostSink 捕获到的一次 CostSink 调用。
type recordedPair struct {
	req  *extension.Request
	resp *extension.Response
}

// fakeCostSink 记录每一次 Record，供测试断言 gateway 实际交给成本接缝的内容。
type fakeCostSink struct {
	mu     sync.Mutex
	pairs  []recordedPair
	called chan struct{}
}

func newFakeCostSink() *fakeCostSink {
	return &fakeCostSink{called: make(chan struct{}, 8)}
}

func (s *fakeCostSink) Name() string { return "fake/cost" }

func (s *fakeCostSink) Record(req *extension.Request, resp *extension.Response) {
	s.mu.Lock()
	s.pairs = append(s.pairs, recordedPair{req: cloneRequest(req), resp: cloneResponse(resp)})
	s.mu.Unlock()
	select {
	case s.called <- struct{}{}:
	default:
	}
}

func (s *fakeCostSink) wait(t *testing.T) recordedPair {
	t.Helper()
	select {
	case <-s.called:
	case <-time.After(10 * time.Second):
		t.Fatalf("CostSink.Record 未被调用")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pairs) == 0 {
		t.Fatalf("CostSink.Record 被调用但没有捕获到内容")
	}
	return s.pairs[len(s.pairs)-1]
}

func cloneRequest(req *extension.Request) *extension.Request {
	if req == nil {
		return nil
	}
	cp := *req
	return &cp
}

func cloneResponse(resp *extension.Response) *extension.Response {
	if resp == nil {
		return nil
	}
	cp := *resp
	return &cp
}

// costEchoUpstream 记录收到的请求体，并在 JSON 字符串里回显它，从而证明
// 入站回填；响应同时携带 usage，让成本接收器有可用数据。
type costEchoUpstream struct {
	mu   sync.Mutex
	body []byte
}

func (u *costEchoUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.body = body
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"echo":%q,"usage":{"input_tokens":3,"output_tokens":2}}`, string(body))
}

func (u *costEchoUpstream) received() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]byte(nil), u.body...)
}

// costSSEUpstream 回显脱敏后的请求体并发送一条 usage 结束块与 [DONE] 哨兵，
// 用于验证流式路径既不阻塞也不破坏 SSE。
type costSSEUpstream struct {
	mu   sync.Mutex
	body []byte
}

func (u *costSSEUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.body = body
	u.mu.Unlock()

	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	fmt.Fprintf(w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", string(body))
	if flusher != nil {
		flusher.Flush()
	}
	fmt.Fprint(w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7}}\n\n")
	if flusher != nil {
		flusher.Flush()
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func (u *costSSEUpstream) received() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]byte(nil), u.body...)
}

// startCostGateway 在临时 loopback 端口上运行一个 gateway，返回其 base URL
// 与停止函数；上游按路径 /v1/messages 固定指向 upstreamURL。
func startCostGateway(t *testing.T, upstreamURL string, sink extension.CostSink) (base string, stop func()) {
	t.Helper()
	dataDir := t.TempDir()

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamURL}

	pipeline, err := BuildPipeline(BuildOptions{
		Detectors: cfg.Detectors.EnabledIDs(),
		Allowlist: cfg.Allowlist,
		Sink:      audit.NoopSink{},
		Tool:      "gateway-cost-test",
	})
	if err != nil {
		t.Fatalf("BuildPipeline: %v", err)
	}

	ready := make(chan RunInfo, 1)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{
			Core:     cfg,
			Pipeline: pipeline,
			CostSink: sink,
			Sink:     audit.NoopSink{},
			Setup: func(d *Deps) error {
				d.DataDir = dataDir
				return nil
			},
			Ready: func(info RunInfo) { ready <- info },
		})
	}()

	select {
	case info := <-ready:
		base = fmt.Sprintf("http://127.0.0.1:%d", info.Port)
	case err := <-errCh:
		cancel()
		t.Fatalf("gateway 在就绪前退出: %v", err)
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatalf("gateway 15s 内未就绪")
	}

	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-errCh:
			case <-time.After(15 * time.Second):
				t.Errorf("gateway 15s 内未关闭")
			}
		})
	}
	return base, stop
}

func postGateway(t *testing.T, url, body string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应: %v", err)
	}
	return resp, raw
}

// renderRecordedJSON 把接收器捕获的 JSON 载荷渲染成文本，便于断言其中是否
// 出现占位符或原始 secret。
func renderRecordedJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化捕获的 JSON: %v", err)
	}
	return string(raw)
}

// TestCostSinkInvoked 验证非流式响应路径：请求完成后 CostSink 收到 Record，
// 且响应副本是脱敏后的占位符 JSON，绝不含原始 secret；上游始终只见占位符。
func TestCostSinkInvoked(t *testing.T) {
	upstream := &costEchoUpstream{}
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	sink := newFakeCostSink()
	base, stop := startCostGateway(t, srv.URL, sink)
	defer stop()

	secret := costTestSecret()
	body := fmt.Sprintf(`{"model":"gateway-cost","messages":[{"role":"user","content":%q}]}`, secret)
	resp, clientRaw := postGateway(t, base+"/v1/messages", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("数据面状态 = %d, want 200", resp.StatusCode)
	}
	if !bytes.Contains(clientRaw, []byte(secret)) {
		t.Fatalf("客户端响应丢失了回填后的 secret: %q", clientRaw)
	}

	upstreamRaw := upstream.received()
	if bytes.Contains(upstreamRaw, []byte(secret)) {
		t.Fatalf("上游收到了原始 secret: %q", upstreamRaw)
	}
	if !costPlaceholderRe.Match(upstreamRaw) {
		t.Fatalf("上游请求体不含占位符: %q", upstreamRaw)
	}

	pair := sink.wait(t)
	if pair.resp == nil {
		t.Fatal("CostSink 收到了 nil response")
	}
	got := renderRecordedJSON(t, pair.resp.JSON)
	if bytes.Contains([]byte(got), []byte(secret)) {
		t.Errorf("CostSink 响应含原始 secret: %s", got)
	}
	if !strings.Contains(got, "__PII_") {
		t.Errorf("CostSink 响应不含脱敏占位符: %s", got)
	}
	if pair.req == nil {
		t.Fatal("CostSink 收到了 nil request")
	}
	reqText := renderRecordedJSON(t, pair.req.JSON)
	if strings.Contains(reqText, secret) {
		t.Errorf("CostSink 请求含原始 secret: %s", reqText)
	}
}

// TestCostSinkStreaming 验证 SSE 路径：流不被阻塞或截断，客户端收到回填后的
// secret，而 CostSink 收到的是回填前、含占位符与 usage 的事件列表。
func TestCostSinkStreaming(t *testing.T) {
	upstream := &costSSEUpstream{}
	srv := httptest.NewServer(upstream)
	defer srv.Close()

	sink := newFakeCostSink()
	base, stop := startCostGateway(t, srv.URL, sink)
	defer stop()

	secret := costTestSecret()
	body := fmt.Sprintf(`{"model":"gateway-stream","messages":[{"role":"user","content":%q}]}`, secret)
	resp, clientRaw := postGateway(t, base+"/v1/messages", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("流式状态 = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want SSE", ct)
	}
	if !bytes.Contains(clientRaw, []byte("data: [DONE]")) {
		t.Fatalf("SSE 流被截断: %q", clientRaw)
	}
	if !bytes.Contains(clientRaw, []byte(secret)) {
		t.Fatalf("SSE 客户端响应未回填 secret: %q", clientRaw)
	}
	if costPlaceholderRe.Match(clientRaw) {
		t.Fatalf("SSE 客户端响应仍含占位符: %q", clientRaw)
	}
	if bytes.Contains(upstream.received(), []byte(secret)) {
		t.Fatalf("上游收到了原始 secret")
	}

	pair := sink.wait(t)
	if pair.resp == nil {
		t.Fatal("CostSink 收到了 nil response")
	}
	got := renderRecordedJSON(t, pair.resp.JSON)
	if bytes.Contains([]byte(got), []byte(secret)) {
		t.Errorf("CostSink 流式响应含原始 secret: %s", got)
	}
	if !strings.Contains(got, "usage") || !strings.Contains(got, "prompt_tokens") {
		t.Errorf("CostSink 未收到 usage chunk: %s", got)
	}
	if !strings.Contains(got, "__PII_") {
		t.Errorf("CostSink 流式响应不含脱敏占位符: %s", got)
	}
}
