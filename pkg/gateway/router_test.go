package gateway

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// routerStub 是一个假的 extension.Router：记录 Pick 调用次数并返回预设结果。
type routerStub struct {
	mu       sync.Mutex
	calls    int
	upstream extension.Upstream
	err      error
}

func (r *routerStub) Name() string { return "stub" }

func (r *routerStub) Pick(*extension.Request) (extension.Upstream, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return r.upstream, r.err
}

func (r *routerStub) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// serveViaRouterDataPlane 直接把请求送进 dataPlane，返回响应体与状态码，用于
// 断言 Router 解析结果实际指向的上游。
func serveViaRouterDataPlane(t *testing.T, core config.Config, router extension.Router, path, body string) (string, int) {
	t.Helper()
	pipeline, err := BuildPipeline(BuildOptions{
		Detectors: core.Detectors.EnabledIDs(),
		Allowlist: core.Allowlist,
		Sink:      audit.NoopSink{},
		Tool:      "gateway-router-test",
	})
	if err != nil {
		t.Fatalf("BuildPipeline: %v", err)
	}
	deps := &Deps{Requests: new(atomic.Uint64), Redactions: new(atomic.Uint64)}
	dp := newDataPlane(Options{Core: core, Router: router, Pipeline: pipeline, Sink: audit.NoopSink{}}, deps)

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("读取响应: %v", err)
	}
	return string(raw), res.StatusCode
}

// TestRouterInjection 验证 Options.Router 注入：注入的 Pick 被调用且其
// upstream 被使用；nil 时回退默认 resolver；零值 Upstream + nil error 也回退
// 默认路由；未知路径仍是 typed error（绝不猜测）。
func TestRouterInjection(t *testing.T) {
	injected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "injected")
	}))
	defer injected.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "default")
	}))
	defer fallback.Close()

	core := config.Default()
	core.Listen.Host = "127.0.0.1"
	core.Listen.Port = 0
	core.Upstreams = config.Upstreams{"/v1/messages": fallback.URL}

	t.Run("注入的 Router 被调用且其 upstream 被使用", func(t *testing.T) {
		stub := &routerStub{upstream: extension.Upstream{Name: "injected", BaseURL: injected.URL}}
		body, code := serveViaRouterDataPlane(t, core, stub, "/v1/messages", `{"model":"m"}`)
		if code != http.StatusOK {
			t.Fatalf("状态码 = %d, want 200", code)
		}
		if body != "injected" {
			t.Fatalf("响应体 = %q, want %q（注入 upstream 未被使用）", body, "injected")
		}
		if n := stub.callCount(); n != 1 {
			t.Fatalf("Pick 调用次数 = %d, want 1", n)
		}
	})

	t.Run("nil Router 回退默认 resolver（默认路径回归）", func(t *testing.T) {
		body, code := serveViaRouterDataPlane(t, core, nil, "/v1/messages", `{"model":"m"}`)
		if code != http.StatusOK {
			t.Fatalf("状态码 = %d, want 200", code)
		}
		if body != "default" {
			t.Fatalf("响应体 = %q, want %q（默认路径回归失败）", body, "default")
		}
	})

	t.Run("零值 Upstream + nil error 回退默认路由", func(t *testing.T) {
		stub := &routerStub{}
		body, code := serveViaRouterDataPlane(t, core, stub, "/v1/messages", `{"model":"m"}`)
		if code != http.StatusOK {
			t.Fatalf("状态码 = %d, want 200", code)
		}
		if body != "default" {
			t.Fatalf("响应体 = %q, want %q（零值未回退默认）", body, "default")
		}
		if n := stub.callCount(); n != 1 {
			t.Fatalf("Pick 调用次数 = %d, want 1", n)
		}
	})

	t.Run("未知路径仍是 typed error", func(t *testing.T) {
		stub := &routerStub{}
		_, code := serveViaRouterDataPlane(t, core, stub, "/v1/not-a-route", `{"model":"m"}`)
		if code != http.StatusBadGateway {
			t.Fatalf("状态码 = %d, want 502", code)
		}
		_, err := proxy.NewResolver(core.Upstreams, nil).
			Pick(&extension.Request{Method: http.MethodPost, Path: "/v1/not-a-route"})
		if !errors.Is(err, proxy.ErrUnknownUpstream) {
			t.Fatalf("默认 resolver 错误 = %v, want ErrUnknownUpstream", err)
		}
	})
}
