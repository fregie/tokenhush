package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/allowlist"
	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
)

// TestAllowlistEndpointWiring 是 W5.3 的 pkg/gateway 验收测试：buildHandler
// 必须把 W0.3/W5.1 的同一 store 句柄接给 ControlAPI，并把
// GET/POST/DELETE /allowlist **以及无方法 /allowlist** 全部注册到同一个受守卫
// 的 control handler（无方法注册是 PUT 留在控制面、产生 405 的唯一原因）。
//
// 决策/证伪边界：failure 子测试里的 PUT 若落到数据面，会经 routerStub 命中
// httptest 上游并返回上游的 418 —— 「上游命中 > 0 / 收到字节」是「落到数据面」
// 的直接证据，而不是靠状态码猜测。
const (
	w53ControlToken = "w5.3-wiring-control-token-not-a-secret"
	w53Seed         = "seed.allowlist.entry"
)

// w53Sink 是 audit.AuditSink 的记录型测试替身。
type w53Sink struct {
	mu   sync.Mutex
	rows []audit.Record
}

func (s *w53Sink) Record(rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, rec)
	return nil
}

func (s *w53Sink) records() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.rows...)
}

// w53Server 用真实 buildHandler 组装一台 loopback 测试网关：真实 pipeline *
// 注入 Router 指向真实上游，控制面与数据面与生产完全同层。
func w53Server(t *testing.T, store AllowlistStore, sink audit.AuditSink, upstreamURL string) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	pipe := mustBuildPipeline(t, BuildOptions{
		Detectors:      cfg.Detectors.EnabledIDs(),
		Allowlist:      cfg.Allowlist,
		AllowlistStore: store,
		Sink:           audit.NoopSink{},
		Tool:           "w5.3-wiring-test",
	})
	deps := &Deps{Requests: new(atomic.Uint64), Redactions: new(atomic.Uint64), Token: w53ControlToken}
	opts := Options{
		Core:           cfg,
		Router:         &routerStub{upstream: extension.Upstream{Name: "w5.3", BaseURL: upstreamURL}},
		Pipeline:       pipe,
		Sink:           sink,
		AllowlistStore: store,
	}

	srv := httptest.NewUnstartedServer(nil)
	tcp, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("httptest listener addr = %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	port := tcp.Port
	srv.Config.Handler = buildHandler(opts, deps, port, []string{"127.0.0.1:" + strconv.Itoa(port)}, time.Now())
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// w53Fixture 构造一个带种子 store + 记录型上游的网关。
func w53Fixture(t *testing.T) (*allowlist.Store, *w13Upstream, *httptest.Server) {
	t.Helper()
	store, err := allowlist.Open(t.TempDir(), []string{w53Seed}, io.Discard)
	if err != nil {
		t.Fatalf("allowlist.Open: %v", err)
	}
	upstream, upstreamURL := w13UpstreamServer(t)
	return store, upstream, w53Server(t, store, &w53Sink{}, upstreamURL)
}

// w53Request 发一次真实 HTTP 请求；token == "" 时不带 Authorization，
// body != nil 时设置 JSON Content-Type。
func w53Request(t *testing.T, srv *httptest.Server, method, path, token string, body []byte, mutate func(*http.Request)) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header, raw
}

// w53AssertNoEffect 断言一次被拒请求没有副作用：白名单逐项未变、上游零命中零字节，
// 并把观测值写进测试日志（failure 证据的原始事实）。
func w53AssertNoEffect(t *testing.T, label string, store AllowlistStore, upstream *w13Upstream, want []string) {
	t.Helper()
	got := store.Entries()
	t.Logf("%s: upstream_hits=%d upstream_bytes=%d allowlist=%v", label, upstream.hitCount(), len(upstream.received()), got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s changed the allowlist: got %v, want %v", label, got, want)
	}
	if hits := upstream.hitCount(); hits != 0 {
		t.Fatalf("%s reached the data plane: upstream dialed %d time(s)", label, hits)
	}
	if raw := upstream.received(); len(raw) != 0 {
		t.Fatalf("%s sent %d byte(s) upstream: %q", label, len(raw), raw)
	}
}

// w53DecodeList 把 /allowlist 响应解码为 []string，失败即 fail。
func w53DecodeList(t *testing.T, body []byte) []string {
	t.Helper()
	var entries []string
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("body is not a JSON string array (%v): %q", err, body)
	}
	return entries
}

func TestAllowlistEndpointWiring(t *testing.T) {
	t.Run("crud_round_trip_status_and_same_store_instance", func(t *testing.T) {
		store, err := allowlist.Open(t.TempDir(), []string{w53Seed}, io.Discard)
		if err != nil {
			t.Fatalf("allowlist.Open: %v", err)
		}
		sink := &w53Sink{}
		upstream, upstreamURL := w13UpstreamServer(t)
		srv := w53Server(t, store, sink, upstreamURL)

		code, _, body := w53Request(t, srv, http.MethodGet, controlAllowlistPath, w53ControlToken, nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /allowlist = %d, want 200 (body %q)", code, body)
		}
		t.Logf("GET /allowlist -> %d %s", code, strings.TrimSpace(string(body)))
		if got := w53DecodeList(t, body); !reflect.DeepEqual(got, []string{w53Seed}) {
			t.Fatalf("initial list = %v, want [%q]", got, w53Seed)
		}

		// 加入白名单之前：数据面必须脱敏 wrapper（上游收到的 body 不含该字面量）。
		wrapper := "keep." + seamTestKey() + ".keep"
		dataBody := []byte(`{"payload":"` + wrapper + `"}`)
		if code, _, _ := w53Request(t, srv, http.MethodPost, "/v1/messages", "", dataBody, nil); code != w13UpstreamStatus {
			t.Fatalf("data-plane before allowlisting = %d, want the upstream's %d", code, w13UpstreamStatus)
		}
		if got := upstream.received(); bytes.Contains(got, []byte(wrapper)) {
			t.Fatalf("wrapper reached the upstream before it was allowlisted (redaction broken): %q", got)
		}

		code, _, body = w53Request(t, srv, http.MethodPost, controlAllowlistPath, w53ControlToken,
			[]byte(`{"entry":"runtime.one"}`), nil)
		if code != http.StatusOK {
			t.Fatalf("POST /allowlist = %d, want 200 (body %q)", code, body)
		}
		t.Logf("POST /allowlist runtime.one -> %d %s", code, strings.TrimSpace(string(body)))
		want := []string{"runtime.one", w53Seed}
		sort.Strings(want)
		if got := w53DecodeList(t, body); !reflect.DeepEqual(got, want) {
			t.Fatalf("post response = %v, want %v", got, want)
		}

		code, _, statusBody := w53Request(t, srv, http.MethodGet, controlStatusPath, w53ControlToken, nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /status = %d, want 200", code)
		}
		var status struct {
			Allowlist int `json:"allowlist"`
		}
		if err := json.Unmarshal(statusBody, &status); err != nil {
			t.Fatalf("/status is not JSON (%v): %q", err, statusBody)
		}
		if status.Allowlist != 2 {
			t.Fatalf("/status allowlist = %d, want 2 (body %q)", status.Allowlist, statusBody)
		}
		t.Logf("GET /status -> %d allowlist=%d", code, status.Allowlist)

		// 身份证明：端点写入的条目必须与 pipeline 检测器读到的是同一 store。
		// 加入 wrapper 后，同一数据面请求必须把 wrapper 逐字节送到上游。
		code, _, body = w53Request(t, srv, http.MethodPost, controlAllowlistPath, w53ControlToken,
			[]byte(`{"entry":"`+wrapper+`"}`), nil)
		if code != http.StatusOK {
			t.Fatalf("POST wrapper /allowlist = %d, want 200 (body %q)", code, body)
		}
		if !bytes.Contains(body, []byte(wrapper)) {
			t.Fatalf("post response %q does not list the new entry", body)
		}
		if code, _, _ := w53Request(t, srv, http.MethodPost, "/v1/messages", "", dataBody, nil); code != w13UpstreamStatus {
			t.Fatalf("data-plane after allowlisting = %d, want the upstream's %d", code, w13UpstreamStatus)
		}
		if got := upstream.received(); !bytes.Contains(got, []byte(wrapper)) {
			t.Fatalf("endpoint and pipeline do not share the store: upstream did not receive the allowlisted wrapper: %q", got)
		}
		t.Logf("identity proof: POST /allowlist then data plane -> upstream received the allowlisted wrapper verbatim")

		code, _, _ = w53Request(t, srv, http.MethodDelete, controlAllowlistPath, w53ControlToken,
			[]byte(`{"entry":"runtime.one"}`), nil)
		if code != http.StatusOK {
			t.Fatalf("DELETE runtime.one = %d, want 200", code)
		}
		code, _, body = w53Request(t, srv, http.MethodDelete, controlAllowlistPath, w53ControlToken,
			[]byte(`{"entry":"`+wrapper+`"}`), nil)
		if code != http.StatusOK {
			t.Fatalf("DELETE wrapper = %d, want 200 (body %q)", code, body)
		}
		if got := w53DecodeList(t, body); !reflect.DeepEqual(got, []string{w53Seed}) {
			t.Fatalf("final list = %v, want [%q]", got, w53Seed)
		}
		code, _, statusBody = w53Request(t, srv, http.MethodGet, controlStatusPath, w53ControlToken, nil, nil)
		if code != http.StatusOK {
			t.Fatalf("final GET /status = %d, want 200", code)
		}
		if err := json.Unmarshal(statusBody, &status); err != nil {
			t.Fatalf("final /status is not JSON (%v): %q", err, statusBody)
		}
		if status.Allowlist != 1 {
			t.Fatalf("final /status allowlist = %d, want 1 (body %q)", status.Allowlist, statusBody)
		}

		// 审计元数据：每次成功变更一行，含动作/来源/结果条目数；绝不含条目文本。
		rows := sink.records()
		if len(rows) != 4 {
			t.Fatalf("audit rows = %d, want 4 (%+v)", len(rows), rows)
		}
		wantActions := []string{"add", "add", "remove", "remove"}
		wantCounts := []int{2, 3, 2, 1}
		for i, row := range rows {
			if row.Method != wantActions[i] {
				t.Errorf("row %d method = %q, want %q", i, row.Method, wantActions[i])
			}
			if row.Client != "allowlist-source-cli" {
				t.Errorf("row %d client/source = %q, want allowlist-source-cli", i, row.Client)
			}
			if len(row.Detectors) != 1 || row.Detectors[0] != "entries:"+strconv.Itoa(wantCounts[i]) {
				t.Errorf("row %d count tag = %v, want [entries:%d]", i, row.Detectors, wantCounts[i])
			}
			if bytes.Contains([]byte(row.Provider+row.Path+row.Method+row.Client), []byte(wrapper)) ||
				bytes.Contains([]byte(row.Provider+row.Path+row.Method+row.Client), []byte("runtime.one")) {
				t.Errorf("row %d leaked an entry value: %+v", i, row)
			}
		}
	})

	t.Run("missing_token_is_401", func(t *testing.T) {
		store, upstream, srv := w53Fixture(t)
		baseline := store.Entries()
		code, _, _ := w53Request(t, srv, http.MethodGet, controlAllowlistPath, "", nil, nil)
		t.Logf("missing token GET /allowlist -> %d", code)
		if code != http.StatusUnauthorized {
			t.Fatalf("GET /allowlist without a token = %d, want 401", code)
		}
		code, _, _ = w53Request(t, srv, http.MethodPost, controlAllowlistPath, "", []byte(`{"entry":"no.token"}`), nil)
		t.Logf("missing token POST /allowlist -> %d", code)
		if code != http.StatusUnauthorized {
			t.Fatalf("POST /allowlist without a token = %d, want 401", code)
		}
		w53AssertNoEffect(t, "missing_token", store, upstream, baseline)
	})

	t.Run("wrong_token_is_401", func(t *testing.T) {
		store, upstream, srv := w53Fixture(t)
		baseline := store.Entries()
		code, _, _ := w53Request(t, srv, http.MethodPost, controlAllowlistPath, "wrong-"+w53ControlToken,
			[]byte(`{"entry":"wrong.token"}`), nil)
		t.Logf("wrong token POST /allowlist -> %d", code)
		if code != http.StatusUnauthorized {
			t.Fatalf("POST /allowlist with a wrong token = %d, want 401", code)
		}
		w53AssertNoEffect(t, "wrong_token", store, upstream, baseline)
	})

	t.Run("wrong_host_is_403", func(t *testing.T) {
		store, upstream, srv := w53Fixture(t)
		baseline := store.Entries()
		code, _, _ := w53Request(t, srv, http.MethodGet, controlAllowlistPath, w53ControlToken, nil,
			func(r *http.Request) { r.Host = "evil.example" })
		t.Logf("foreign Host GET /allowlist -> %d", code)
		if code != http.StatusForbidden {
			t.Fatalf("GET /allowlist with a foreign Host = %d, want 403", code)
		}
		w53AssertNoEffect(t, "wrong_host", store, upstream, baseline)
	})

	t.Run("cross_site_origin_is_403", func(t *testing.T) {
		store, upstream, srv := w53Fixture(t)
		baseline := store.Entries()
		code, _, _ := w53Request(t, srv, http.MethodPost, controlAllowlistPath, w53ControlToken,
			[]byte(`{"entry":"cross.site"}`), func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") })
		t.Logf("cross-site Origin POST /allowlist -> %d", code)
		if code != http.StatusForbidden {
			t.Fatalf("cross-site POST /allowlist = %d, want 403", code)
		}
		w53AssertNoEffect(t, "cross_site_origin", store, upstream, baseline)
	})

	t.Run("put_is_405_and_never_reaches_the_data_plane", func(t *testing.T) {
		store, upstream, srv := w53Fixture(t)
		baseline := store.Entries()

		code, header, body := w53Request(t, srv, http.MethodPut, controlAllowlistPath, w53ControlToken,
			[]byte(`{"entry":"put.must.not.land"}`), nil)
		t.Logf("PUT /allowlist -> %d Allow=%q upstream_hits=%d upstream_bytes=%d",
			code, header.Get("Allow"), upstream.hitCount(), len(upstream.received()))
		if code != http.StatusMethodNotAllowed {
			t.Fatalf("PUT /allowlist = %d, want 405 (body %q); upstream_hits=%d upstream_bytes=%q means it fell through to the data plane",
				code, body, upstream.hitCount(), upstream.received())
		}
		if allow := header.Get("Allow"); allow == "" {
			t.Fatalf("PUT /allowlist Allow header is empty, want the registered methods")
		}
		if got := w53DecodeJSONError(t, body); got == "" {
			t.Fatalf("PUT 405 body = %q, want a JSON error", body)
		}
		w53AssertNoEffect(t, "put", store, upstream, baseline)
	})

	t.Run("nil_store_returns_503_without_panic", func(t *testing.T) {
		upstream, upstreamURL := w13UpstreamServer(t)
		srv := w53Server(t, nil, &w53Sink{}, upstreamURL)
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			var body []byte
			if method != http.MethodGet {
				body = []byte(`{"entry":"x"}`)
			}
			code, _, raw := w53Request(t, srv, method, controlAllowlistPath, w53ControlToken, body, nil)
			t.Logf("nil store %s /allowlist -> %d", method, code)
			if code != http.StatusServiceUnavailable {
				t.Fatalf("%s /allowlist with no store = %d, want 503 (body %q)", method, code, raw)
			}
		}
		if hits := upstream.hitCount(); hits != 0 {
			t.Fatalf("nil-store /allowlist reached the data plane: upstream dialed %d time(s)", hits)
		}
	})
}

// w53DecodeJSONError 提取控制面 {"error": ...} 消息，失败即 fail。
func w53DecodeJSONError(t *testing.T, body []byte) string {
	t.Helper()
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("body is not a JSON error (%v): %q", err, body)
	}
	return payload.Error
}
