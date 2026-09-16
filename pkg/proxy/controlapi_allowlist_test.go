package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
)

// TestAllowlistEndpoint 是 W5.3 的 pkg/proxy 验收测试：ControlAPI 在
// HostAllowlist → OriginPolicy → ControlAuth 之后提供 GET/POST/DELETE
// /allowlist，复用 W5.1 的 store 与三个哨兵错误，并且每次成功变更回调一次审计
// 元数据。所有请求都打到真实 loopback 端口，不 mock 守卫链。
//
// 形状冻结（与 gateway 的接线共用）：
//   - GET  返回 200 + JSON 数组（确定性排序，空集为 []）；
//   - POST/DELETE 请求体 {"entry":"..."}，返回 200 + 变更后的完整数组；
//   - ErrInvalidEntry / ErrDuplicate → 400、ErrNotFound → 404（带 store 原始消息）；
//   - 未配置 store → GET/POST/DELETE 一律 503，其它方法仍是 JSON 405；
//   - 方法不匹配（PUT/PATCH）由内部 mux 产出 JSON 405 并保留 Allow。
func TestAllowlistEndpoint(t *testing.T) {
	t.Run("crud_round_trip_lists_entries_and_records_audit", func(t *testing.T) {
		const seed = "seed.allowlist.entry"
		store := newAllowlistTestStore(t, seed)
		var events []ControlAuditEvent
		api := NewControlAPI(
			allowlistStatusFunc(store),
			WithControlAllowlist(store),
			WithControlAudit(func(ev ControlAuditEvent) { events = append(events, ev) }),
		)
		srv := controlServer(t, api, controlTestToken)

		code, _, body := controlDo(t, srv, http.MethodGet, controlAllowlistPath, controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /allowlist = %d, want 200 (body %q)", code, body)
		}
		if got := controlDecodeJSON[[]string](t, body); !reflect.DeepEqual(got, []string{seed}) {
			t.Fatalf("initial list = %v, want [%q]", got, seed)
		}

		code, _, body = controlDoBody(t, srv, http.MethodPost, controlAllowlistPath, controlTestToken,
			[]byte(`{"entry":"runtime.one"}`), nil)
		if code != http.StatusOK {
			t.Fatalf("POST /allowlist = %d, want 200 (body %q)", code, body)
		}
		want := []string{"runtime.one", seed}
		sort.Strings(want)
		if got := controlDecodeJSON[[]string](t, body); !reflect.DeepEqual(got, want) {
			t.Fatalf("post response = %v, want %v", got, want)
		}

		// status 必须反映变更后的条目数（metadata only）。
		code, _, statusBody := controlDo(t, srv, http.MethodGet, controlStatusPath, controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /status = %d, want 200", code)
		}
		if got := controlDecodeJSON[ControlStatus](t, statusBody); got.Allowlist != len(want) {
			t.Fatalf("/status allowlist = %d, want %d", got.Allowlist, len(want))
		}

		code, _, body = controlDoBody(t, srv, http.MethodDelete, controlAllowlistPath, controlTestToken,
			[]byte(`{"entry":"runtime.one"}`), nil)
		if code != http.StatusOK {
			t.Fatalf("DELETE /allowlist = %d, want 200 (body %q)", code, body)
		}
		if got := controlDecodeJSON[[]string](t, body); !reflect.DeepEqual(got, []string{seed}) {
			t.Fatalf("delete response = %v, want [%q]", got, seed)
		}

		if len(events) != 2 {
			t.Fatalf("audit events = %d, want 2 (%+v)", len(events), events)
		}
		if events[0].Action != ControlAllowlistActionAdd || events[1].Action != ControlAllowlistActionRemove {
			t.Fatalf("audit actions = %q,%q, want add,remove", events[0].Action, events[1].Action)
		}
		for i, ev := range events {
			if ev.Source != ControlAllowlistSource {
				t.Errorf("audit event %d source = %q, want %q", i, ev.Source, ControlAllowlistSource)
			}
		}
		if events[0].Count != 2 || events[1].Count != 1 {
			t.Errorf("audit counts = %d,%d, want 2,1", events[0].Count, events[1].Count)
		}
	})

	t.Run("empty_list_serializes_as_array", func(t *testing.T) {
		empty := newAllowlistTestStore(t)
		srv := controlServer(t, NewControlAPI(nil, WithControlAllowlist(empty)), controlTestToken)
		code, _, body := controlDo(t, srv, http.MethodGet, controlAllowlistPath, controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET empty /allowlist = %d, want 200 (body %q)", code, body)
		}
		if !bytes.Contains(body, []byte("[]")) {
			t.Fatalf("empty list body = %q, want [] (never null)", body)
		}
	})

	t.Run("audit_runs_only_on_success", func(t *testing.T) {
		store := newAllowlistTestStore(t, "present.entry")
		calls := 0
		srv := controlServer(t, NewControlAPI(nil,
			WithControlAllowlist(store),
			WithControlAudit(func(ControlAuditEvent) { calls++ }),
		), controlTestToken)

		code, _, body := controlDoBody(t, srv, http.MethodPost, controlAllowlistPath, controlTestToken,
			[]byte(`{"entry":"present.entry"}`), nil)
		if code != http.StatusBadRequest {
			t.Fatalf("duplicate POST = %d, want 400 (body %q)", code, body)
		}
		if calls != 0 {
			t.Fatalf("audit ran %d time(s) on a rejected mutation, want 0", calls)
		}

		code, _, _ = controlDoBody(t, srv, http.MethodPost, controlAllowlistPath, controlTestToken,
			[]byte(`{"entry":"fresh.entry"}`), nil)
		if code != http.StatusOK {
			t.Fatalf("valid POST = %d, want 200", code)
		}
		if calls != 1 {
			t.Fatalf("audit ran %d time(s) after a mutation, want 1", calls)
		}
	})

	t.Run("invalid_entry_is_400_with_the_store_message", func(t *testing.T) {
		store := newAllowlistTestStore(t)
		srv := controlServer(t, NewControlAPI(nil, WithControlAllowlist(store)), controlTestToken)
		code, _, body := controlDoBody(t, srv, http.MethodPost, controlAllowlistPath, controlTestToken,
			[]byte("{\"entry\":\"bad\\nvalue\"}"), nil)
		if code != http.StatusBadRequest {
			t.Fatalf("control-char POST = %d, want 400 (body %q)", code, body)
		}
		if got := controlDecodeJSON[controlErrorBody](t, body); got.Error == "" {
			t.Fatalf("error body = %q, want the store's message", body)
		}
		if len(store.Entries()) != 0 {
			t.Fatalf("store changed on an invalid entry: %v", store.Entries())
		}
	})

	t.Run("duplicate_is_400", func(t *testing.T) {
		store := newAllowlistTestStore(t, "dup.entry")
		srv := controlServer(t, NewControlAPI(nil, WithControlAllowlist(store)), controlTestToken)
		code, _, body := controlDoBody(t, srv, http.MethodPost, controlAllowlistPath, controlTestToken,
			[]byte(`{"entry":"dup.entry"}`), nil)
		if code != http.StatusBadRequest {
			t.Fatalf("duplicate POST = %d, want 400 (body %q)", code, body)
		}
		if got := controlDecodeJSON[controlErrorBody](t, body); got.Error == "" {
			t.Fatalf("duplicate error body = %q, want non-empty", body)
		}
	})

	t.Run("remove_missing_is_404_with_the_store_message", func(t *testing.T) {
		store := newAllowlistTestStore(t)
		srv := controlServer(t, NewControlAPI(nil, WithControlAllowlist(store)), controlTestToken)
		code, _, body := controlDoBody(t, srv, http.MethodDelete, controlAllowlistPath, controlTestToken,
			[]byte(`{"entry":"never.there"}`), nil)
		t.Logf("missing DELETE /allowlist -> %d %s", code, bytes.TrimSpace(body))
		if code != http.StatusNotFound {
			t.Fatalf("missing DELETE = %d, want 404 (body %q)", code, body)
		}
		// 关键：404 必须携带 store 自己的消息，而不是 controlJSONWriter 的
		// 通用 "not found"（若为后者，说明显式 JSON 404 被当成了 mux 回退）。
		if got := controlDecodeJSON[controlErrorBody](t, body); got.Error == "" || got.Error == "not found" {
			t.Fatalf("404 error body = %q, want the store's own message", body)
		}
	})

	t.Run("entry_must_come_from_the_json_body", func(t *testing.T) {
		store := newAllowlistTestStore(t)
		srv := controlServer(t, NewControlAPI(nil, WithControlAllowlist(store)), controlTestToken)

		code, _, _ := controlDoBody(t, srv, http.MethodPost, controlAllowlistPath+"?entry=via.query",
			controlTestToken, []byte(`{"entry":"via.body"}`), nil)
		if code != http.StatusBadRequest {
			t.Fatalf("query-parameter POST = %d, want 400", code)
		}
		if len(store.Entries()) != 0 {
			t.Fatalf("query-parameter request mutated the store: %v", store.Entries())
		}

		for name, raw := range map[string]string{
			"malformed":      `{"entry":`,
			"unknown_field":  `{"entry":"x","extra":true}`,
			"wrong_type":     `{"entry":42}`,
			"trailing_value": `{"entry":"x"}{"entry":"y"}`,
			"missing_field":  `{}`,
		} {
			t.Run(name, func(t *testing.T) {
				code, _, body := controlDoBody(t, srv, http.MethodPost, controlAllowlistPath, controlTestToken, []byte(raw), nil)
				if code != http.StatusBadRequest {
					t.Fatalf("POST %s = %d, want 400 (body %q)", raw, code, body)
				}
			})
		}
	})

	t.Run("nil_store_is_503", func(t *testing.T) {
		srv := controlServer(t, NewControlAPI(nil), controlTestToken)
		for _, tc := range []struct {
			method string
			body   []byte
		}{
			{method: http.MethodGet},
			{method: http.MethodPost, body: []byte(`{"entry":"x"}`)},
			{method: http.MethodDelete, body: []byte(`{"entry":"x"}`)},
		} {
			code, header, body := controlDoBody(t, srv, tc.method, controlAllowlistPath, controlTestToken, tc.body, nil)
			t.Logf("nil store %s /allowlist -> %d %s", tc.method, code, bytes.TrimSpace(body))
			if code != http.StatusServiceUnavailable {
				t.Fatalf("%s /allowlist with no store = %d, want 503 (body %q)", tc.method, code, body)
			}
			if ct := header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Errorf("%s nil-store Content-Type = %q, want JSON", tc.method, ct)
			}
			if got := controlDecodeJSON[controlErrorBody](t, body); got.Error == "" {
				t.Errorf("%s nil-store error body = %q, want non-empty", tc.method, body)
			}
		}
	})

	t.Run("method_mismatch_is_json_405_with_allow", func(t *testing.T) {
		store := newAllowlistTestStore(t)
		srv := controlServer(t, NewControlAPI(nil, WithControlAllowlist(store)), controlTestToken)
		code, header, body := controlDoBody(t, srv, http.MethodPut, controlAllowlistPath, controlTestToken,
			[]byte(`{"entry":"must.not.land"}`), nil)
		t.Logf("PUT /allowlist -> %d Allow=%q %s", code, header.Get("Allow"), bytes.TrimSpace(body))
		if code != http.StatusMethodNotAllowed {
			t.Fatalf("PUT /allowlist = %d, want 405 (body %q)", code, body)
		}
		if allow := header.Get("Allow"); allow == "" {
			t.Fatalf("PUT /allowlist Allow header empty, want the registered methods")
		}
		if ct := header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Fatalf("PUT 405 Content-Type = %q, want JSON", ct)
		}
		if got := controlDecodeJSON[controlErrorBody](t, body); got.Error == "" {
			t.Fatalf("405 body = %q, want JSON error", body)
		}
		if len(store.Entries()) != 0 {
			t.Fatalf("PUT mutated the store: %v", store.Entries())
		}
	})
}

// newAllowlistTestStore 构造一个真实的 W5.1 store（临时目录 + 给定种子）。
func newAllowlistTestStore(t *testing.T, seed ...string) *allowlist.Store {
	t.Helper()
	store, err := allowlist.Open(t.TempDir(), seed, io.Discard)
	if err != nil {
		t.Fatalf("allowlist.Open: %v", err)
	}
	return store
}

// allowlistStatusFunc 是生产接缝的本地镜像：调用方把 store 的条目数放进
// ControlStatus.Allowlist（ControlAPI 自己不读 store 来填 status）。
func allowlistStatusFunc(store *allowlist.Store) ControlStatusFunc {
	return func() ControlStatus {
		return ControlStatus{State: ControlStateRunning, Allowlist: len(store.Entries())}
	}
}

// controlDoBody 是 controlDo 的带请求体版本：body != nil 时设置 JSON
// Content-Type；bearer == "" 时不带 Authorization。
func controlDoBody(t *testing.T, srv *httptest.Server, method, path, bearer string, body []byte, mutate func(*http.Request)) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
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
