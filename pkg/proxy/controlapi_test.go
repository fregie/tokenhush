package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/audit"
)

// controlTestToken is an obviously fake bearer value used by the control-API
// tests; it is never a real credential and never written to disk.
const controlTestToken = "control-api-unit-token-not-a-secret"

// controlQuerierFunc adapts a function to audit.AuditQuerier so tests can
// capture the exact query the handler forwards to the injected seam.
type controlQuerierFunc func(context.Context, audit.Query) ([]audit.Record, error)

func (f controlQuerierFunc) Query(ctx context.Context, q audit.Query) ([]audit.Record, error) {
	return f(ctx, q)
}

// controlServer wraps api in the documented production chain —
// HostAllowlist(port)(OriginPolicy(ControlAuth(token)(api))) — and serves it on
// a real loopback port, so every test exercises the same composition W4.7 uses.
func controlServer(t *testing.T, api http.Handler, token string) *httptest.Server {
	t.Helper()
	srv, _ := startGuardServer(t, func(port int) http.Handler {
		return HostAllowlist(port)(OriginPolicy(ControlAuth(func() string { return token })(api)))
	})
	return srv
}

// controlDo performs one HTTP request against srv and returns status, headers
// and body. bearer=="" omits the Authorization header; mutate can forge
// headers or the Host, which http.Client otherwise derives from the URL.
func controlDo(t *testing.T, srv *httptest.Server, method, path, bearer string, mutate func(*http.Request)) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header, body
}

// controlDecodeJSON decodes a control-API body, failing the test on malformed
// JSON so a bare status code can never stand in for the wire contract.
func controlDecodeJSON[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("body is not JSON (%v): %q", err, body)
	}
	return v
}

// controlErrorBody mirrors the wire shape of every control-API error response.
type controlErrorBody struct {
	Error string `json:"error"`
}

// TestControlAPI is the W3.6 acceptance test: behind the full Host → Origin →
// ControlAuth chain, GET /status returns the live metadata snapshot as JSON and
// GET /audit returns the injected querier's rows as a JSON array.
func TestControlAPI(t *testing.T) {
	requests := uint64(3)
	statusCalls := 0
	statusFn := func() ControlStatus {
		statusCalls++
		return ControlStatus{
			State:      ControlStateRunning,
			Addrs:      []string{"127.0.0.1:8787", "[::1]:8787"},
			UptimeMS:   4200,
			Requests:   requests,
			Redactions: 4,
		}
	}

	records := []audit.Record{{
		ID:         7,
		TS:         1_700_000_000_000,
		Provider:   "anthropic",
		Path:       "/v1/messages",
		Method:     http.MethodPost,
		Status:     http.StatusOK,
		ReqBytes:   128,
		RespBytes:  256,
		Redactions: 2,
		Detectors:  []string{"prefix"},
		Client:     "claude-code",
	}}
	var queries []audit.Query
	querier := controlQuerierFunc(func(_ context.Context, q audit.Query) ([]audit.Record, error) {
		queries = append(queries, q)
		return records, nil
	})

	srv := controlServer(t, NewControlAPI(statusFn, querier), controlTestToken)

	t.Run("status returns the live metadata snapshot", func(t *testing.T) {
		code, header, body := controlDo(t, srv, http.MethodGet, "/status", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /status = %d, want %d (body %q)", code, http.StatusOK, body)
		}
		t.Logf("GET /status -> %d %s", code, strings.TrimSpace(string(body)))
		if ct := header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", ct)
		}
		got := controlDecodeJSON[ControlStatus](t, body)
		if got.State != ControlStateRunning {
			t.Errorf("state = %q, want %q", got.State, ControlStateRunning)
		}
		if want := []string{"127.0.0.1:8787", "[::1]:8787"}; !reflect.DeepEqual(got.Addrs, want) {
			t.Errorf("addrs = %v, want %v", got.Addrs, want)
		}
		if got.UptimeMS != 4200 {
			t.Errorf("uptime_ms = %d, want 4200", got.UptimeMS)
		}
		if got.Requests != 3 || got.Redactions != 4 {
			t.Errorf("requests/redactions = %d/%d, want 3/4", got.Requests, got.Redactions)
		}
		if statusCalls == 0 {
			t.Fatal("status snapshot func was never called")
		}

		// The snapshot is pulled per request: counters that move between calls
		// are reflected without rebuilding the handler.
		requests = 12
		code, _, body = controlDo(t, srv, http.MethodGet, "/status", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("second GET /status = %d, want %d", code, http.StatusOK)
		}
		if got := controlDecodeJSON[ControlStatus](t, body); got.Requests != 12 {
			t.Errorf("second snapshot requests = %d, want 12 (stale snapshot?)", got.Requests)
		}
		requests = 3
	})

	t.Run("audit returns the injected querier rows as a JSON array", func(t *testing.T) {
		before := len(queries)
		code, header, body := controlDo(t, srv, http.MethodGet, "/audit", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /audit = %d, want %d (body %q)", code, http.StatusOK, body)
		}
		t.Logf("GET /audit -> %d %s", code, strings.TrimSpace(string(body)))
		if ct := header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", ct)
		}
		got := controlDecodeJSON[[]audit.Record](t, body)
		if !reflect.DeepEqual(got, records) {
			t.Fatalf("GET /audit rows = %+v, want %+v", got, records)
		}
		if len(queries) != before+1 {
			t.Fatalf("querier calls = %d, want %d (injected querier must be used)", len(queries), before+1)
		}
		q := queries[len(queries)-1]
		if !q.Since.IsZero() || !q.Until.IsZero() || q.Provider != "" || q.Limit != 0 {
			t.Fatalf("no-param query = %+v, want zero value", q)
		}
	})

	t.Run("audit maps and clamps query parameters", func(t *testing.T) {
		before := len(queries)
		code, _, body := controlDo(t, srv, http.MethodGet,
			"/audit?since=1700000000000&until=1700000001000&provider=anthropic&limit=5",
			controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /audit with params = %d, want 200 (body %q)", code, body)
		}
		if len(queries) != before+1 {
			t.Fatalf("querier calls = %d, want %d", len(queries), before+1)
		}
		q := queries[len(queries)-1]
		if got := q.Since.UnixMilli(); got != 1700000000000 {
			t.Errorf("since = %d, want 1700000000000", got)
		}
		if got := q.Until.UnixMilli(); got != 1700000001000 {
			t.Errorf("until = %d, want 1700000001000", got)
		}
		if q.Provider != "anthropic" {
			t.Errorf("provider = %q, want anthropic", q.Provider)
		}
		if q.Limit != 5 {
			t.Errorf("limit = %d, want 5", q.Limit)
		}

		// A huge limit is clamped to the exported maximum, never passed through.
		code, _, body = controlDo(t, srv, http.MethodGet, "/audit?limit=100000000", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /audit?limit=100000000 = %d, want 200 (body %q)", code, body)
		}
		if got := queries[len(queries)-1].Limit; got != MaxControlAuditLimit {
			t.Errorf("huge limit = %d, want clamp to %d", got, MaxControlAuditLimit)
		}

		// limit=0 means "leave it to the querier", which the zero Value encodes.
		code, _, body = controlDo(t, srv, http.MethodGet, "/audit?limit=0", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /audit?limit=0 = %d, want 200 (body %q)", code, body)
		}
		if got := queries[len(queries)-1].Limit; got != 0 {
			t.Errorf("limit=0 mapped to %d, want 0", got)
		}
	})

	t.Run("audit rejects malformed parameters with 400", func(t *testing.T) {
		before := len(queries)
		paths := []string{
			"/audit?limit=abc",
			"/audit?limit=-1",
			"/audit?limit=5.5",
			"/audit?since=abc",
			"/audit?until=99999999999999999999999999",
			"/audit?since=2000&until=1000",
			"/audit?limit=1&limit=2",
			"/audit?provider=a&provider=b",
		}
		for _, path := range paths {
			code, header, body := controlDo(t, srv, http.MethodGet, path, controlTestToken, nil)
			if code != http.StatusBadRequest {
				t.Errorf("GET %s = %d, want 400 (body %q)", path, code, body)
				continue
			}
			if ct := header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Errorf("GET %s Content-Type = %q, want JSON", path, ct)
			}
			if e := controlDecodeJSON[controlErrorBody](t, body); e.Error == "" {
				t.Errorf("GET %s error body = %q, want non-empty error", path, body)
			}
		}
		if len(queries) != before {
			t.Fatalf("querier called %d time(s) for malformed input, want 0", len(queries)-before)
		}
	})

	t.Run("unknown query parameters are ignored", func(t *testing.T) {
		before := len(queries)
		code, _, body := controlDo(t, srv, http.MethodGet, "/audit?bogus=1", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /audit?bogus=1 = %d, want 200 (body %q)", code, body)
		}
		q := queries[len(queries)-1]
		if !q.Since.IsZero() || !q.Until.IsZero() || q.Provider != "" || q.Limit != 0 {
			t.Fatalf("unknown-param query = %+v, want zero value", q)
		}
		if len(queries) != before+1 {
			t.Fatalf("querier calls = %d, want %d", len(queries), before+1)
		}
	})

	t.Run("nil seams default to running state and the noop querier", func(t *testing.T) {
		defaultSrv := controlServer(t, NewControlAPI(nil, nil), controlTestToken)
		code, _, body := controlDo(t, defaultSrv, http.MethodGet, "/status", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("default GET /status = %d, want 200 (body %q)", code, body)
		}
		got := controlDecodeJSON[ControlStatus](t, body)
		if got.State != ControlStateRunning {
			t.Errorf("default state = %q, want %q", got.State, ControlStateRunning)
		}
		if got.Addrs == nil {
			t.Error("default addrs decoded as nil, want empty slice (JSON [])")
		}
		if raw := string(body); !strings.Contains(raw, `"addrs":[]`) {
			t.Errorf("default /status body = %q, want addrs serialized as []", raw)
		}

		code, _, body = controlDo(t, defaultSrv, http.MethodGet, "/audit", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("default GET /audit = %d, want 200 (body %q)", code, body)
		}
		if raw := strings.TrimSpace(string(body)); raw != "[]" {
			t.Fatalf("default /audit body = %q, want [] (noop querier, not null)", raw)
		}
		if got := controlDecodeJSON[[]audit.Record](t, body); len(got) != 0 {
			t.Fatalf("default /audit rows = %v, want empty", got)
		}
	})

	t.Run("empty state and nil records are normalized", func(t *testing.T) {
		normalized := controlServer(t, NewControlAPI(func() ControlStatus { return ControlStatus{} },
			controlQuerierFunc(func(context.Context, audit.Query) ([]audit.Record, error) {
				return nil, nil
			})), controlTestToken)
		code, _, body := controlDo(t, normalized, http.MethodGet, "/status", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /status = %d, want 200 (body %q)", code, body)
		}
		if got := controlDecodeJSON[ControlStatus](t, body); got.State != ControlStateRunning {
			t.Errorf("normalized state = %q, want %q", got.State, ControlStateRunning)
		}
		code, _, body = controlDo(t, normalized, http.MethodGet, "/audit", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /audit = %d, want 200 (body %q)", code, body)
		}
		if raw := strings.TrimSpace(string(body)); raw != "[]" {
			t.Fatalf("nil records body = %q, want []", raw)
		}
	})

	t.Run("querier errors surface as 500 without leaking the cause", func(t *testing.T) {
		boom := controlQuerierFunc(func(context.Context, audit.Query) ([]audit.Record, error) {
			return nil, errors.New("sqlite: open /secret/path/audit.db: permission denied")
		})
		errSrv := controlServer(t, NewControlAPI(nil, boom), controlTestToken)
		code, header, body := controlDo(t, errSrv, http.MethodGet, "/audit", controlTestToken, nil)
		if code != http.StatusInternalServerError {
			t.Fatalf("GET /audit with failing querier = %d, want 500 (body %q)", code, body)
		}
		if ct := header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q, want JSON", ct)
		}
		if raw := string(body); strings.Contains(raw, "sqlite") || strings.Contains(raw, "secret") {
			t.Fatalf("error body leaked the underlying cause: %q", raw)
		}
		if e := controlDecodeJSON[controlErrorBody](t, body); e.Error != "audit query failed" {
			t.Fatalf("error body = %q, want audit query failed", body)
		}
	})
}

// TestControlAPIUnauthorized locks the 401 behavior of the composed chain: a
// missing, malformed or wrong bearer token never reaches the control handlers
// and the rejection body never echoes the token or any metadata.
func TestControlAPIUnauthorized(t *testing.T) {
	srv := controlServer(t, NewControlAPI(nil, nil), controlTestToken)

	cases := []struct {
		name   string
		bearer string
		mutate func(*http.Request)
	}{
		{name: "missing"},
		{name: "wrong", bearer: "wrong-" + controlTestToken},
		{name: "truncated", bearer: controlTestToken[:8]},
		{name: "blank credential", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }},
		{name: "wrong scheme", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Basic "+controlTestToken) }},
		{name: "duplicate headers", mutate: func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer "+controlTestToken)
			r.Header.Add("Authorization", "Bearer "+controlTestToken)
		}},
	}

	for _, tc := range cases {
		for _, path := range []string{"/status", "/audit"} {
			t.Run(tc.name+" "+path, func(t *testing.T) {
				code, header, body := controlDo(t, srv, http.MethodGet, path, tc.bearer, tc.mutate)
				if code != http.StatusUnauthorized {
					t.Fatalf("GET %s = %d, want 401 (body %q)", path, code, body)
				}
				if got := header.Get("WWW-Authenticate"); got != `Bearer realm="tokenhush"` {
					t.Errorf("WWW-Authenticate = %q, want bearer challenge", got)
				}
				raw := string(body)
				if strings.Contains(raw, controlTestToken) {
					t.Fatalf("401 body echoed the valid token: %q", raw)
				}
				for _, meta := range []string{"state", "addrs", "uptime_ms", "requests", "redactions", "id", "provider"} {
					if strings.Contains(raw, meta) {
						t.Fatalf("401 body leaked control metadata %q: %q", meta, raw)
					}
				}
				if strings.Contains(raw, "<") {
					t.Fatalf("401 body looks like HTML: %q", raw)
				}
				t.Logf("GET %s (case %q) -> %d %q", path, tc.name, code, strings.TrimSpace(raw))
			})
		}
	}
}

// TestControlAPIRouting locks method and path behavior: ServeMux method
// patterns produce 405 (with Allow) for a known path with the wrong method and
// every unknown path is a JSON 404 — never an HTML redirect or text body.
func TestControlAPIRouting(t *testing.T) {
	srv := controlServer(t, NewControlAPI(nil, nil), controlTestToken)

	cases := []struct {
		name      string
		method    string
		path      string
		bearer    string
		want      int
		wantAllow string
	}{
		{name: "post status", method: http.MethodPost, path: "/status", bearer: controlTestToken, want: http.StatusMethodNotAllowed, wantAllow: http.MethodGet},
		{name: "put audit", method: http.MethodPut, path: "/audit", bearer: controlTestToken, want: http.StatusMethodNotAllowed, wantAllow: http.MethodGet},
		{name: "delete status", method: http.MethodDelete, path: "/status", bearer: controlTestToken, want: http.StatusMethodNotAllowed, wantAllow: http.MethodGet},
		{name: "unknown path", method: http.MethodGet, path: "/nope", bearer: controlTestToken, want: http.StatusNotFound},
		{name: "unknown path post", method: http.MethodPost, path: "/nope", bearer: controlTestToken, want: http.StatusNotFound},
		{name: "trailing slash", method: http.MethodGet, path: "/status/", bearer: controlTestToken, want: http.StatusNotFound},
		{name: "double slash", method: http.MethodGet, path: "//status", bearer: controlTestToken, want: http.StatusNotFound},
		{name: "unknown path still authenticated", method: http.MethodGet, path: "/nope", want: http.StatusUnauthorized},
		{name: "status ignores query", method: http.MethodGet, path: "/status?verbose=1", bearer: controlTestToken, want: http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, header, body := controlDo(t, srv, tc.method, tc.path, tc.bearer, nil)
			if code != tc.want {
				t.Fatalf("%s %s = %d, want %d (body %q)", tc.method, tc.path, code, tc.want, body)
			}
			if tc.wantAllow != "" {
				if got := header.Get("Allow"); !strings.Contains(got, tc.wantAllow) {
					t.Errorf("Allow = %q, want it to contain %q", got, tc.wantAllow)
				}
			}
			switch tc.want {
			case http.StatusNotFound, http.StatusMethodNotAllowed:
				if ct := header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
					t.Errorf("Content-Type = %q, want JSON", ct)
				}
				e := controlDecodeJSON[controlErrorBody](t, body)
				if e.Error == "" {
					t.Errorf("error body = %q, want non-empty error", body)
				}
				if strings.Contains(string(body), "<") {
					t.Errorf("error body looks like HTML: %q", body)
				}
			}
		})
	}
}

// TestControlAPIChain locks the documented guard order:
// HostAllowlist → OriginPolicy → ControlAuth → ControlAPI. A rebinding Host is
// rejected before auth, a cross-site Origin before token validation, and a
// same-origin request with a valid token passes.
func TestControlAPIChain(t *testing.T) {
	srv := controlServer(t, NewControlAPI(nil, nil), controlTestToken)

	t.Run("foreign host is rejected before authentication", func(t *testing.T) {
		code, _, _ := controlDo(t, srv, http.MethodGet, "/status", controlTestToken, func(r *http.Request) {
			r.Host = "evil.example:8787"
		})
		if code != http.StatusForbidden {
			t.Fatalf("forged Host = %d, want 403", code)
		}
	})

	t.Run("cross-site origin is rejected before token validation", func(t *testing.T) {
		code, _, _ := controlDo(t, srv, http.MethodGet, "/status", "wrong-token", func(r *http.Request) {
			r.Header.Set("Origin", "http://evil.example")
		})
		if code != http.StatusForbidden {
			t.Fatalf("cross-site Origin = %d, want 403", code)
		}
	})

	t.Run("same-origin origin with a valid token passes", func(t *testing.T) {
		code, _, body := controlDo(t, srv, http.MethodGet, "/status", controlTestToken, func(r *http.Request) {
			r.Header.Set("Origin", srv.URL)
		})
		if code != http.StatusOK {
			t.Fatalf("same-origin request = %d, want 200 (body %q)", code, body)
		}
		_ = controlDecodeJSON[ControlStatus](t, body)
	})
}
