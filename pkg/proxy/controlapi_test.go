package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// controlTestToken is an obviously fake bearer value used by the control-API
// tests; it is never a real credential and never written to disk.
const controlTestToken = "control-api-unit-token-not-a-secret"

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
// ControlAuth chain, GET /status returns the live metadata snapshot as JSON.
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

	srv := controlServer(t, NewControlAPI(statusFn), controlTestToken)

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

	t.Run("nil status defaults to running state", func(t *testing.T) {
		defaultSrv := controlServer(t, NewControlAPI(nil), controlTestToken)
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
	})

	t.Run("empty state is normalized", func(t *testing.T) {
		normalized := controlServer(t, NewControlAPI(func() ControlStatus { return ControlStatus{} }), controlTestToken)
		code, _, body := controlDo(t, normalized, http.MethodGet, "/status", controlTestToken, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /status = %d, want 200 (body %q)", code, body)
		}
		if got := controlDecodeJSON[ControlStatus](t, body); got.State != ControlStateRunning {
			t.Errorf("normalized state = %q, want %q", got.State, ControlStateRunning)
		}
	})
}

// TestControlAPIUnauthorized locks the 401 behavior of the composed chain: a
// missing, malformed or wrong bearer token never reaches the control handlers
// and the rejection body never echoes the token or any metadata.
func TestControlAPIUnauthorized(t *testing.T) {
	srv := controlServer(t, NewControlAPI(nil), controlTestToken)

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
		for _, path := range []string{"/status"} {
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
	srv := controlServer(t, NewControlAPI(nil), controlTestToken)

	cases := []struct {
		name      string
		method    string
		path      string
		bearer    string
		want      int
		wantAllow string
	}{
		{name: "post status", method: http.MethodPost, path: "/status", bearer: controlTestToken, want: http.StatusMethodNotAllowed, wantAllow: http.MethodGet},
		{name: "put audit", method: http.MethodPut, path: "/audit", bearer: controlTestToken, want: http.StatusNotFound},
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
	srv := controlServer(t, NewControlAPI(nil), controlTestToken)

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
