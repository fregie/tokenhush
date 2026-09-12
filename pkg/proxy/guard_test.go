package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// guardToken is an obviously fake bearer value used by the guard tests; it is
// never a real credential and never written to disk.
const guardToken = "unit-test-token-not-a-secret"

// guardOK is the terminal handler for guard tests: reaching it proves the
// wrapped middleware chain allowed the request through.
func guardOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "guard-ok")
	})
}

// startGuardServer starts an httptest server whose handler is built from the
// actual bound port, exactly as run does with Listeners.Port(). Using
// NewUnstartedServer keeps the middleware construction honest: the port baked
// into the allowlist is the port the client really dials, and no test ever
// binds the real default port 8787.
func startGuardServer(t *testing.T, build func(port int) http.Handler) (*httptest.Server, int) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	tcp, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("httptest listener addr = %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	port := tcp.Port
	srv.Config.Handler = build(port)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, port
}

// guardRoundTrip sends a GET to srv, optionally forging the Host header
// (host == "" keeps the natural dialed host) and mutating the request, and
// returns the status code and body.
func guardRoundTrip(t *testing.T, srv *httptest.Server, host string, mutate func(*http.Request)) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s (Host %q): %v", srv.URL, req.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// guardDirect invokes an already-built middleware chain without a socket, so
// malformed Host/Origin/Authorization shapes that an http.Client refuses to
// put on the wire can still be probed for safe rejection (no panic, no 200).
func guardDirect(t *testing.T, mw func(http.Handler) http.Handler, mutate func(*http.Request)) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	mw(guardOK()).ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// rawHTTPStatus writes a raw request to the server socket and returns the
// status of the first response. It is used for shapes an http.Client refuses
// to generate: duplicate, empty or missing Host headers.
func rawHTTPStatus(t *testing.T, srv *httptest.Server, raw string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write raw request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestHostAllowlist is the docs/security.md DNS-rebinding acceptance test: only
// the three loopback spellings bound by Listeners.Port() may pass; anything
// else is rejected with 403 before the wrapped handler runs.
func TestHostAllowlist(t *testing.T) {
	t.Run("allowed_loopback_hosts_pass", func(t *testing.T) {
		srv, port := startGuardServer(t, func(port int) http.Handler {
			return HostAllowlist(port)(guardOK())
		})
		for _, host := range []string{
			net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			net.JoinHostPort("localhost", strconv.Itoa(port)),
			net.JoinHostPort("LocalHost", strconv.Itoa(port)),
			net.JoinHostPort("LOCALHOST", strconv.Itoa(port)),
			net.JoinHostPort("::1", strconv.Itoa(port)),
		} {
			code, body := guardRoundTrip(t, srv, host, nil)
			if code != http.StatusOK {
				t.Errorf("Host %q: status = %d (body %q), want 200", host, code, body)
			}
		}
	})

	t.Run("foreign_and_dns_rebinding_hosts_forbidden", func(t *testing.T) {
		srv, port := startGuardServer(t, func(port int) http.Handler {
			return HostAllowlist(port)(guardOK())
		})
		portText := strconv.Itoa(port)
		for _, host := range []string{
			"evil.example.com:" + portText,
			"evil.example.com",
			"attacker.test:" + portText,
			"127.0.0.1.nip.io:" + portText,
			"localhost.evil.example.com:" + portText,
			"0.0.0.0:" + portText,
			"192.168.1.10:" + portText,
			"127.0.0.1:" + strconv.Itoa(port+1),
			"127.0.0.1:1",
			"127.0.0.1:" + portText + "0",
			"[::1]:" + strconv.Itoa(port+1),
			"127.0.0.1",
			"localhost",
			"localhost.",
			"[::1]",
		} {
			code, body := guardRoundTrip(t, srv, host, nil)
			if code != http.StatusForbidden {
				t.Errorf("Host %q: status = %d (body %q), want 403", host, code, body)
			}
		}
	})

	t.Run("malformed_hosts_rejected_without_panic", func(t *testing.T) {
		mw := HostAllowlist(8787)
		for _, host := range []string{
			"",
			" ",
			"127.0.0.1",
			"localhost",
			"[::1]",
			"127.0.0.1:",
			":8787",
			"127.0.0.1:8787:99",
			"127.0.0.1:08787",
			"127.0.0.1:+8787",
			"127.0.0.1: 8787",
			"127.0.0.1:8787 ",
			"http://127.0.0.1:8787",
			"localhost:8787,evil.example.com",
			"[::1%eth0]:8787",
			"[::1%25eth0]:8787",
			"ｌｏｃａｌｈｏｓｔ:8787",
			"127.0.0.1\x00:8787",
		} {
			code, body := guardDirect(t, mw, func(req *http.Request) { req.Host = host })
			if code != http.StatusForbidden {
				t.Errorf("malformed Host %q: status = %d (body %q), want 403", host, code, body)
			}
		}
	})

	t.Run("non_positive_port_fails_closed", func(t *testing.T) {
		for _, port := range []int{0, -1} {
			code, body := guardDirect(t, HostAllowlist(port), func(req *http.Request) {
				req.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			})
			if code != http.StatusForbidden {
				t.Errorf("HostAllowlist(%d): status = %d (body %q), want 403", port, code, body)
			}
		}
	})
}

// TestControlAuth locks the control-plane bearer requirements: missing,
// malformed or wrong credentials get 401, a valid bearer token passes, the
// token provider is consulted per request, and responses never echo a token.
func TestControlAuth(t *testing.T) {
	t.Run("over_the_wire", func(t *testing.T) {
		srv, _ := startGuardServer(t, func(int) http.Handler {
			return ControlAuth(func() string { return guardToken })(guardOK())
		})
		cases := []struct {
			name   string
			header []string
			want   int
		}{
			{name: "missing", header: nil, want: http.StatusUnauthorized},
			{name: "valid", header: []string{"Bearer " + guardToken}, want: http.StatusOK},
			{name: "lowercase_scheme", header: []string{"bearer " + guardToken}, want: http.StatusOK},
			{name: "uppercase_scheme", header: []string{"BEARER " + guardToken}, want: http.StatusOK},
			{name: "extra_spaces", header: []string{"Bearer   " + guardToken}, want: http.StatusOK},
			{name: "wrong_token", header: []string{"Bearer wrong-token"}, want: http.StatusUnauthorized},
			{name: "wrong_token_same_length", header: []string{"Bearer " + strings.Repeat("x", len(guardToken))}, want: http.StatusUnauthorized},
			{name: "scheme_only", header: []string{"Bearer"}, want: http.StatusUnauthorized},
			{name: "blank_credential", header: []string{"Bearer   "}, want: http.StatusUnauthorized},
			{name: "wrong_scheme", header: []string{"Basic " + guardToken}, want: http.StatusUnauthorized},
			{name: "no_scheme", header: []string{guardToken}, want: http.StatusUnauthorized},
			{name: "trailing_garbage", header: []string{"Bearer " + guardToken + " extra"}, want: http.StatusUnauthorized},
			{name: "empty_header", header: []string{""}, want: http.StatusUnauthorized},
			{name: "duplicate_headers_same", header: []string{"Bearer " + guardToken, "Bearer " + guardToken}, want: http.StatusUnauthorized},
			{name: "duplicate_headers_mixed", header: []string{"Bearer wrong", "Bearer " + guardToken}, want: http.StatusUnauthorized},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, body := guardRoundTrip(t, srv, "", func(req *http.Request) {
					for _, h := range tc.header {
						req.Header.Add("Authorization", h)
					}
				})
				if code != tc.want {
					t.Fatalf("status = %d (body %q), want %d", code, body, tc.want)
				}
				if strings.Contains(body, guardToken) {
					t.Fatalf("response leaked the token: %q", body)
				}
			})
		}
	})

	t.Run("unauthorized_carries_challenge", func(t *testing.T) {
		srv, _ := startGuardServer(t, func(int) http.Handler {
			return ControlAuth(func() string { return guardToken })(guardOK())
		})
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if got, want := resp.Header.Get("WWW-Authenticate"), `Bearer realm="tokenhush"`; got != want {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
		}
	})

	t.Run("empty_provider_fails_closed", func(t *testing.T) {
		for name, provider := range map[string]TokenSource{
			"nil_provider":   nil,
			"empty_provider": func() string { return "" },
		} {
			code, body := guardDirect(t, ControlAuth(provider), func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+guardToken)
			})
			if code != http.StatusUnauthorized {
				t.Errorf("%s: status = %d (body %q), want 401", name, code, body)
			}
		}
	})

	t.Run("provider_consulted_per_request", func(t *testing.T) {
		current := guardToken
		mw := ControlAuth(func() string { return current })
		authAs := func(tok string) func(*http.Request) {
			return func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+tok) }
		}
		if code, _ := guardDirect(t, mw, authAs(guardToken)); code != http.StatusOK {
			t.Fatalf("first session token: status = %d, want 200", code)
		}
		current = "rotated-session-token"
		if code, _ := guardDirect(t, mw, authAs(guardToken)); code != http.StatusUnauthorized {
			t.Fatalf("stale token after rotation: status = %d, want 401", code)
		}
		if code, _ := guardDirect(t, mw, authAs(current)); code != http.StatusOK {
			t.Fatalf("rotated token: status = %d, want 200", code)
		}
	})

	t.Run("malformed_authorization_headers_fail_safely", func(t *testing.T) {
		mw := ControlAuth(func() string { return guardToken })
		for _, header := range [][]string{
			{"Bearer"},
			{"Bearer "},
			{"Bearer   "},
			{"Bearer\t" + guardToken},
			{"Bearer " + guardToken + "\nextra"},
			{"Bearer " + guardToken + "  extra"},
			{"basic " + guardToken},
			{" "},
			{"Bearer " + guardToken, "garbage"},
		} {
			code, body := guardDirect(t, mw, func(req *http.Request) {
				for _, h := range header {
					req.Header.Add("Authorization", h)
				}
			})
			if code != http.StatusUnauthorized {
				t.Errorf("Authorization %q: status = %d (body %q), want 401", header, code, body)
			}
			if strings.Contains(body, guardToken) {
				t.Errorf("Authorization %q: response leaked the token", header)
			}
		}
	})
}

// TestOriginPolicy locks the control-plane browser policy: same-origin is the
// only accepted web origin, Sec-Fetch-Site must be same-origin or a direct
// user navigation, and CLI/curl requests with no Origin are left to the
// bearer-token guard.
func TestOriginPolicy(t *testing.T) {
	srv, port := startGuardServer(t, func(int) http.Handler {
		return OriginPolicy(ControlAuth(func() string { return guardToken })(guardOK()))
	})
	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	sameOrigin := "http://" + host
	localOrigin := "http://" + net.JoinHostPort("localhost", strconv.Itoa(port))

	cases := []struct {
		name       string
		forgedHost string
		origin     string
		fetchSite  string
		auth       string
		want       int
	}{
		{name: "no_origin_with_valid_token", want: http.StatusOK, auth: "Bearer " + guardToken},
		{name: "no_origin_without_token", want: http.StatusUnauthorized},
		{name: "no_origin_with_wrong_token", want: http.StatusUnauthorized, auth: "Bearer wrong-token"},
		{name: "same_origin_with_valid_token", want: http.StatusOK, origin: sameOrigin, auth: "Bearer " + guardToken},
		{name: "same_origin_without_token", want: http.StatusUnauthorized, origin: sameOrigin},
		{
			name:       "localhost_origin_with_localhost_host",
			forgedHost: net.JoinHostPort("localhost", strconv.Itoa(port)),
			origin:     localOrigin,
			auth:       "Bearer " + guardToken,
			want:       http.StatusOK,
		},
		{
			name:   "localhost_origin_with_ip_host_is_cross_origin",
			origin: localOrigin,
			auth:   "Bearer " + guardToken,
			want:   http.StatusForbidden,
		},
		{name: "cross_site_origin", origin: "http://evil.example.com", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "cross_site_origin_without_token", origin: "http://evil.example.com", want: http.StatusForbidden},
		{name: "other_loopback_port", origin: "http://127.0.0.1:" + strconv.Itoa(port+1), auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "https_scheme_mismatch", origin: "https://" + host, auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "null_origin", origin: "null", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "malformed_origin", origin: "://", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "origin_with_path", origin: sameOrigin + "/evil", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "origin_with_userinfo", origin: "http://user@127.0.0.1:" + strconv.Itoa(port), auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "origin_with_query", origin: sameOrigin + "?x=1", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "cross_site_fetch_site", fetchSite: "cross-site", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "same_site_fetch_site", fetchSite: "same-site", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "uppercase_cross_site_fetch_site", fetchSite: "Cross-Site", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "unknown_fetch_site", fetchSite: "banana", auth: "Bearer " + guardToken, want: http.StatusForbidden},
		{name: "same_origin_fetch_site", fetchSite: "same-origin", auth: "Bearer " + guardToken, want: http.StatusOK},
		{name: "none_fetch_site_direct_navigation", fetchSite: "none", auth: "Bearer " + guardToken, want: http.StatusOK},
		{name: "cross_site_origin_and_fetch_site", origin: "http://evil.example.com", fetchSite: "cross-site", auth: "Bearer " + guardToken, want: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := guardRoundTrip(t, srv, tc.forgedHost, func(req *http.Request) {
				if tc.origin != "" {
					req.Header.Set("Origin", tc.origin)
				}
				if tc.fetchSite != "" {
					req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
				}
				if tc.auth != "" {
					req.Header.Set("Authorization", tc.auth)
				}
			})
			if code != tc.want {
				t.Fatalf("status = %d (body %q), want %d", code, body, tc.want)
			}
			if strings.Contains(body, guardToken) {
				t.Fatalf("response leaked the token: %q", body)
			}
		})
	}

	t.Run("duplicate_browser_headers_fail_closed", func(t *testing.T) {
		mw := func(next http.Handler) http.Handler {
			return OriginPolicy(ControlAuth(func() string { return guardToken })(next))
		}
		for _, header := range []string{"Origin", "Sec-Fetch-Site"} {
			code, body := guardDirect(t, mw, func(req *http.Request) {
				req.Header.Add("Authorization", "Bearer "+guardToken)
				req.Header.Add(header, "http://127.0.0.1")
				req.Header.Add(header, "http://evil.example.com")
			})
			if code != http.StatusForbidden {
				t.Errorf("duplicate %s: status = %d (body %q), want 403", header, code, body)
			}
		}
	})

	t.Run("composed_chain", func(t *testing.T) {
		srv, port := startGuardServer(t, func(port int) http.Handler {
			return HostAllowlist(port)(OriginPolicy(ControlAuth(func() string { return guardToken })(guardOK())))
		})
		host := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		cases := []struct {
			name   string
			host   string
			origin string
			auth   string
			want   int
		}{
			{name: "foreign_host_wins_even_with_valid_token", host: "evil.example.com:" + strconv.Itoa(port), auth: "Bearer " + guardToken, want: http.StatusForbidden},
			{name: "cross_site_origin_rejected", origin: "http://evil.example.com", auth: "Bearer " + guardToken, want: http.StatusForbidden},
			{name: "cli_with_valid_token", auth: "Bearer " + guardToken, want: http.StatusOK},
			{name: "allowed_host_bad_token", host: host, auth: "Bearer nope", want: http.StatusUnauthorized},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, body := guardRoundTrip(t, srv, tc.host, func(req *http.Request) {
					if tc.origin != "" {
						req.Header.Set("Origin", tc.origin)
					}
					if tc.auth != "" {
						req.Header.Set("Authorization", tc.auth)
					}
				})
				if code != tc.want {
					t.Fatalf("status = %d (body %q), want %d", code, body, tc.want)
				}
			})
		}
	})
}

// TestGuardMalformedInput is the adversarial pass: hostile or malformed HTTP
// shapes must end in a safe 4xx rejection, never a panic and never a 200.
func TestGuardMalformedInput(t *testing.T) {
	t.Run("raw_host_headers_rejected_at_the_server_edge", func(t *testing.T) {
		srv, port := startGuardServer(t, func(port int) http.Handler {
			return HostAllowlist(port)(guardOK())
		})
		allowed := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		raws := []struct {
			name string
			raw  string
		}{
			{
				name: "duplicate_host_headers",
				raw:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nHost: evil.example.com\r\nConnection: close\r\n\r\n", allowed),
			},
			{name: "empty_host", raw: "GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n"},
			{name: "missing_host", raw: "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"},
			{
				name: "space_in_host",
				raw:  fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s evil\r\nConnection: close\r\n\r\n", allowed),
			},
			{
				name: "absolute_form_foreign_authority",
				raw:  fmt.Sprintf("GET http://evil.example.com/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", allowed),
			},
		}
		for _, tc := range raws {
			t.Run(tc.name, func(t *testing.T) {
				code := rawHTTPStatus(t, srv, tc.raw)
				t.Logf("raw %s -> status %d", tc.name, code)
				if code < 400 || code >= 500 {
					t.Fatalf("status = %d, want a 4xx safe rejection (never 200)", code)
				}
			})
		}
	})
}

// TestControlTokenLifecycle locks generation, persistence, regeneration per
// run and the error contract of <dataDir>/control.token held behind an
// injectable data dir so tests never touch the real platform data directory.
func TestControlTokenLifecycle(t *testing.T) {
	dir := t.TempDir()

	t.Run("generate_is_random_url_safe_and_wide_enough", func(t *testing.T) {
		first, err := GenerateControlToken()
		if err != nil {
			t.Fatalf("GenerateControlToken: %v", err)
		}
		second, err := GenerateControlToken()
		if err != nil {
			t.Fatalf("GenerateControlToken: %v", err)
		}
		if first == second {
			t.Fatal("two generated tokens are identical")
		}
		const urlSafeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		for name, tok := range map[string]string{"first": first, "second": second} {
			raw, err := base64.RawURLEncoding.DecodeString(tok)
			if err != nil {
				t.Fatalf("%s token %q is not Raw URL-safe base64: %v", name, tok, err)
			}
			if len(raw) != tokenBytes {
				t.Fatalf("%s token entropy = %d bytes, want %d", name, len(raw), tokenBytes)
			}
			if len(raw)*8 < 128 {
				t.Fatalf("%s token entropy = %d bits, want >= 128", name, len(raw)*8)
			}
			for _, r := range tok {
				if !strings.ContainsRune(urlSafeAlphabet, r) {
					t.Fatalf("%s token contains %q, outside the URL-safe alphabet", name, r)
				}
			}
		}
	})

	t.Run("write_read_round_trip_and_regeneration", func(t *testing.T) {
		tok1, err := GenerateControlToken()
		if err != nil {
			t.Fatalf("GenerateControlToken: %v", err)
		}
		path, err := WriteControlToken(dir, tok1)
		if err != nil {
			t.Fatalf("WriteControlToken: %v", err)
		}
		if want := filepath.Join(dir, ControlTokenFileName); path != want {
			t.Fatalf("path = %q, want %q", path, want)
		}
		got, err := ReadControlToken(dir)
		if err != nil {
			t.Fatalf("ReadControlToken: %v", err)
		}
		if got != tok1 {
			t.Fatal("read token differs from the written token")
		}

		// Regenerate per run: a second write replaces the first token.
		tok2, err := GenerateControlToken()
		if err != nil {
			t.Fatalf("GenerateControlToken: %v", err)
		}
		if _, err := WriteControlToken(dir, tok2); err != nil {
			t.Fatalf("WriteControlToken(second): %v", err)
		}
		got2, err := ReadControlToken(dir)
		if err != nil {
			t.Fatalf("ReadControlToken(second): %v", err)
		}
		if got2 != tok2 || got2 == tok1 {
			t.Fatal("second write did not replace the first token")
		}

		// NewControlToken generates and persists in one step.
		tok3, path3, err := NewControlToken(dir)
		if err != nil {
			t.Fatalf("NewControlToken: %v", err)
		}
		if path3 != path {
			t.Fatalf("NewControlToken path = %q, want %q", path3, path)
		}
		got3, err := ReadControlToken(dir)
		if err != nil {
			t.Fatalf("ReadControlToken(third): %v", err)
		}
		if got3 != tok3 || got3 == tok2 {
			t.Fatal("NewControlToken did not persist a fresh token")
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		if len(entries) != 1 || entries[0].Name() != ControlTokenFileName {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("data dir entries = %v, want exactly %s (no temp leftovers)", names, ControlTokenFileName)
		}
	})

	t.Run("missing_and_empty_token_files", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent")
		if _, err := ReadControlToken(missing); !errors.Is(err, ErrNoControlToken) {
			t.Fatalf("ReadControlToken(missing) error = %v, want ErrNoControlToken", err)
		}

		emptyDir := t.TempDir()
		emptyPath := filepath.Join(emptyDir, ControlTokenFileName)
		if err := os.WriteFile(emptyPath, []byte(" \n\t"), 0o600); err != nil {
			t.Fatalf("write empty token file: %v", err)
		}
		if _, err := ReadControlToken(emptyDir); !errors.Is(err, ErrNoControlToken) {
			t.Fatalf("ReadControlToken(empty) error = %v, want ErrNoControlToken", err)
		}
	})

	t.Run("rejects_empty_token_and_empty_dir", func(t *testing.T) {
		for _, tok := range []string{"", " ", "\n"} {
			if _, err := WriteControlToken(dir, tok); !errors.Is(err, ErrEmptyControlToken) {
				t.Errorf("WriteControlToken(%q) error = %v, want ErrEmptyControlToken", tok, err)
			}
		}
		if _, err := WriteControlToken("", "some-token"); err == nil {
			t.Error("WriteControlToken with an empty data dir succeeded, want error")
		}
	})
}

// TestControlHandshakeURL locks the minimal browser handshake: the token
// travels in the URL fragment of a loopback URL, so it is never sent to the
// server (no request line, no Referer) and the control UI can consume and
// clear it on first load (full UI is W9.1).
func TestControlHandshakeURL(t *testing.T) {
	tok, err := GenerateControlToken()
	if err != nil {
		t.Fatalf("GenerateControlToken: %v", err)
	}
	const port = 45678
	raw := ControlHandshakeURL(port, tok)
	if raw == "" {
		t.Fatal("ControlHandshakeURL returned an empty URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("handshake URL %q does not parse: %v", raw, err)
	}
	if u.Scheme != "http" {
		t.Errorf("scheme = %q, want http", u.Scheme)
	}
	if want := net.JoinHostPort("127.0.0.1", strconv.Itoa(port)); u.Host != want {
		t.Errorf("host = %q, want %q", u.Host, want)
	}
	if u.Path != "/" {
		t.Errorf("path = %q, want /", u.Path)
	}
	if want := "token=" + tok; u.Fragment != want {
		t.Errorf("fragment = %q, want %q", u.Fragment, want)
	}
	if u.RawQuery != "" {
		t.Errorf("query = %q, want none", u.RawQuery)
	}
	if got := u.RequestURI(); got != "/" {
		t.Errorf("RequestURI = %q, want / (the fragment must never reach the server)", got)
	}

	for name, invalid := range map[string]string{
		"zero_port":   ControlHandshakeURL(0, tok),
		"high_port":   ControlHandshakeURL(70000, tok),
		"empty_token": ControlHandshakeURL(port, ""),
	} {
		if invalid != "" {
			t.Errorf("ControlHandshakeURL(%s) = %q, want empty", name, invalid)
		}
	}
}
