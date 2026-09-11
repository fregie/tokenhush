package proxy

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Middleware wraps an http.Handler with a cross-cutting guard. Guards compose
// by nesting, outermost first:
//
//	handler := HostAllowlist(port)(OriginPolicy(ControlAuth(token)(mux)))
//
// HostAllowlist runs first so a DNS-rebinding request is rejected before any
// control-plane authentication is attempted.
type Middleware func(http.Handler) http.Handler

// HostAllowlist returns middleware that rejects every request whose Host
// header is not exactly one of the loopback spellings bound by
// Listeners.Port(): "127.0.0.1:PORT", "localhost:PORT" (case-insensitive) or
// "[::1]:PORT". Foreign hosts, DNS-rebinding style names, malformed
// authorities and Host-less requests get 403 before next runs (docs/13 §3.4).
//
// port must be the port the listeners actually bound (Listeners.Port()), not
// the configured port, which may have been 0. A non-positive port makes the
// guard fail closed: every request is rejected.
func HostAllowlist(port int) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowedHost(r.Host, port) {
				deny(w, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// allowedHost reports whether host is one of the three loopback spellings at
// exactly the bound port. The port is compared as its canonical decimal text,
// so alternate spellings ("08787", "+8787") are rejected rather than coerced.
func allowedHost(host string, port int) bool {
	if port <= 0 {
		return false
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	if p != strconv.Itoa(port) {
		return false
	}
	switch h {
	case loopbackV4, loopbackV6:
		return true
	default:
		return strings.EqualFold(h, "localhost")
	}
}

// TokenSource returns the active control-API bearer token, or "" when no
// session token is available. It is called on every request, so a rotated
// token takes effect without rebuilding the middleware, and an empty result
// fails closed: every request is rejected.
type TokenSource func() string

// ControlAuth returns middleware that requires a valid per-session bearer
// token (RFC 6750) on the wrapped handler. The credential is compared in
// constant time; a missing, malformed, duplicated or wrong credential gets
// 401 with a WWW-Authenticate challenge. The token is never logged, echoed or
// included in any response (docs/13 §3.4 / docs/security.md §1–2).
func ControlAuth(token TokenSource) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			want := ""
			if token != nil {
				want = token()
			}
			got, ok := bearerCredential(r.Header.Values("Authorization"))
			if !ok || want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="tokenhush"`)
				deny(w, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerCredential extracts the token from exactly one Authorization header.
// The scheme is case-insensitive (RFC 7235); the credential is separated by
// one or more spaces. Duplicate headers, other schemes, blank credentials and
// credentials with embedded whitespace are rejected.
func bearerCredential(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	const scheme = "bearer"
	value := values[0]
	if len(value) <= len(scheme) || value[len(scheme)] != ' ' || !strings.EqualFold(value[:len(scheme)], scheme) {
		return "", false
	}
	credential := strings.TrimSpace(value[len(scheme)+1:])
	if credential == "" || strings.ContainsAny(credential, " \t") {
		return "", false
	}
	return credential, true
}

// OriginPolicy is middleware that rejects browser-initiated cross-site
// requests to the control plane. A request carrying Origin must carry the
// request's own http origin; a request carrying Sec-Fetch-Site must be
// "same-origin" or a direct user navigation ("none"). Requests carrying
// neither header (CLI, curl, other local tools) pass through so the next
// guard can enforce the bearer token (docs/13 §3.4).
//
// Only plain http is accepted as same-origin: the V1 control plane has no TLS
// listener. A different loopback alias (localhost vs 127.0.0.1) is a
// different origin and is rejected.
func OriginPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin, ok := singleHeader(r.Header.Values("Origin"))
		if !ok {
			deny(w, http.StatusForbidden)
			return
		}
		if origin != "" && !sameOrigin(origin, r.Host) {
			deny(w, http.StatusForbidden)
			return
		}
		fetchSite, ok := singleHeader(r.Header.Values("Sec-Fetch-Site"))
		if !ok {
			deny(w, http.StatusForbidden)
			return
		}
		switch strings.ToLower(fetchSite) {
		case "", "same-origin", "none":
			// CLI/curl (no header), same-origin fetches, and user-typed or
			// bookmarked navigations are not cross-site.
		default:
			deny(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// singleHeader returns the sole value of a browser-security header. The
// boolean is false when the header appears more than once: duplicated Origin
// or Sec-Fetch-Site values are malformed and must fail closed.
func singleHeader(values []string) (string, bool) {
	switch len(values) {
	case 0:
		return "", true
	case 1:
		return values[0], true
	default:
		return "", false
	}
}

// sameOrigin reports whether origin designates the same http origin as the
// request's Host. Origins with a non-http scheme, userinfo, path, query or
// fragment are malformed and rejected.
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// deny writes a guard rejection status. Bodies are status text only and never
// echo request data (headers, hosts or credentials).
func deny(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}
