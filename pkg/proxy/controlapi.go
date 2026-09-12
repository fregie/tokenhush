package proxy

import (
	"encoding/json"
	"net/http"
)

// Control-plane routes. They are registered on the internal mux with Go 1.22+
// method patterns, so the allowed method is part of the route and a known path
// with another method is a 405 (with Allow), never a silent fallback.
const (
	controlStatusPath = "/status"
)

// ControlStateRunning is the state string GET /status reports while the
// daemon is serving. The control API itself only exists inside a running
// process, so this is the only V1 state.
const ControlStateRunning = "running"

// ControlStatus is the metadata-only snapshot GET /status returns. It carries
// no request or response content: only liveness, bound addresses and the
// session's cumulative counters (docs/12 §5, docs/13 §3.4).
type ControlStatus struct {
	State      string   `json:"state"`      // ControlStateRunning while serving
	Addrs      []string `json:"addrs"`      // bound listener addresses
	UptimeMS   int64    `json:"uptime_ms"`  // milliseconds since start
	Requests   uint64   `json:"requests"`   // proxied requests this session
	Redactions uint64   `json:"redactions"` // redaction replacements this session
}

// ControlStatusFunc returns a fresh status snapshot. It is called on every
// GET /status, so the daemon can report counters that move without rebuilding
// the handler. A nil func defaults to a minimal running snapshot.
type ControlStatusFunc func() ControlStatus

// ControlAPI is the metadata-only control plane served on the loopback
// listeners: GET /status (liveness, addresses, counters).
//
// ControlAPI is a plain http.Handler and expects to be wrapped by the W3.2
// guards; the intended production composition is:
//
//	control := proxy.NewControlAPI(statusFunc)
//	handler := proxy.HostAllowlist(ls.Port())(
//		proxy.OriginPolicy(proxy.ControlAuth(tokenSource)(control)))
//
// HostAllowlist runs outermost so a DNS-rebinding Host is rejected before any
// authentication work; OriginPolicy runs before ControlAuth so a cross-site
// browser request gets 403 without revealing whether a token would be valid.
// The data-plane forwarder is deliberately a separate handler: it takes the
// Host allowlist alone and must never be exposed behind token auth.
//
// All responses are JSON; unknown paths and wrong methods get JSON errors, and
// no response ever contains request content, secrets or HTML.
type ControlAPI struct {
	status ControlStatusFunc
	routes *http.ServeMux
}

// NewControlAPI returns the control-plane handler. status is pulled on every
// GET /status.
func NewControlAPI(status ControlStatusFunc) *ControlAPI {
	if status == nil {
		status = controlDefaultStatus
	}
	api := &ControlAPI{status: status}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+controlStatusPath, api.handleStatus)
	api.routes = mux
	return api
}

// ServeHTTP routes the control path and rejects everything else with a JSON
// 404. The path is checked before the mux runs so malformed paths (double
// slashes, trailing slashes) cannot trigger the mux's HTML redirect bodies;
// method mismatches on the known path fall through to the mux, whose 405 is
// rewritten to JSON with the Allow header preserved.
func (c *ControlAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case controlStatusPath:
		cw := &controlJSONWriter{ResponseWriter: w}
		c.routes.ServeHTTP(cw, r)
		cw.finish()
	default:
		controlWriteError(w, http.StatusNotFound, "not found")
	}
}

// handleStatus serializes the current snapshot. An empty state is normalized
// to ControlStateRunning and a nil address list to [], so the JSON contract is
// stable for W6.3 and W9.1 consumers.
func (c *ControlAPI) handleStatus(w http.ResponseWriter, _ *http.Request) {
	status := c.status()
	if status.State == "" {
		status.State = ControlStateRunning
	}
	if status.Addrs == nil {
		status.Addrs = []string{}
	}
	controlWriteJSON(w, http.StatusOK, status)
}

// controlDefaultStatus is the snapshot used when NewControlAPI receives a nil
// status func: running, no addresses and zero counters.
func controlDefaultStatus() ControlStatus {
	return ControlStatus{State: ControlStateRunning, Addrs: []string{}}
}

// controlError is the JSON shape of every control-API error response.
type controlError struct {
	Error string `json:"error"`
}

// controlWriteJSON is the single success/error writer: it pins the JSON
// content type, blocks MIME sniffing and encodes the payload. An encode
// failure cannot change the already-sent status; control payloads are plain
// structs/slices and are always encodable.
func controlWriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// controlWriteError writes payload as {"error": message}.
func controlWriteError(w http.ResponseWriter, status int, message string) {
	controlWriteJSON(w, status, controlError{Error: message})
}

// controlJSONWriter replaces the text/plain body net/http emits for method
// mismatches (405) with the API's JSON error shape. Only 404/405 are
// intercepted, and the headers the fallback already set (Allow, nosniff) are
// preserved; every other status, including 200 from the handlers, passes
// through untouched.
type controlJSONWriter struct {
	http.ResponseWriter
	intercepted int
}

// WriteHeader intercepts net/http's fallback statuses and forwards the rest.
func (w *controlJSONWriter) WriteHeader(status int) {
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		if w.intercepted == 0 {
			w.intercepted = status
		}
	default:
		w.ResponseWriter.WriteHeader(status)
	}
}

// Write swallows the fallback text body; all other writes pass through.
func (w *controlJSONWriter) Write(p []byte) (int, error) {
	if w.intercepted != 0 {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

// finish emits the JSON error for an intercepted fallback response.
func (w *controlJSONWriter) finish() {
	if w.intercepted == 0 {
		return
	}
	message := "not found"
	if w.intercepted == http.StatusMethodNotAllowed {
		message = "method not allowed"
	}
	controlWriteError(w.ResponseWriter, w.intercepted, message)
}
