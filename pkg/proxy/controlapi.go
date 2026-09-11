package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
)

// Control-plane routes. They are registered on the internal mux with Go 1.22+
// method patterns, so the allowed method is part of the route and a known path
// with another method is a 405 (with Allow), never a silent fallback.
const (
	controlStatusPath = "/status"
	controlAuditPath  = "/audit"
)

// ControlStateRunning is the state string GET /status reports while the
// daemon is serving. The control API itself only exists inside a running
// process, so this is the only V1 state.
const ControlStateRunning = "running"

// MaxControlAuditLimit caps the number of rows a single GET /audit may
// request. A larger limit parameter is clamped to this value, so a malformed
// or hostile client cannot ask the audit store for an unbounded read.
const MaxControlAuditLimit = 1000

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
// listeners: GET /status (liveness, addresses, counters) and GET /audit
// (metadata-only audit rows from the injected audit.AuditQuerier).
//
// ControlAPI is a plain http.Handler and expects to be wrapped by the W3.2
// guards; the intended production composition is:
//
//	control := proxy.NewControlAPI(statusFunc, querier)
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
	audit  audit.AuditQuerier
	routes *http.ServeMux
}

// NewControlAPI returns the control-plane handler. status is pulled on every
// GET /status; querier backs GET /audit and must be the injected
// audit.AuditQuerier seam — until W5.3 wires the real store, callers pass nil
// and the audit.NoopQuerier default serves an empty array.
func NewControlAPI(status ControlStatusFunc, querier audit.AuditQuerier) *ControlAPI {
	if status == nil {
		status = controlDefaultStatus
	}
	if querier == nil {
		querier = audit.NoopQuerier{}
	}
	api := &ControlAPI{status: status, audit: querier}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+controlStatusPath, api.handleStatus)
	mux.HandleFunc("GET "+controlAuditPath, api.handleAudit)
	api.routes = mux
	return api
}

// ServeHTTP routes the two control paths and rejects everything else with a
// JSON 404. The path is checked before the mux runs so malformed paths
// (double slashes, trailing slashes) cannot trigger the mux's HTML redirect
// bodies; method mismatches on a known path fall through to the mux, whose 405
// is rewritten to JSON with the Allow header preserved.
func (c *ControlAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case controlStatusPath, controlAuditPath:
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

// handleAudit validates the query parameters, forwards the audit.Query to the
// injected AuditQuerier and serializes the rows as a JSON array ([] when
// empty, never null). Malformed parameters are a 400; a querier failure is a
// 500 whose body carries a stable message and never the underlying cause.
func (c *ControlAPI) handleAudit(w http.ResponseWriter, r *http.Request) {
	query, err := controlParseAuditQuery(r.URL.Query())
	if err != nil {
		controlWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	records, err := c.audit.Query(r.Context(), query)
	if err != nil {
		// Store errors can embed filesystem paths or SQL details; the client
		// only needs the stable failure, and a non-200 keeps it visible.
		controlWriteError(w, http.StatusInternalServerError, "audit query failed")
		return
	}
	if records == nil {
		records = []audit.Record{}
	}
	controlWriteJSON(w, http.StatusOK, records)
}

// controlParseAuditQuery maps URL query parameters onto audit.Query:
//
//	since, until  unix milliseconds (inclusive), optional
//	provider      provider filter, optional
//	limit         row cap; 0 or absent leaves it to the querier, values above
//	              MaxControlAuditLimit are clamped to it
//
// Unknown parameters are ignored so benign cache-busting parameters keep
// working; known parameters are strictly validated and repeated parameters are
// rejected instead of first-wins, which would let a proxy smuggle a second
// value past validation.
func controlParseAuditQuery(values url.Values) (audit.Query, error) {
	since, err := controlQueryParamTime(values, "since")
	if err != nil {
		return audit.Query{}, err
	}
	until, err := controlQueryParamTime(values, "until")
	if err != nil {
		return audit.Query{}, err
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return audit.Query{}, errors.New(`"since" must not be after "until"`)
	}
	provider, err := controlSingleParam(values, "provider")
	if err != nil {
		return audit.Query{}, err
	}
	limit, err := controlQueryParamLimit(values)
	if err != nil {
		return audit.Query{}, err
	}
	return audit.Query{Since: since, Until: until, Provider: provider, Limit: limit}, nil
}

// controlQueryParamTime parses an optional unix-millisecond timestamp.
func controlQueryParamTime(values url.Values, name string) (time.Time, error) {
	raw, err := controlSingleParam(values, name)
	if err != nil || raw == "" {
		return time.Time{}, err
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %q parameter", name)
	}
	return time.UnixMilli(ms), nil
}

// controlQueryParamLimit parses and clamps the optional row limit.
func controlQueryParamLimit(values url.Values) (int, error) {
	raw, err := controlSingleParam(values, "limit")
	if err != nil || raw == "" {
		return 0, err
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, errors.New(`invalid "limit" parameter`)
	}
	if n > MaxControlAuditLimit {
		return MaxControlAuditLimit, nil
	}
	return n, nil
}

// controlSingleParam returns the sole value of a control query parameter.
// Repeated parameters are malformed and rejected.
func controlSingleParam(values url.Values, name string) (string, error) {
	vals, ok := values[name]
	if !ok {
		return "", nil
	}
	if len(vals) != 1 {
		return "", fmt.Errorf("duplicate %q parameter", name)
	}
	return vals[0], nil
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
