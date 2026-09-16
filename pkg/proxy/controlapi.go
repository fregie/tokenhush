package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/fregie/tokenhush/pkg/allowlist"
)

// Control-plane routes. They are registered on the internal mux with Go 1.22+
// method patterns, so the allowed method is part of the route and a known path
// with another method is a 405 (with Allow), never a silent fallback.
const (
	controlStatusPath    = "/status"
	controlAllowlistPath = "/allowlist"
)

// controlJSONContentType is the exact content type every control-plane
// response carries. controlJSONWriter uses it to tell an explicit JSON error
// written by a handler apart from net/http's text/plain mux fallback.
const controlJSONContentType = "application/json; charset=utf-8"

// controlAllowlistMaxBody bounds the POST/DELETE /allowlist request body. The
// store enforces the real per-entry limit; this only stops a caller from
// streaming an unbounded body into the decoder.
const controlAllowlistMaxBody = 64 << 10

// Control-plane allowlist mutation identifiers. They are part of the audit
// metadata contract: the action names the mutation and the source records who
// performed it. ControlAllowlistSource is deliberately coarse: the control API
// is only reachable by a local authenticated caller, so every mutation through
// it is a human action (CLI or web UI) in the ADR-0026 sense, never a model
// tool call.
const (
	// ControlAllowlistActionAdd is the action recorded for POST /allowlist.
	ControlAllowlistActionAdd = "add"
	// ControlAllowlistActionRemove is the action recorded for DELETE /allowlist.
	ControlAllowlistActionRemove = "remove"
	// ControlAllowlistSource is the source identifier recorded on every
	// control-plane allowlist mutation.
	ControlAllowlistSource = "allowlist-source-cli"
)

// ControlStateRunning is the state string GET /status reports while the
// daemon is serving. The control API itself only exists inside a running
// process, so this is the only V1 state.
const ControlStateRunning = "running"

// ControlStatus is the metadata-only snapshot GET /status returns. It carries
// no request or response content: only liveness, bound addresses and the
// session's cumulative counters (docs/deployment.md §5, docs/security.md).
type ControlStatus struct {
	State      string   `json:"state"`      // ControlStateRunning while serving
	Addrs      []string `json:"addrs"`      // bound listener addresses
	UptimeMS   int64    `json:"uptime_ms"`  // milliseconds since start
	Requests   uint64   `json:"requests"`   // proxied requests this session
	Redactions uint64   `json:"redactions"` // redaction replacements this session
	// Allowlist is the number of effective allowlist entries (static YAML seed
	// ∪ runtime additions) at snapshot time. Metadata only: the entry values
	// are never part of /status.
	Allowlist int `json:"allowlist"`
}

// ControlStatusFunc returns a fresh status snapshot. It is called on every
// GET /status, so the daemon can report counters that move without rebuilding
// the handler. A nil func defaults to a minimal running snapshot.
type ControlStatusFunc func() ControlStatus

// ControlAllowlist is the runtime-mutable allowlist handle backing the
// /allowlist routes. It is satisfied structurally by pkg/allowlist.Store and
// by gateway.AllowlistStore, so pkg/proxy never depends on their constructors.
type ControlAllowlist interface {
	// Entries returns the effective entries in deterministic order.
	Entries() []string
	// Add inserts an entry; invalid or duplicate entries return an error.
	Add(entry string) error
	// Remove deletes an entry; a missing entry returns an error.
	Remove(entry string) error
}

// ControlAuditEvent is the metadata-only description of one successful
// allowlist mutation. It deliberately carries no entry value: the store's
// entries are user data and an audit row must never persist them.
type ControlAuditEvent struct {
	// Action is ControlAllowlistActionAdd or ControlAllowlistActionRemove.
	Action string
	// Source identifies who changed the allowlist (ControlAllowlistSource for
	// the control plane).
	Source string
	// Count is the number of effective entries after the mutation.
	Count int
}

// ControlOption configures the optional C7 surface of a ControlAPI. The zero
// option set (no options) preserves the pre-C7 handler exactly.
type ControlOption func(*ControlAPI)

// WithControlAllowlist registers GET/POST/DELETE /allowlist on the API and
// backs them with store. A nil store leaves the routes registered but makes
// them answer a JSON 503 (see ControlAPI), so the method routing — including
// the 405 for unsupported methods — is identical whether or not C7 is wired.
func WithControlAllowlist(store ControlAllowlist) ControlOption {
	return func(c *ControlAPI) { c.allowlist = store }
}

// WithControlAudit installs the callback invoked once per successful allowlist
// mutation. A nil callback is a no-op. The callback is called synchronously on
// the request goroutine before the response is written, so a metadata row is
// recorded for every change a caller observes.
func WithControlAudit(record func(ControlAuditEvent)) ControlOption {
	return func(c *ControlAPI) {
		if record != nil {
			c.audit = record
		}
	}
}

// ControlAPI is the metadata-only control plane served on the loopback
// listeners: GET /status (liveness, addresses, counters) and, once a store is
// configured, the /allowlist CRUD routes.
//
// ControlAPI is a plain http.Handler and expects to be wrapped by the W3.2
// guards; the intended production composition is:
//
//	control := proxy.NewControlAPI(statusFunc, proxy.WithControlAllowlist(store))
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
// no response ever contains request content, secrets or HTML. The /allowlist
// routes require ControlAuth like every other control route: loopback callers
// get no exemption.
type ControlAPI struct {
	status    ControlStatusFunc
	routes    *http.ServeMux
	allowlist ControlAllowlist
	audit     func(ControlAuditEvent)
}

// NewControlAPI returns the control-plane handler. status is pulled on every
// GET /status. Optional ControlOptions wire the C7 allowlist surface; without
// them the handler behaves exactly as before.
func NewControlAPI(status ControlStatusFunc, opts ...ControlOption) *ControlAPI {
	if status == nil {
		status = controlDefaultStatus
	}
	api := &ControlAPI{status: status}
	for _, opt := range opts {
		if opt != nil {
			opt(api)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+controlStatusPath, api.handleStatus)
	mux.HandleFunc("GET "+controlAllowlistPath, api.handleAllowlistList)
	mux.HandleFunc("POST "+controlAllowlistPath, api.handleAllowlistAdd)
	mux.HandleFunc("DELETE "+controlAllowlistPath, api.handleAllowlistRemove)
	api.routes = mux
	return api
}

// ServeHTTP routes the control path and rejects everything else with a JSON
// 404. The path is checked before the mux runs so malformed paths (double
// slashes, trailing slashes) cannot trigger the mux's HTML redirect bodies;
// method mismatches on the known paths fall through to the mux, whose 405 is
// rewritten to JSON with the Allow header preserved.
func (c *ControlAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case controlStatusPath, controlAllowlistPath:
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

// handleAllowlistList answers GET /allowlist with the current entries.
func (c *ControlAPI) handleAllowlistList(w http.ResponseWriter, _ *http.Request) {
	if c.allowlist == nil {
		controlWriteError(w, http.StatusServiceUnavailable, controlAllowlistMissingMessage)
		return
	}
	controlWriteJSON(w, http.StatusOK, controlAllowlistEntries(c.allowlist))
}

// handleAllowlistAdd answers POST /allowlist.
func (c *ControlAPI) handleAllowlistAdd(w http.ResponseWriter, r *http.Request) {
	c.mutateAllowlist(w, r, ControlAllowlistActionAdd)
}

// handleAllowlistRemove answers DELETE /allowlist.
func (c *ControlAPI) handleAllowlistRemove(w http.ResponseWriter, r *http.Request) {
	c.mutateAllowlist(w, r, ControlAllowlistActionRemove)
}

// controlAllowlistMissingMessage is the JSON error of the /allowlist routes
// when no store was configured. A nil store is a disabled capability, not an
// unknown path, so it answers 503 rather than 404: a 404 would be
// indistinguishable from a mistyped control path, and 503 tells a caller the
// route exists but the daemon has no runtime allowlist wired.
const controlAllowlistMissingMessage = "allowlist is not configured"

// mutateAllowlist performs one add or remove. The request body carries the
// entry in a JSON object, the call is rejected before touching the store when
// the body is malformed, and every successful mutation records one audit event
// and answers with the resulting entry list.
func (c *ControlAPI) mutateAllowlist(w http.ResponseWriter, r *http.Request, action string) {
	if c.allowlist == nil {
		controlWriteError(w, http.StatusServiceUnavailable, controlAllowlistMissingMessage)
		return
	}
	entry, ok := controlAllowlistEntry(w, r)
	if !ok {
		return
	}
	var err error
	switch action {
	case ControlAllowlistActionAdd:
		err = c.allowlist.Add(entry)
	case ControlAllowlistActionRemove:
		err = c.allowlist.Remove(entry)
	}
	if err != nil {
		controlWriteError(w, controlAllowlistErrorStatus(err), err.Error())
		return
	}
	entries := controlAllowlistEntries(c.allowlist)
	if c.audit != nil {
		c.audit(ControlAuditEvent{Action: action, Source: ControlAllowlistSource, Count: len(entries)})
	}
	controlWriteJSON(w, http.StatusOK, entries)
}

// controlAllowlistRequest is the frozen POST/DELETE body shape: exactly one
// "entry" field.
type controlAllowlistRequest struct {
	Entry string `json:"entry"`
}

// controlAllowlistEntry decodes the entry from the JSON body. The entry is
// never accepted as a query parameter: one input channel keeps the shape
// unambiguous. Unknown fields, malformed JSON, trailing data and an empty
// entry are all JSON 400s; an empty entry also fails the store's own
// validation, but rejecting it here keeps the error local to the wire shape.
func controlAllowlistEntry(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.URL.RawQuery != "" {
		controlWriteError(w, http.StatusBadRequest, `the entry is carried in the JSON body: {"entry":"..."}`)
		return "", false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, controlAllowlistMaxBody))
	decoder.DisallowUnknownFields()
	var req controlAllowlistRequest
	if err := decoder.Decode(&req); err != nil {
		controlWriteError(w, http.StatusBadRequest, `invalid request body, want {"entry":"..."}`)
		return "", false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		controlWriteError(w, http.StatusBadRequest, `invalid request body: trailing data, want {"entry":"..."}`)
		return "", false
	}
	if req.Entry == "" {
		controlWriteError(w, http.StatusBadRequest, "entry must not be empty")
		return "", false
	}
	return req.Entry, true
}

// controlAllowlistEntries returns the entries as a JSON array even when the
// store has none: a nil slice would serialize as null.
func controlAllowlistEntries(store ControlAllowlist) []string {
	entries := store.Entries()
	if entries == nil {
		return []string{}
	}
	return entries
}

// controlAllowlistErrorStatus maps the store's sentinel errors to HTTP
// statuses. ErrInvalidEntry and ErrDuplicate are client errors (400): the
// request itself is rejected. ErrNotFound is a 404. A non-sentinel store
// failure is a server error (500). The store's own message is the response
// body, so the caller never learns more than the store already reports.
func controlAllowlistErrorStatus(err error) int {
	switch {
	case errors.Is(err, allowlist.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, allowlist.ErrInvalidEntry), errors.Is(err, allowlist.ErrDuplicate):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
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
	w.Header().Set("Content-Type", controlJSONContentType)
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
// A handler that already wrote an explicit JSON error has set the JSON content
// type; that status and body must pass through untouched, so only the
// text/plain mux fallback is rewritten.
func (w *controlJSONWriter) WriteHeader(status int) {
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		if w.intercepted == 0 && !controlIsJSONContentType(w.Header().Get("Content-Type")) {
			w.intercepted = status
			return
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

// controlIsJSONContentType reports whether a Content-Type value is the API's
// JSON type (matching the media type, ignoring any parameters).
func controlIsJSONContentType(value string) bool {
	return strings.HasPrefix(strings.ToLower(value), "application/json")
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
