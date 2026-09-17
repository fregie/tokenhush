package proxy

// controlapi.go is the metadata-only control surface: exactly one route,
// GET /status, returning the proxy-owned subset of the frozen status keys.
// Every value is metadata -- a lifecycle word, the bound addresses, counters --
// and no field can carry content. pack_serial is deliberately absent because
// internal/cli merges it from the rules cache (pkg/proxy must not import
// pkg/supply), and there is no self_protection_interceptions and no
// egress_blocks because those subsystems do not exist.
//
// The surface is read-only by construction: there is no allowlist mutation
// endpoint and no second endpoint at all. Any non-GET request to any path is a
// JSON 405 with Allow: GET, and any other GET is a JSON 404. The control token
// never appears in a response.

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"time"
)

// statusPath is the control API's only route.
const statusPath = "/status"

// ControlConfig wires the control API. Every field is metadata: no field can
// carry content. An empty State reads as "running", Addrs is emitted as a JSON
// array even when empty, and Started drives uptime_ms (a zero or future start
// reads as zero).
type ControlConfig struct {
	State    string
	Addrs    []string
	Port     int
	Started  time.Time
	Counters *Counters
}

// ControlAPI serves the metadata-only control surface. It is stateless after
// construction and safe for concurrent use.
type ControlAPI struct {
	state    string
	addrs    []string
	port     int
	started  time.Time
	counters *Counters
}

// ControlAPI serves HTTP.
var _ http.Handler = (*ControlAPI)(nil)

// NewControlAPI returns the control API over the configured metadata.
func NewControlAPI(cfg ControlConfig) *ControlAPI {
	state := cfg.State
	if state == "" {
		state = "running"
	}
	addrs := slices.Clone(cfg.Addrs)
	if addrs == nil {
		addrs = []string{}
	}
	return &ControlAPI{state: state, addrs: addrs, port: cfg.Port, started: cfg.Started, counters: cfg.Counters}
}

// statusPayload is the exact wire shape of GET /status: the nine proxy-owned
// keys of the frozen status surface, all of them metadata.
type statusPayload struct {
	State               string   `json:"state"`
	Addrs               []string `json:"addrs"`
	Port                int      `json:"port"`
	UptimeMS            int64    `json:"uptime_ms"`
	Requests            int64    `json:"requests"`
	Redactions          int64    `json:"redactions"`
	ContentPolicyBlocks int64    `json:"content_policy_blocks"`
	RuleBlocks          int64    `json:"rule_blocks"`
	WalkSkips           int64    `json:"walk_skips"`
}

// controlRefusal is the metadata-only control refusal document.
type controlRefusal struct {
	Error string `json:"error"`
}

// ServeHTTP serves exactly GET /status. Every non-GET method on every path is a
// JSON 405 with Allow: GET, and every other GET is a JSON 404: there is no
// allowlist mutation route and no second endpoint.
func (c *ControlAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == statusPath {
		writeControlJSON(w, http.StatusOK, c.status())
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeControlJSON(w, http.StatusMethodNotAllowed, controlRefusal{Error: "method_not_allowed"})
		return
	}
	writeControlJSON(w, http.StatusNotFound, controlRefusal{Error: "not_found"})
}

// status renders the current metadata snapshot. A nil counter set reads zero.
func (c *ControlAPI) status() statusPayload {
	return statusPayload{
		State:               c.state,
		Addrs:               c.addrs,
		Port:                c.port,
		UptimeMS:            uptimeMillis(c.started),
		Requests:            c.counters.Requests(),
		Redactions:          c.counters.Redactions(),
		ContentPolicyBlocks: c.counters.ContentPolicyBlocks(),
		RuleBlocks:          c.counters.RuleBlocks(),
		WalkSkips:           c.counters.WalkSkips(),
	}
}

// writeControlJSON writes one JSON document with an explicit length.
func writeControlJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"refusal"}`)
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// uptimeMillis is the elapsed time implied by started; a zero or future start
// reads as zero.
func uptimeMillis(started time.Time) int64 {
	if started.IsZero() {
		return 0
	}
	elapsed := time.Since(started)
	if elapsed <= 0 {
		return 0
	}
	return elapsed.Milliseconds()
}
