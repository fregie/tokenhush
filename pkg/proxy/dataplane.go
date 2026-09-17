package proxy

// dataplane.go is the request-side half of invariant 5: a request that declares
// JSON is walked and evaluated before the forwarder ever reads it, and every
// failure in that pipeline is refused locally with a metadata-only body, so an
// unwalkable payload can never reach an upstream. The verdict is deliberately
// taken at the HTTP layer, where both the Content-Type header and the first
// body byte are visible.
//
// The "declares JSON" predicate is exactly: the Content-Type media type is
// application/json (case-insensitive, parameters stripped), or there is no
// Content-Type header and the first non-whitespace byte is '{', '[' or '"'.
// Any other media type -- application/json-seq, application/json-patch+json,
// text/plain -- takes the byte-for-byte passthrough with no walk and no counter
// change. A request carrying a non-identity Content-Encoding goes to the
// forwarder untouched, which refuses it with 415 before reading a byte.
//
// Refusals: an unwalkable declared-JSON body is a 400 carrying the walk's
// classification; a body over the pkg/config scan budget is 403
// scan_budget_exceeded (refused before the walk, so the verdict is
// deterministic and independent of timing); a walk or detector panic, a
// detector timeout and a failed evaluation are 403 plugin_failure with a closed
// reason; a request-scoped Block -- including a global blocklist literal, which
// the evaluator reports as the rule id "blocklist" -- is 403 naming the rule
// id. Every 400 and every 403 moves content_policy_blocks, and a rule block
// additionally moves rule_blocks. Refusal bodies are metadata only: a fixed
// code plus the JSON-encoded rule id the core stamped, never a matched byte.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/protocol"
)

// RequestAction is the request-bound effect of one request-phase evaluation.
// The direction contract admits exactly allow and block on this path; an
// undefined action fails closed as a rule block.
type RequestAction string

// The two request-bound actions.
const (
	RequestAllow RequestAction = "allow"
	RequestBlock RequestAction = "block"
)

// RequestDecision is the proxy-owned verdict of one request-phase evaluation.
// RuleIDs names the rules backing Action in core order.
type RequestDecision struct {
	Action  RequestAction
	RuleIDs []string
}

// FailureReason is the classified reason one request-phase detection failed.
// The set is closed; a reason outside it is reported as FailureError.
type FailureReason string

// The five failure reasons, mirroring pkg/filter's classification.
const (
	FailureBudget    FailureReason = "budget"
	FailureTimeout   FailureReason = "timeout"
	FailureError     FailureReason = "error"
	FailurePanic     FailureReason = "panic"
	FailureMalformed FailureReason = "malformed"
)

// DetectorFailure is the classified failure of one request-phase evaluation:
// the reason the frozen plugin_failure contract requires. Any other error is
// reported as FailureError.
type DetectorFailure struct {
	RuleID string
	Reason FailureReason
}

// Error renders the classified failure without any content.
func (e *DetectorFailure) Error() string {
	return "proxy: detector " + e.RuleID + " failed: " + string(e.Reason)
}

// RequestEvaluator is the request-bound evaluation seam. An error means the
// evaluation failed: a *DetectorFailure names one of the five reasons, anything
// else is a plain error. A nil evaluator means no evaluation.
type RequestEvaluator interface {
	EvaluateRequest(ctx context.Context, leaves []protocol.Leaf) (RequestDecision, error)
}

// Walker is the leaf-walk seam; protocol.Walk is the production value.
type Walker interface {
	Walk(data []byte) ([]protocol.Leaf, error)
}

// WalkerFunc adapts a walk function to Walker.
type WalkerFunc func(data []byte) ([]protocol.Leaf, error)

// Walk implements Walker.
func (f WalkerFunc) Walk(data []byte) ([]protocol.Leaf, error) { return f(data) }

// DataPlaneConfig wires the request-side data plane's injectable seams. A nil
// Walker means protocol.Walk, a nil Evaluator means no evaluation and a nil
// Counters means a fresh discarded set. Budget is the deterministic scan cap
// (pkg/config ScanBudgetBytes) and Timeout the detector bound (pkg/config
// DetectorTimeout); a non-positive value takes the pkg/config default.
type DataPlaneConfig struct {
	Walker    Walker
	Evaluator RequestEvaluator
	Counters  *Counters
	Budget    int64
	Timeout   time.Duration
}

// DataPlane is the request-side fail-closed gate. It reads the whole body,
// decides whether the request declares JSON, and either refuses locally or
// hands the request to the next handler with the identical body restored. It is
// safe for concurrent use.
type DataPlane struct {
	next      http.Handler
	walker    Walker
	evaluator RequestEvaluator
	counters  *Counters
	budget    int64
	timeout   time.Duration
}

// DataPlane serves HTTP.
var _ http.Handler = (*DataPlane)(nil)

// NewDataPlane returns a data plane over the configured seams. next receives
// every request this gate admits; a nil next answers 404 and never dials.
func NewDataPlane(next http.Handler, cfg DataPlaneConfig) *DataPlane {
	if next == nil {
		next = http.NotFoundHandler()
	}
	walker := cfg.Walker
	if walker == nil {
		walker = WalkerFunc(protocol.Walk)
	}
	counters := cfg.Counters
	if counters == nil {
		counters = NewCounters()
	}
	budget := cfg.Budget
	if budget <= 0 {
		budget = config.ScanBudgetBytes
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = config.DetectorTimeout
	}
	return &DataPlane{next: next, walker: walker, evaluator: cfg.Evaluator, counters: counters, budget: budget, timeout: timeout}
}

// ServeHTTP applies the request-side contract in order: an encoded request goes
// to the forwarder untouched (which refuses it 415 before reading), a non-JSON
// body is forwarded byte-identically without a walk, and a declared-JSON body
// is walked and evaluated or refused locally.
func (p *DataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !identityOnlyEncoding(r.Header) {
		p.next.ServeHTTP(w, r)
		return
	}
	body, err := readRequestBody(r)
	if err != nil {
		p.refuse(w, http.StatusBadRequest, dataPlaneRefusal{Error: refusalUnreadableBody})
		return
	}
	if !declaresJSON(r.Header, body) {
		p.forward(w, r, body)
		return
	}
	p.inspect(w, r, body)
}

// inspect walks and evaluates one declared-JSON body under the scan budget and
// the detector bound.
func (p *DataPlane) inspect(w http.ResponseWriter, r *http.Request, body []byte) {
	if int64(len(body)) > p.budget {
		p.refuse(w, http.StatusForbidden, dataPlaneRefusal{Error: refusalScanBudget})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()

	walked := guardCall(p.timeout, func() ([]protocol.Leaf, error) { return p.walker.Walk(body) })
	switch {
	case walked.reason != "":
		p.refuse(w, http.StatusForbidden, pluginFailure(walked.reason))
		return
	case walked.err != nil:
		p.refuse(w, http.StatusBadRequest, dataPlaneRefusal{Error: walkClassification(walked.err)})
		return
	}
	if p.evaluator == nil {
		p.forward(w, r, body)
		return
	}
	decided := guardCall(p.timeout, func() (RequestDecision, error) {
		return p.evaluator.EvaluateRequest(ctx, walked.value)
	})
	switch {
	case decided.reason != "":
		p.refuse(w, http.StatusForbidden, pluginFailure(decided.reason))
	case decided.err != nil:
		p.refuse(w, http.StatusForbidden, pluginFailure(failureReason(decided.err)))
	case decided.value.Action == RequestAllow:
		p.forward(w, r, body)
	default:
		p.block(w, decided.value.RuleIDs)
	}
}

// callOutcome is one guarded seam call: a value, a classification error, or a
// fail-closed reason when the call panicked or outran its bound.
type callOutcome[T any] struct {
	value  T
	err    error
	reason FailureReason
}

// guardCall runs call under the detector bound with panic recovery. The result
// channel is buffered, so an abandoned call can never block or leak.
func guardCall[T any](timeout time.Duration, call func() (T, error)) callOutcome[T] {
	results := make(chan callOutcome[T], 1)
	go func() {
		defer func() {
			if recover() != nil {
				results <- callOutcome[T]{reason: FailurePanic}
			}
		}()
		value, err := call()
		results <- callOutcome[T]{value: value, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-results:
		return result
	case <-timer.C:
		return callOutcome[T]{reason: FailureTimeout}
	}
}

// The metadata-only request refusal codes.
const (
	refusalUnreadableBody = "unreadable_body"
	refusalScanBudget     = "scan_budget_exceeded"
	refusalPluginFailure  = "plugin_failure"
	refusalUnwalkableJSON = "unwalkable_json"
)

// dataPlaneRefusal is the client-bound request refusal document: a fixed code,
// the classified failure reason where one applies and the rule id of a block.
// No field can hold content.
type dataPlaneRefusal struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
	RuleID string `json:"rule_id,omitempty"`
}

// failureReasons is the closed set the plugin_failure contract admits.
var failureReasons = map[FailureReason]bool{
	FailureBudget:    true,
	FailureTimeout:   true,
	FailureError:     true,
	FailurePanic:     true,
	FailureMalformed: true,
}

// pluginFailure renders the fail-closed detection refusal for one reason.
func pluginFailure(reason FailureReason) dataPlaneRefusal {
	return dataPlaneRefusal{Error: refusalPluginFailure, Reason: string(reason)}
}

// refuse moves content_policy_blocks and writes the metadata-only refusal.
func (p *DataPlane) refuse(w http.ResponseWriter, status int, doc dataPlaneRefusal) {
	p.counters.countContentPolicyBlock()
	writeDataPlaneRefusal(w, status, doc)
}

// block moves both content counters and writes the rule-block refusal naming
// the first rule id the decision carried.
func (p *DataPlane) block(w http.ResponseWriter, ruleIDs []string) {
	p.counters.countContentPolicyBlock()
	p.counters.countRuleBlock()
	writeDataPlaneRefusal(w, http.StatusForbidden, dataPlaneRefusal{Error: refusalRuleBlocked, RuleID: primaryRule(ruleIDs)})
}

// writeDataPlaneRefusal writes one JSON refusal with an explicit length.
func writeDataPlaneRefusal(w http.ResponseWriter, status int, doc dataPlaneRefusal) {
	body, err := json.Marshal(doc)
	if err != nil {
		body = []byte(`{"error":"refusal"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// forward hands the request to the next handler with the identical body
// restored, so an admitted request is byte-for-byte.
func (p *DataPlane) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	p.next.ServeHTTP(w, r)
}

// jsonWhitespace is the four-byte JSON whitespace set.
const jsonWhitespace = " \t\n\r"

// declaresJSON implements the frozen predicate exactly. A present Content-Type
// header decides on its own: only the exact application/json media type
// declares JSON. With no header at all, the first non-whitespace byte decides,
// and an empty body declares nothing.
func declaresJSON(header http.Header, body []byte) bool {
	if values := header.Values("Content-Type"); len(values) > 0 {
		return mediaType(values[0]) == "application/json"
	}
	trimmed := bytes.TrimLeft(body, jsonWhitespace)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '[' || trimmed[0] == '"'
}

// mediaType lowercases one Content-Type value and strips every parameter.
func mediaType(value string) string {
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

// walkClassification maps a walk failure onto the stable classification the 400
// body carries. The error text is never echoed.
func walkClassification(err error) string {
	switch {
	case errors.Is(err, protocol.ErrMalformedJSON):
		return "malformed_json"
	case errors.Is(err, protocol.ErrTrailingData):
		return "trailing_data"
	case errors.Is(err, protocol.ErrNonUTF8):
		return "invalid_utf8"
	case errors.Is(err, protocol.ErrMaxDepth):
		return "max_depth"
	default:
		return refusalUnwalkableJSON
	}
}

// failureReason classifies an evaluator error: a *DetectorFailure names one of
// the five reasons and anything else is FailureError, so the wire contract
// stays closed.
func failureReason(err error) FailureReason {
	var failure *DetectorFailure
	if errors.As(err, &failure) && failureReasons[failure.Reason] {
		return failure.Reason
	}
	return FailureError
}
