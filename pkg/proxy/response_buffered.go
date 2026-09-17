package proxy

// response_buffered.go is the buffered, client-bound half of invariant 7: no
// encoded content may reach the client uninspected, and no status code may be
// committed before decoding has succeeded. An upstream response is read in
// full, every Content-Encoding token is classified, and a gzip/deflate body is
// decoded before the status code is even chosen. A coding the gateway cannot
// decode -- br, zstd, an unknown token, a list mixing supported and unsupported
// codings, or a corrupt stream -- is a transport refusal: 502 with the upstream
// bytes discarded and no content-policy counter moved.
//
// A decodable body is then evaluated through the injected Evaluator. Its error
// means the body could not be walked (it does not parse as JSON): such a body
// is forwarded byte-identically with backfill still running and walk_skips
// incremented, because both directions are client-bound -- an unparseable
// response cannot exfiltrate, and failing closed here would break legitimate
// plain-text error bodies and [DONE]/ping streams. A response-scoped Block is
// a 502 naming the rule id, discards the upstream bytes and moves
// content_policy_blocks and rule_blocks; a Warn forwards the response
// unchanged and writes one metadata-only warning line.
//
// Backfill always runs last on the client-bound path, and the forward-only
// placeholder writer is unreachable from this file by construction: the only
// substitution writer this path can hold is a Backfiller.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

// ResponseAction is the client-bound effect of one response-phase evaluation.
// The direction contract admits exactly allow, warn and block on this path;
// there is deliberately no redact value, because only a request-phase rule may
// request a substitution.
type ResponseAction string

// The three client-bound actions.
const (
	ResponseAllow ResponseAction = "allow"
	ResponseWarn  ResponseAction = "warn"
	ResponseBlock ResponseAction = "block"
)

// ResponseDecision is the proxy-owned verdict of one response-phase
// evaluation. RuleIDs names the rules backing Action in core order; a Block
// refusal names the first one and a Warn writes one warning line per id.
// An undefined Action fails closed, never through.
type ResponseDecision struct {
	Action  ResponseAction
	RuleIDs []string
}

// Evaluator is the client-bound evaluation seam. An error means the body could
// not be walked, which is the one condition the response direction forwards
// rather than refuses.
type Evaluator interface {
	EvaluateResponse(ctx context.Context, body []byte) (ResponseDecision, error)
}

// Backfiller restores session placeholders on the client-bound path. It is the
// only substitution writer this path can hold, so the forward-only placeholder
// writer stays unreachable.
type Backfiller interface {
	Backfill([]byte) []byte
}

// WarningWriter receives metadata-only warning lines (stderr in production).
type WarningWriter interface {
	Warn(line string)
}

// Counters are the proxy-owned, metadata-only counters behind the frozen
// status surface. Each counter is a monotonic total and nothing here can hold
// content. A nil *Counters reads as zero and ignores increments, so a status
// read can never panic.
type Counters struct {
	counts [counterCount]atomic.Int64
}

// The counter slots, in the order of the frozen status surface.
const (
	counterRequests = iota
	counterRedactions
	counterContentPolicyBlocks
	counterRuleBlocks
	counterWalkSkips
	counterCount
)

// value reads one counter slot; a nil set reads as zero.
func (c *Counters) value(slot int) int64 {
	if c == nil {
		return 0
	}
	return c.counts[slot].Load()
}

// bump adds one to one counter slot; a nil set ignores it.
func (c *Counters) bump(slot int) {
	if c != nil {
		c.counts[slot].Add(1)
	}
}

// Requests is the total number of proxied requests.
func (c *Counters) Requests() int64 { return c.value(counterRequests) }

// Redactions is the total number of request-phase substitutions.
func (c *Counters) Redactions() int64 { return c.value(counterRedactions) }

// ContentPolicyBlocks is the total number of content-policy refusals.
func (c *Counters) ContentPolicyBlocks() int64 { return c.value(counterContentPolicyBlocks) }

// RuleBlocks is the total number of rule-decided blocks.
func (c *Counters) RuleBlocks() int64 { return c.value(counterRuleBlocks) }

// WalkSkips is the total number of client-bound bodies that could not be
// walked and were forwarded byte-identically instead.
func (c *Counters) WalkSkips() int64 { return c.value(counterWalkSkips) }

// NewCounters returns a zeroed counter set.
func NewCounters() *Counters { return &Counters{} }

// countRequest records one proxied request.
func (c *Counters) countRequest() { c.bump(counterRequests) }

// countRedaction records one request-phase substitution.
func (c *Counters) countRedaction() { c.bump(counterRedactions) }

// countContentPolicyBlock records one content-policy refusal.
func (c *Counters) countContentPolicyBlock() { c.bump(counterContentPolicyBlocks) }

// countRuleBlock records one rule-decided block.
func (c *Counters) countRuleBlock() { c.bump(counterRuleBlocks) }

// countWalkSkip records one client-bound body that could not be walked.
func (c *Counters) countWalkSkip() { c.bump(counterWalkSkips) }

// ResponseConfig wires the buffered response handler's injectable seams. A nil
// Evaluator means no evaluation, a nil Backfiller is the identity transform, a
// nil Counters means a fresh discarded set, and a nil WarningWriter drops
// warnings (production wires stderr).
type ResponseConfig struct {
	Evaluator  Evaluator
	Backfiller Backfiller
	Counters   *Counters
	Warnings   WarningWriter
}

// ResponseHandler is the buffered client-bound response path. It is stateless
// after construction and therefore safe for concurrent use.
type ResponseHandler struct {
	evaluator  Evaluator
	backfiller Backfiller
	counters   *Counters
	warnings   WarningWriter
}

// ErrNilResponse is returned when Handle is asked to handle a nil response: a
// caller contract violation, never a client-visible condition.
var ErrNilResponse = errors.New("proxy: nil upstream response")

// NewResponseHandler returns a handler over the configured seams. Nil seams
// take their documented inert defaults, so a handler always exists.
func NewResponseHandler(cfg ResponseConfig) *ResponseHandler {
	counters := cfg.Counters
	if counters == nil {
		counters = NewCounters()
	}
	return &ResponseHandler{
		evaluator:  cfg.Evaluator,
		backfiller: cfg.Backfiller,
		counters:   counters,
		warnings:   cfg.Warnings,
	}
}

// Handle buffers one upstream response and returns the status, headers and
// body to send to the client. Decoding happens before any status is chosen, so
// an undecodable response returns a 502 rather than the upstream status. An
// error is returned only for a nil response; every per-response refusal is
// materialised here as a 502 with a metadata-only JSON body. Handle reads
// upstream.Body to EOF without closing it: the caller owns it.
func (h *ResponseHandler) Handle(upstream *http.Response) (int, http.Header, []byte, error) {
	if upstream == nil {
		return 0, nil, nil, ErrNilResponse
	}
	raw, err := readAll(upstream)
	if err != nil {
		return refuse(http.StatusBadGateway, refusalUnreadable, "")
	}
	codings, ok := declaredCodings(upstream.Header.Values("Content-Encoding"))
	if !ok {
		return refuse(http.StatusBadGateway, refusalUndecodable, "")
	}
	body, ok := decodeAll(raw, codings)
	if !ok {
		return refuse(http.StatusBadGateway, refusalUndecodable, "")
	}
	if h.evaluator != nil {
		decision, err := h.evaluator.EvaluateResponse(clientContext(upstream), body)
		switch {
		case err != nil:
			h.counters.countWalkSkip()
		case decision.Action == ResponseWarn:
			h.warn(decision.RuleIDs)
		case decision.Action == ResponseAllow:
		default:
			h.counters.countContentPolicyBlock()
			h.counters.countRuleBlock()
			return refuse(http.StatusBadGateway, refusalRuleBlocked, primaryRule(decision.RuleIDs))
		}
	}
	body = h.backfill(body)
	header := make(http.Header, len(upstream.Header))
	copyEndToEndHeaders(header, upstream.Header)
	if len(codings) > 0 {
		header.Del("Content-Encoding")
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return upstream.StatusCode, header, body, nil
}

// warningPrefix opens every metadata-only response warning line.
const warningPrefix = "tokenhush: response warn"

// The metadata-only refusal codes the buffered response path may emit. They
// are observations, never content: no upstream byte appears in a refusal.
const (
	refusalUndecodable = "undecodable_content_encoding"
	refusalUnreadable  = "upstream_body_unreadable"
	refusalRuleBlocked = "rule_blocked"
)

// refusal is the client-bound refusal document. It carries a reason code and,
// for a rule block, the rule id; it has no field that could hold content.
type refusal struct {
	Error  string `json:"error"`
	RuleID string `json:"rule_id,omitempty"`
}

// refuse renders a client-bound refusal. The rule id is quarantined through
// the JSON encoder, so a hostile id cannot break out of the document.
func refuse(status int, code, ruleID string) (int, http.Header, []byte, error) {
	body, err := json.Marshal(refusal{Error: code, RuleID: ruleID})
	if err != nil {
		body = []byte(`{"error":"refusal"}`)
	}
	header := make(http.Header, 2)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return status, header, body, nil
}

// readAll consumes the upstream body without closing it; a nil body is empty.
func readAll(upstream *http.Response) ([]byte, error) {
	if upstream.Body == nil {
		return nil, nil
	}
	return io.ReadAll(upstream.Body)
}

// clientContext returns the context of the request that produced the response,
// so an evaluation observes client cancellation; a hand-built response gets
// the background context.
func clientContext(upstream *http.Response) context.Context {
	if upstream.Request == nil {
		return context.Background()
	}
	return upstream.Request.Context()
}

// primaryRule returns the first rule id of a decision, or "" when it names none.
func primaryRule(ruleIDs []string) string {
	if len(ruleIDs) == 0 {
		return ""
	}
	return ruleIDs[0]
}

// declaredCodings flattens every comma-separated Content-Encoding value into
// its codings, lowercased and in declared order, dropping identity. ok is
// false when any token is outside gzip, x-gzip and deflate, so a
// declared-but-unsupported coding can never pass through undecoded; a blank
// value fails closed for the same reason it does on the request direction.
func declaredCodings(values []string) ([]string, bool) {
	var codings []string
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			switch coding := strings.ToLower(strings.TrimSpace(token)); coding {
			case "identity":
			case "gzip", "x-gzip", "deflate":
				codings = append(codings, coding)
			default:
				return nil, false
			}
		}
	}
	return codings, true
}

// decodeAll unwinds every declared coding in reverse, so "gzip, deflate" is
// decoded deflate-first. ok is false on the first failure; the caller discards
// whatever was decoded so far rather than forwarding a partial body.
func decodeAll(raw []byte, codings []string) ([]byte, bool) {
	body := raw
	for i := len(codings) - 1; i >= 0; i-- {
		var (
			decoded []byte
			err     error
		)
		switch codings[i] {
		case "gzip", "x-gzip":
			decoded, err = readGzip(body)
		case "deflate":
			decoded, err = readFlate(body)
		default:
			return nil, false
		}
		if err != nil {
			return nil, false
		}
		body = decoded
	}
	return body, true
}

// readGzip decodes one gzip stream.
func readGzip(body []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

// readFlate decodes one raw deflate stream.
func readFlate(body []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(body))
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

// warn writes one metadata-only warning line per rule that backed a Warn
// decision. The rule id is quoted, so a hostile id can never inject a second
// line into the warning stream.
func (h *ResponseHandler) warn(ruleIDs []string) {
	if h.warnings == nil {
		return
	}
	if len(ruleIDs) == 0 {
		h.warnings.Warn(warningPrefix)
		return
	}
	for _, id := range ruleIDs {
		h.warnings.Warn(warningPrefix + " rule=" + strconv.Quote(id))
	}
}

// backfill restores session placeholders on the client-bound body. It runs
// last, after any evaluation, and a nil backfiller is the identity transform.
func (h *ResponseHandler) backfill(body []byte) []byte {
	if h.backfiller == nil {
		return body
	}
	return h.backfiller.Backfill(body)
}
