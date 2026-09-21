package proxy

// dataplane_refusal.go owns every client-bound refusal document the gateway
// writes: the metadata-only codes, the JSON shape, the single writer and the
// classifiers that pick a code. Every request-side refusal is HTTP 403 or the
// unwalkable-body 400, and the body is always the same document, so a client
// classifies a refusal by shape alone.
//
// HTTP 413 was considered for the body-size refusal and rejected: every other
// gateway refusal is 403 with this document, and a second status would make
// body_too_large the only refusal a client could not classify the same way.
//
// No field of a refusal can hold content: they carry a fixed code, one of the
// five classified failure reasons and a rule id.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// The metadata-only request refusal codes. refusalRuleBlocked is shared with
// the response path and is defined beside its writer in response_buffered.go.
const (
	refusalUnreadableBody = "unreadable_body"
	refusalBodyTooLarge   = "body_too_large"
	refusalPluginFailure  = "plugin_failure"
	refusalUnwalkableJSON = "unwalkable_json"
)

// dataPlaneRefusal is the client-bound refusal document: a fixed code, the
// classified failure reason where one applies and the rule id of a block.
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
