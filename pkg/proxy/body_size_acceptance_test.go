package proxy

// body_size_acceptance_test.go is the end-to-end acceptance test for the
// reported multimodal failure: a session whose request body is dominated by
// base64 image leaves grew past the scan_budget_bytes aggregate gate (32 MiB),
// so every turn was refused with 403 scan_budget_exceeded before the walk. The
// test drives the real pipeline -- DataPlane -> Forwarder -> fake loopback
// upstream -- with a body above the old aggregate gate and below the
// max_body_bytes cap, and asserts all three halves of the user-visible
// contract: the request is admitted and forwarded, the one text-leaf secret is
// redacted on the way out, and the session placeholder is restored on the
// client-bound path. It is RED until the aggregate refusal is removed.

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// TestMultimodalBodySizeAcceptance reproduces the reported failure: a
// declared-JSON body above the 32 MiB aggregate scan gate but below the
// max_body_bytes cap, dominated by base64 image leaves and carrying exactly one
// detectable secret in a text leaf, must be admitted, forwarded with the secret
// redacted, and restored on the client-bound path.
func TestMultimodalBodySizeAcceptance(t *testing.T) {
	const (
		imageLeaves = 20
		imageBytes  = 1_800_000
	)

	// The placeholder prefix is assembled from two fragments so no single
	// placeholder-shaped literal sits in the source.
	placeholder := "__PII_" + "email_"

	// The address is assembled at runtime from fragments for the same reason.
	// It ends in .com, so the built-in email detector matches it.
	secret := "acceptance" + "-probe" + "@" + "fauxmail" + ".com"

	// Given: a multimodal body above the 32 MiB aggregate gate and below the
	// max_body_bytes cap, built once from one shared filler.
	filler := strings.Repeat("A", imageBytes)
	var body bytes.Buffer
	body.Grow(imageLeaves*(imageBytes+96) + 256)
	body.WriteString(`{"model":"vision-probe","messages":[{"role":"user","content":[{"type":"text","text":"contact `)
	body.WriteString(secret)
	body.WriteString(`"}`)
	for i := 0; i < imageLeaves; i++ {
		body.WriteString(`,{"type":"image_url","image_url":{"url":"data:image/png;base64,`)
		body.WriteString(filler)
		body.WriteString(`"}}`)
	}
	body.WriteString(`]}]}`)
	raw := body.Bytes()
	if int64(len(raw)) <= config.ScanBudgetBytes || int64(len(raw)) >= config.MaxBodyBytes {
		t.Fatalf("test body is %d bytes, want inside (scan budget %d, max body %d)", len(raw), config.ScanBudgetBytes, config.MaxBodyBytes)
	}

	// The pipeline composition mirrors internal/cli: registered built-ins with
	// the configured scan budget, the action policy, the session backfiller and
	// forward writer, and a BodyTransform that mirrors redactRequest.
	registry := filter.NewRegistry()
	if err := registry.RegisterBuiltin(filter.BuiltinDetectorsBudget(int(config.ScanBudgetBytes))...); err != nil {
		t.Fatalf("RegisterBuiltin: %v", err)
	}
	policy := filter.NewPolicy(registry, filter.PolicyConfig{Timeout: config.DetectorTimeout})
	backfiller := redact.NewBackfiller()
	writer := redact.NewForwardWriter(nil)
	blocked := errors.New("request blocked by content policy")
	transform := func(body []byte) ([]byte, error) {
		leaves, err := protocol.Walk(body)
		if err != nil {
			return body, nil
		}
		decision, err := policy.Decide(leaves, filter.ScopeRequest)
		if err != nil {
			return nil, err
		}
		if decision.Refusal != nil || decision.Action == filter.ActionBlock {
			return nil, blocked
		}
		if decision.Action != filter.ActionRedact {
			return body, nil
		}
		subs := make([]redact.Substitution, 0, len(decision.Substitutions))
		for _, request := range decision.Substitutions {
			if request.LeafIndex < 0 || request.LeafIndex >= len(leaves) {
				continue
			}
			subs = append(subs, redact.Substitution{
				Leaf: leaves[request.LeafIndex], Start: request.Start, End: request.End, Category: request.Category,
			})
		}
		transformed, _, err := backfiller.Substitute(writer, body, subs)
		if err != nil {
			return nil, err
		}
		return transformed, nil
	}
	upstream := newFakeUpstream(t)
	forwarder, _ := recordedForwarder(t, upstream, transform)
	plane := NewDataPlane(forwarder, DataPlaneConfig{Evaluator: allowRequestEvaluator()})

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")

	// When: the real pipeline serves the large multimodal request.
	response := httptest.NewRecorder()
	plane.ServeHTTP(response, request)

	// Then (1): the request is admitted and the upstream observed it.
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; refusal = %s", response.Code, response.Body.String())
	}
	seen := requireUpstream(t, upstream)
	if !bytes.Contains(seen.body, []byte(placeholder)) {
		t.Errorf("the upstream body carries no %s placeholder", placeholder)
	}
	// (2): the original secret never left the gateway.
	if bytes.Contains(seen.body, []byte(secret)) {
		t.Error("the upstream body still carries the text-leaf secret")
	}

	// (3): the client-bound path restores the secret from the echoed body.
	handler := NewResponseHandler(ResponseConfig{Backfiller: backfiller})
	echoed := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(seen.body)),
		Request:    request,
	}
	status, _, clientBody, err := handler.Handle(echoed)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("client-bound status = %d, want 200", status)
	}
	if !bytes.Contains(clientBody, []byte(secret)) {
		t.Error("the client-bound body did not restore the secret")
	}
}
