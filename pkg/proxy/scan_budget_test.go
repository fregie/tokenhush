package proxy

// Deterministic scan-budget and content-policy accounting regressions. The
// budget replaces the wall-clock detector race as the primary gate: a body at
// or below it is scanned, a body above it is refused before any detector runs,
// and the verdict depends only on the input size. Every refusal is counted and
// labelled in the 403 body, so a content-policy block is neither uncounted nor
// anonymous.

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// budgetBody returns a JSON body guaranteed to exceed any small test budget.
func budgetBody(size int) []byte {
	return []byte(`{"input":"` + strings.Repeat("A", size) + `"}`)
}

// errorInspector is a FailClosed inspector whose Inspect always errors, so the
// policy folds it into a plugin_failure block. It exists only to prove the 403
// body names the class, the plugin id and the reason.
type errorInspector struct{}

func (errorInspector) ID() string { return "test-error-inspector" }

func (errorInspector) Capabilities() extension.Capabilities {
	return extension.Capabilities{
		Phases:      []extension.Phase{extension.RequestContent, extension.ResponseContent},
		ReadContent: true,
		CanBlock:    true,
	}
}

func (errorInspector) Inspect(*extension.Document) ([]extension.Finding, error) {
	return nil, errors.New("forced detector error")
}

// TestScanBudgetRefusesOverBudgetBodyDeterministically locks the core of (A):
// an over-budget body is refused before any detector runs, with the dedicated
// finding type and reason, and the refusal moves the content-policy counter.
func TestScanBudgetRefusesOverBudgetBodyDeterministically(t *testing.T) {
	pipe := w45Pipeline(t, PipelineConfig{
		Registry:   w45Registry(t),
		Engine:     w45Engine(t),
		ScanBudget: 1024,
	})
	body := budgetBody(4096)
	if int64(len(body)) <= pipe.ScanBudget() {
		t.Fatalf("test body %d bytes does not exceed budget %d", len(body), pipe.ScanBudget())
	}

	_, err := pipe.RequestTransform()(body)
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("over-budget request error = %v, want a *BlockedError", err)
	}
	if len(blocked.Findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1", len(blocked.Findings))
	}
	f := blocked.Findings[0]
	if f.Type != TypeScanBudgetExceeded {
		t.Fatalf("finding type = %q, want %q", f.Type, TypeScanBudgetExceeded)
	}
	if f.Action != extension.Block {
		t.Fatalf("finding action = %q, want block", f.Action)
	}
	if f.Meta["reason"] != "budget" {
		t.Fatalf("finding reason = %v, want budget", f.Meta["reason"])
	}
	if f.Meta["limit_bytes"] != int64(1024) {
		t.Fatalf("finding limit_bytes = %v, want 1024", f.Meta["limit_bytes"])
	}
	if got := pipe.ContentPolicyBlocks(); got != 1 {
		t.Fatalf("content_policy_blocks after one over-budget refusal = %d, want 1", got)
	}

	// A body at or below the budget is scanned, not refused, and moves nothing.
	small := budgetBody(16)
	if int64(len(small)) > pipe.ScanBudget() {
		t.Fatalf("control body unexpectedly over budget")
	}
	if _, err := pipe.RequestTransform()(small); err != nil {
		t.Fatalf("at-budget request error = %v, want nil", err)
	}
	if got := pipe.ContentPolicyBlocks(); got != 1 {
		t.Fatalf("content_policy_blocks after a clean request = %d, want 1 (unchanged)", got)
	}
}

// TestScanBudgetVerdictDependsOnlyOnSize proves the determinism property the
// budget exists for: the same body is refused at a budget below its size and
// accepted at a budget above it, with no timing involved. A machine's speed
// cannot move this verdict.
func TestScanBudgetVerdictDependsOnlyOnSize(t *testing.T) {
	body := budgetBody(2048)
	at := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: w45Engine(t), ScanBudget: int64(len(body))})
	if _, err := at.RequestTransform()(body); err != nil {
		t.Fatalf("body == budget: error = %v, want nil (the budget is inclusive)", err)
	}
	below := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: w45Engine(t), ScanBudget: int64(len(body)) - 1})
	if _, err := below.RequestTransform()(body); err == nil {
		t.Fatal("body > budget: error = nil, want a deterministic refusal")
	}
}

// TestScanBudget403NamesClass locks (C): the 403 body names the class and the
// reason instead of a bare "blocked by content policy".
func TestScanBudget403NamesClass(t *testing.T) {
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: w45Engine(t), ScanBudget: 1024})
	_, err := pipe.RequestTransform()(budgetBody(4096))
	if err == nil {
		t.Fatal("over-budget request error = nil, want a refusal")
	}
	rec := httptest.NewRecorder()
	if !pipe.TransformErrorHandler()(rec, err) {
		t.Fatal("TransformErrorHandler did not handle the BlockedError")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	msg := rec.Body.String()
	for _, want := range []string{"blocked by content policy", TypeScanBudgetExceeded, "reason=budget"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("403 body %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "AAAA") {
		t.Fatalf("403 body leaked body content: %q", msg)
	}
}

// TestPluginFailure403NamesClass covers the fail-closed detector failure class
// the task names (timeout / plugin error): the 403 body carries the class, the
// plugin id and the reason, and the block is counted.
func TestPluginFailure403NamesClass(t *testing.T) {
	reg := w45Registry(t, errorInspector{})
	policy := extension.NewPolicy(reg, extension.PolicyConfig{
		Failures: map[string]extension.FailurePolicy{"test-error-inspector": extension.FailClosed},
	})
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Policy: policy, Engine: w45Engine(t)})

	_, err := pipe.RequestTransform()(budgetBody(8))
	if err == nil {
		t.Fatal("failing detector: error = nil, want a fail-closed refusal")
	}
	rec := httptest.NewRecorder()
	if !pipe.TransformErrorHandler()(rec, err) {
		t.Fatal("TransformErrorHandler did not handle the BlockedError")
	}
	msg := rec.Body.String()
	for _, want := range []string{"plugin_failure", "plugin=test-error-inspector", "reason=error"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("403 body %q does not contain %q", msg, want)
		}
	}
	if got := pipe.ContentPolicyBlocks(); got != 1 {
		t.Fatalf("content_policy_blocks after a plugin_failure block = %d, want 1", got)
	}
}

// TestScanBudgetOverBudgetIsNotSilent locks the owner's fail-closed choice: an
// over-budget body is refused outright, never silently allowed and never
// partially scanned.
func TestScanBudgetOverBudgetIsNotSilent(t *testing.T) {
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: w45Engine(t)})
	pipe.SetScanBudget(64)
	body := budgetBody(4096)
	out, err := pipe.RequestTransform()(body)
	if err == nil || out != nil {
		t.Fatalf("over-budget transform = (%v, %v), want (nil, refusal)", out, err)
	}
}

// TestScanBudgetResponsePathRefusesOverBudget covers the inbound direction of
// the same budget: a client-bound body over the budget is refused before its
// detectors run and the block is counted with the response direction.
func TestScanBudgetResponsePathRefusesOverBudget(t *testing.T) {
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: w45Engine(t), ScanBudget: 1024})
	body := budgetBody(4096)
	_, err := pipe.transformResponse(body, pipe.tool)
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("over-budget response error = %v, want a *BlockedError", err)
	}
	if blocked.Phase != extension.ResponseContent {
		t.Fatalf("blocked phase = %q, want response_content", blocked.Phase)
	}
	if blocked.Findings[0].Type != TypeScanBudgetExceeded {
		t.Fatalf("finding type = %q, want %q", blocked.Findings[0].Type, TypeScanBudgetExceeded)
	}
	if got := pipe.ContentPolicyBlocks(); got != 1 {
		t.Fatalf("content_policy_blocks after one over-budget response = %d, want 1", got)
	}
}

// applied: after the walk. A body the detectors would never scan (not JSON)
// keeps its documented byte-for-byte passthrough even when it exceeds the
// budget, so a large non-JSON upload is not turned into a refusal.
func TestScanBudgetLeavesNonJSONPassthroughUnchanged(t *testing.T) {
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: w45Engine(t), ScanBudget: 64})
	body := []byte("this is not json and is longer than the 64-byte budget " + strings.Repeat("x", 256))
	out, err := pipe.RequestTransform()(body)
	if !errors.Is(err, ErrUnwalkableBody) {
		t.Fatalf("non-JSON over-budget error = %v, want ErrUnwalkableBody (passthrough, not a block)", err)
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("non-JSON over-budget body was rewritten:\n got %s\nwant %s", out, body)
	}
	if got := pipe.ContentPolicyBlocks(); got != 0 {
		t.Fatalf("content_policy_blocks for a non-JSON passthrough = %d, want 0", got)
	}
}
