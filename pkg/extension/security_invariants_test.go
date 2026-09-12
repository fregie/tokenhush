package extension

import (
	"errors"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
)

// TestFailSafeOnDetectorError is the W5.4 named invariant (docs/security.md §2,
// docs/plugins.md): when a critical detector fails — returns an error, panics, or
// times out — the core degrades fail-safe. The request is blocked, never
// silently forwarded, and the failure is audited. A detector failure is folded
// into the Decision; it is never surfaced as an Evaluate error that a caller
// could mistake for "allow".
func TestFailSafeOnDetectorError(t *testing.T) {
	cases := []struct {
		name    string
		insp    *scriptedInspector
		timeout time.Duration
		reason  string
	}{
		{
			name:   "error",
			insp:   &scriptedInspector{id: "critical", caps: policyTestCaps(RequestContent), err: errors.New("detector unavailable")},
			reason: FailureReasonError,
		},
		{
			name:   "panic",
			insp:   &scriptedInspector{id: "critical", caps: policyTestCaps(RequestContent), panicMsg: "detector exploded"},
			reason: FailureReasonPanic,
		},
		{
			name:    "timeout",
			insp:    &scriptedInspector{id: "critical", caps: policyTestCaps(RequestContent), delay: 50 * time.Millisecond},
			timeout: time.Nanosecond,
			reason:  FailureReasonTimeout,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recordingSink{}
			reg := NewRegistry()
			if err := reg.Register(tc.insp); err != nil {
				t.Fatalf("Register(critical) error = %v", err)
			}
			// A permissive inspector must not be able to outvote the block.
			if err := reg.Register(&scriptedInspector{id: "ok", caps: policyTestCaps(RequestContent)}); err != nil {
				t.Fatalf("Register(ok) error = %v", err)
			}

			got, err := NewPolicy(reg, PolicyConfig{
				Sink:     sink,
				Timeout:  tc.timeout,
				Failures: map[string]FailurePolicy{"critical": FailClosed},
			}).Evaluate(policyTestDoc())
			if err != nil {
				t.Fatalf("Evaluate() error = %v; a detector failure must degrade inside the Decision, not surface as an error", err)
			}
			if !got.Blocks() || got.Action != Block {
				t.Fatalf("Action = %s blocks = %v, want Block (fail-safe on detector failure)", got.Action, got.Blocks())
			}

			// A 1ns deadline times out every inspector, so the timeout case may
			// carry an extra warning for the permissive inspector; the critical
			// failure must always be among the audited rows.
			recs := sink.snapshot()
			var critical *audit.Record
			for i := range recs {
				if len(recs[i].Detectors) == 3 && recs[i].Detectors[1] == "critical" {
					critical = &recs[i]
				}
			}
			if critical == nil {
				t.Fatalf("no critical fail-safe warning among %d audit rows", len(recs))
			}
			assertPolicyWarning(t, *critical, "critical", tc.reason)
			t.Logf("detector %s -> action=%s blocks=%v audit_reason=%q audit_rows=%d",
				tc.name, got.Action, got.Blocks(), critical.Detectors[2], len(recs))
		})
	}
}
