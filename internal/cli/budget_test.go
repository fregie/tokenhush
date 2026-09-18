// budget_test.go is the B-fix acceptance for the detector budget. It drives the
// REAL run gateway over a loopback echo upstream and asserts on captured bytes:
// a ~1.5 MB single leaf whose secret sits past the old fixed 1 MiB cap is
// redacted because the per-primitive budget now follows scan_budget_bytes; a
// leaf past a deliberately small budget is not redacted, emits exactly one
// metadata-only `detector budget exceeded` stderr line, and moves no status
// key.
package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
)

// budgetExceededPrefix is the frozen prefix of the budget-report line.
const budgetExceededPrefix = "tokenhush: detector budget exceeded"

// TestE2ELargeLeafSecretIsRedacted is the regression for the finding: before
// the fix the built-in primitives truncated at a fixed 1 MiB, so a secret in a
// 1.5 MB leaf was forwarded unredacted and silently. With the budget aligned to
// scan_budget_bytes it is redacted, counted and restored.
func TestE2ELargeLeafSecretIsRedacted(t *testing.T) {
	upstream := newE2EUpstream(t)
	base, logs, dataDir := redactGateway(t, upstream)
	token := readControlToken(t, dataDir)

	secret := e2eSecret(t)
	content := strings.Repeat("A", 1536*1024) + " " + secret
	if len(content) <= 1<<20 {
		t.Fatalf("the fixture leaf (%d bytes) must exceed the old 1 MiB cap", len(content))
	}
	before := readLiveCounters(t, base, token)
	status, got := e2ePostTimeout(t, base+e2ePath, redactJSONBody(t, content), nil, 120*time.Second)
	if status != http.StatusOK {
		t.Fatalf("POST = %d, want 200 (body %s)", status, got)
	}
	sent := upstream.recorded()
	if bytes.Contains(sent, []byte(secret)) {
		t.Errorf("the secret at the end of a 1.5 MB leaf left the process: %d bytes captured", len(sent))
	}
	if !bytes.Contains(sent, []byte("__PII_email_")) {
		t.Errorf("no placeholder reached the upstream: the large leaf was not redacted")
	}
	if delta := readLiveCounters(t, base, token).Redactions - before.Redactions; delta != 1 {
		t.Errorf("redactions moved by %d, want exactly 1", delta)
	}
	if !bytes.Contains(got, []byte(secret)) {
		t.Errorf("the original secret did not return to the client")
	}
	if logs.count(budgetExceededPrefix) != 0 {
		t.Errorf("the default budget (scan_budget_bytes) was reported exceeded: %s", logs.String())
	}
}

// TestE2EBudgetExceededIsObservable pins the residual contract on the one
// request shape that reaches the transform over budget: a valid JSON body that
// does not DECLARE JSON, so the data-plane gate forwards it and the transform
// still walks it. The leaf longer than the effective budget produces exactly
// one metadata-only stderr line and moves no status key, while the unredacted
// bytes still leave for the upstream.
func TestE2EBudgetExceededIsObservable(t *testing.T) {
	upstream := newE2EUpstream(t)
	const budget = 64
	base, logs, dataDir := redactGatewayTuned(t, upstream, func(cfg *config.Config) {
		cfg.ScanBudgetBytes = budget
	})
	token := readControlToken(t, dataDir)

	secret := e2eSecret(t)
	content := strings.Repeat("B", 200) + " " + secret
	before := readLiveCounters(t, base, token)
	status, got := e2ePost(t, base+e2ePath, redactJSONBody(t, content), map[string]string{"Content-Type": "text/plain"})
	if status != http.StatusOK {
		t.Fatalf("POST = %d, want 200 (body %s)", status, got)
	}
	sent := upstream.recorded()
	if bytes.Contains(sent, []byte("__PII_")) {
		t.Errorf("a leaf past the budget minted a placeholder: %d bytes captured", len(sent))
	}
	if !bytes.Contains(sent, []byte(secret)) {
		t.Errorf("a secret past the budget was silently altered")
	}
	if count := logs.count(budgetExceededPrefix); count != 1 {
		t.Fatalf("detector budget lines = %d, want exactly 1 (stderr: %s)", count, logs.String())
	}
	wantLine := fmt.Sprintf("%s leaf=%d budget=%d", budgetExceededPrefix, len(content), budget)
	if !strings.Contains(logs.String(), wantLine) {
		t.Errorf("stderr does not carry %q: %s", wantLine, logs.String())
	}
	after := readLiveCounters(t, base, token)
	if after.Redactions != before.Redactions || after.WalkSkips != before.WalkSkips ||
		after.ContentPolicyBlocks != before.ContentPolicyBlocks || after.RuleBlocks != before.RuleBlocks {
		t.Errorf("a budget report moved a status key: before %+v after %+v", before, after)
	}
	if bytes.Contains(got, []byte("__PII_")) {
		t.Errorf("a placeholder reached the client for an over-budget leaf")
	}
}
