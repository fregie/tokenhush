package gateway

// Deterministic fail-closed assertions for the remote-rule interpreter at the
// gateway layer (task T9).
//
// The remote pack adds a second scanner over attacker-influenced request
// bodies, so an interpreter failure must abort the request instead of silently
// forwarding it. The failure is triggered by MATCH COUNT, never by a wall
// clock: one keyword rule that produces more than rules.MaxMatches (4096) spans
// makes the interpreter return ErrTooManyMatches — the per-rule keyword trigger
// in pkg/rules/matching.go:61-63 (the regex branch is :38) and the cross-rule
// backstop in pkg/rules/interpreter.go:116-118. Timeouts never enter this path,
// which is exactly why "the same oversized body under a normal timeout" cannot
// serve as a negative control: it always blocks.
//
// Attribution is only reachable at this layer: the policy engine turns the
// interpreter error into the block-forcing finding
// {Type: "plugin_failure", Action: Block, PluginID: id} when the plugin's
// FailurePolicy is FailClosed (pkg/extension/policy.go:219-231, with policyFor
// at :253-258), and failClosedDetectors is what maps rules.DefaultPluginID to
// FailClosed while a pack is active (pkg/gateway/build.go:113-131). The cli
// layer cannot observe PluginID at all; its isolation assertion lives in
// internal/cli/remote_rules_failclosed_test.go.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/rules"
)

const (
	// failClosedKeyword is the T9 pack's only keyword, mirroring the cli
	// fixture's remoteOnlyToken (17 ASCII letters, no digits, none of
	// "+ / _ ="). It bears no built-in prefix, which keeps both layers' packs
	// identical even though the built-ins are disabled here anyway.
	failClosedKeyword = "zzremoteonlytoken"
	// failClosedTriggerMatches sits above rules.MaxMatches with a margin: the
	// interpreter fails on the 4097th span (Inspect passes MaxMatches+1 as the
	// per-rule limit), so 4200 leaves no doubt that the count is the trigger.
	failClosedTriggerMatches = rules.MaxMatches + 104
	// failClosedNormalMatches is the reverse-gate-A count: far below
	// MaxMatches, so the same rule document must redact, never fail.
	failClosedNormalMatches = 5
)

// failClosedRulePack returns the T9 pack: exactly one keyword rule with a
// redact action, no blocklist and no block action. That shape is load-bearing:
// the rule document can never request a Block on its own
// (assertPackCannotBlock), so a Block observed in the oversized case can only
// come from the policy's fail() path for the FailClosed interpreter.
func failClosedRulePack() *rules.Config {
	return &rules.Config{
		SchemaVersion: rules.SchemaVersion,
		Rules: []rules.Rule{{
			ID:       "zz-remote-only",
			Type:     rules.RuleKeyword,
			Keywords: []string{failClosedKeyword},
			Action:   string(extension.Redact),
		}},
	}
}

// assertPackCannotBlock makes the "this pack cannot block" property explicit
// instead of leaving it to a reviewer's eye: no blocklist entry, no block
// action, and the compiled interpreter does not even declare CanBlock.
func assertPackCannotBlock(t *testing.T, cfg *rules.Config) {
	t.Helper()
	if len(cfg.Blocklist) != 0 {
		t.Fatalf("T9 pack carries a blocklist (%v); the negative controls would be vacuous", cfg.Blocklist)
	}
	for _, r := range cfg.Rules {
		if r.Action == string(extension.Block) {
			t.Fatalf("T9 pack rule %q uses a block action; the pack must only warn/redact", r.ID)
		}
	}
	interp, err := rules.Compile(cfg, rules.DefaultOptions())
	if err != nil {
		t.Fatalf("compile T9 pack: %v", err)
	}
	if interp.Capabilities().CanBlock {
		t.Fatalf("T9 pack declares CanBlock; it must be a warn/redact-only document")
	}
}

// failClosedBody renders one JSON request whose terminal leaf holds occurrences
// copies of the keyword.
func failClosedBody(occurrences int) string {
	return fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`,
		strings.Repeat(failClosedKeyword+" ", occurrences))
}

// failClosedPipeline builds the isolated pipeline: every built-in detector is
// disabled, so the remote interpreter is the only registered inspector and a
// Block cannot be attributed to a built-in. The timeout is a normal one
// (extension.DefaultPluginTimeout): the failure is count-driven and completes
// long before any timeout could fire, so timeouts are not part of this proof.
func failClosedPipeline(t *testing.T, cfg *rules.Config) proxy.BodyTransform {
	t.Helper()
	pipeline, err := BuildPipeline(BuildOptions{
		Detectors: []string{},
		Rules:     cfg,
		Timeout:   extension.DefaultPluginTimeout,
	})
	if err != nil {
		t.Fatalf("BuildPipeline: %v", err)
	}
	return pipeline.RequestTransform()
}

// TestRemoteRulesFailClosedAttribution drives the count-driven interpreter
// failure through the real assembled pipeline and pins both the block and its
// attribution: the returned error is a *proxy.BlockedError whose first finding
// is the policy's synthetic failure finding owned by rules.DefaultPluginID
// ("customrules"), with the "error" reason — not a timeout.
func TestRemoteRulesFailClosedAttribution(t *testing.T) {
	cfg := failClosedRulePack()
	assertPackCannotBlock(t, cfg)
	transform := failClosedPipeline(t, cfg)

	body := failClosedBody(failClosedTriggerMatches)
	out, err := transform([]byte(body))
	t.Logf("trigger: occurrences=%d body_bytes=%d transform_out_bytes=%d err=%v",
		failClosedTriggerMatches, len(body), len(out), err)

	var blocked *proxy.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("oversized body transform error = %v, want *proxy.BlockedError", err)
	}
	if len(blocked.Findings) == 0 {
		t.Fatalf("BlockedError carries no findings; the block cannot be attributed")
	}
	if got := blocked.Phase; got != extension.RequestContent {
		t.Errorf("blocked phase = %v, want %v", got, extension.RequestContent)
	}
	if got := blocked.Findings[0].PluginID; got != rules.DefaultPluginID {
		t.Errorf("Findings[0].PluginID = %q, want %q", got, rules.DefaultPluginID)
	}
	if got := blocked.Findings[0].Type; got != "plugin_failure" {
		t.Errorf("Findings[0].Type = %q, want %q", got, "plugin_failure")
	}
	if got := blocked.Findings[0].Action; got != extension.Block {
		t.Errorf("Findings[0].Action = %q, want %q", got, extension.Block)
	}
	// The reason pins the failure to the interpreter's error return: a timeout
	// or a panic would report a different reason, so this also documents that
	// the trigger is the deterministic count-driven path.
	if got, _ := blocked.Findings[0].Meta["reason"].(string); got != extension.FailureReasonError {
		t.Errorf("Findings[0].Meta[reason] = %q, want %q", got, extension.FailureReasonError)
	}
	for i, f := range blocked.Findings {
		if f.PluginID != rules.DefaultPluginID {
			t.Errorf("Findings[%d].PluginID = %q, want %q (built-ins are disabled; only the interpreter is registered)",
				i, f.PluginID, rules.DefaultPluginID)
		}
	}
}

// TestRemoteRulesFailClosedNormalBodyNotBlocked is reverse gate A: the SAME
// pack with a normal body (a handful of matches, far below MaxMatches) under
// the same normal timeout must not block. The redact-action finding proves the
// pack really ran, so the oversized case's Block cannot be explained by the
// pack's rules — only by the policy's fail() path.
func TestRemoteRulesFailClosedNormalBodyNotBlocked(t *testing.T) {
	cfg := failClosedRulePack()
	assertPackCannotBlock(t, cfg)
	transform := failClosedPipeline(t, cfg)

	body := failClosedBody(failClosedNormalMatches)
	out, err := transform([]byte(body))
	t.Logf("normal body: occurrences=%d body_bytes=%d transform_out_bytes=%d err=%v",
		failClosedNormalMatches, len(body), len(out), err)
	if err != nil {
		var blocked *proxy.BlockedError
		if errors.As(err, &blocked) {
			t.Fatalf("normal body (%d matches, below MaxMatches %d) was blocked: %+v",
				failClosedNormalMatches, rules.MaxMatches, blocked)
		}
		t.Fatalf("normal body transform error = %v, want nil", err)
	}
	if !strings.Contains(string(out), "__PII_custom_zz_remote_only") {
		t.Errorf("normal body output has no custom placeholder; the pack's redact rule did not run:\n%s", out)
	}
	if strings.Contains(string(out), failClosedKeyword) {
		t.Errorf("normal body output still contains the raw keyword:\n%s", out)
	}
}
