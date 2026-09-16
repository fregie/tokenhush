package cli

// Deterministic fail-closed isolation for the remote-rule interpreter at the
// cli layer (task T9).
//
// This is the isolation half of the two-layer proof. Every built-in detector is
// disabled (cfg.Detectors = config.Detectors{}), so the synced pack's
// interpreter (rules.DefaultPluginID, "customrules") is the ONLY registered
// inspector; a Block observed here is therefore attributable by elimination.
// The trigger is count-driven, never a wall-clock race: a body with more than
// rules.MaxMatches (4096) keyword occurrences makes the interpreter return
// ErrTooManyMatches (pkg/rules/matching.go:61-63; cross-rule backstop
// pkg/rules/interpreter.go:116-118), the FailClosed policy converts that error
// into a Block (pkg/extension/policy.go:219-231), and the request is rejected
// with 403 before any upstream dial.
//
// The cli layer cannot observe PluginID — that attribution is asserted at the
// gateway layer in pkg/gateway/remote_rules_failclosed_test.go. Here the claim
// is exactly: 403 + zero upstream hits, with the pack provably applied (reverse
// gate A shows the same pack redacting a normal body).
//
// The pack is the same shape as the gateway fixture: exactly one keyword rule,
// action redact, no blocklist, no block action (assertFailClosedPackOnlyRedacts).

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/rules"
)

// failClosedTriggerMatches is deliberately above rules.MaxMatches with a
// margin: the interpreter fails on the 4097th span, so 4200 leaves no doubt
// that the match count is the trigger.
const failClosedTriggerMatches = rules.MaxMatches + 104

// failClosedNormalMatches is the reverse-gate-A count: far below MaxMatches, so
// the same pack must redact, never fail.
const failClosedNormalMatches = 5

// failClosedRulesPack mirrors the gateway T9 pack: exactly one keyword rule
// with a redact action, no blocklist and no block action. remoteOnlyToken is
// the cli fixture's pure-letter token, invisible to every built-in detector;
// here that only keeps the two layers' packs identical, since the built-ins are
// disabled anyway.
func failClosedRulesPack() rules.Config {
	return rules.Config{
		SchemaVersion: rules.SchemaVersion,
		Rules: []rules.Rule{{
			ID: "zz-remote-only", Type: rules.RuleKeyword,
			Keywords: []string{remoteOnlyToken}, Action: "redact",
		}},
	}
}

// assertFailClosedPackOnlyRedacts makes the "this pack cannot block" property
// explicit: a block action or a blocklist entry would make the negative
// controls vacuous, so the test refuses to run such a pack.
func assertFailClosedPackOnlyRedacts(t *testing.T, cfg rules.Config) {
	t.Helper()
	if len(cfg.Blocklist) != 0 {
		t.Fatalf("T9 pack carries a blocklist (%v); the negative controls would be vacuous", cfg.Blocklist)
	}
	for _, r := range cfg.Rules {
		if r.Action == "block" {
			t.Fatalf("T9 pack rule %q uses a block action; the pack must only warn/redact", r.ID)
		}
	}
}

// publishFailClosedPack serves the T9 pack (temporary Ed25519 key, serial 1)
// and syncs it through the CLI seams into root, so Active() returns it at
// startup.
func publishFailClosedPack(t *testing.T, root string) *cliBackend {
	t.Helper()
	cfg := failClosedRulesPack()
	assertFailClosedPackOnlyRedacts(t, cfg)
	b := newCLIBackend(t, 1, nil)
	b.publishWithConfig(t, 1, nil, cfg)
	installRulesSeams(t, b, root)
	syncTestPack(t)
	return b
}

// startFailClosedDaemon starts RunServer with EVERY built-in detector disabled,
// which makes the pack's interpreter the only inspector. The upstream, base URL
// and stop function follow startRulesDaemon.
func startFailClosedDaemon(t *testing.T, stderr io.Writer) (*echoUpstream, string, func() error) {
	t.Helper()
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}
	// The isolation contract: no built-in detector is registered, so the 403
	// under test cannot be produced by one.
	cfg.Detectors = config.Detectors{}
	base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: t.TempDir(), Stderr: stderr})
	return upstream, base, stop
}

// failClosedBody renders one JSON request whose terminal leaf holds occurrences
// copies of the remote-only keyword.
func failClosedBody(occurrences int) string {
	return fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`,
		strings.Repeat(remoteOnlyToken+" ", occurrences))
}

// TestRemoteRulesFailClosedIsolation is the cli-layer acceptance: with all
// built-ins disabled and the pack active, the oversized body is rejected with
// 403 and the upstream is never dialed. The captured diagnostics may not carry
// PluginID (unreachable here) but must show the policy-failure block line, so
// the 403 is also observable as a plugin_failure decision rather than a generic
// error.
func TestRemoteRulesFailClosedIsolation(t *testing.T) {
	publishFailClosedPack(t, t.TempDir())

	var stderr bytes.Buffer
	upstream, base, stop := startFailClosedDaemon(t, &stderr)
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json",
		failClosedBody(failClosedTriggerMatches), nil)
	status := resp.StatusCode
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	diagnostics := stderr.String()
	t.Logf("status: %d", status)
	t.Logf("diagnostics:\n%s", diagnostics)
	t.Logf("upstream hits: %d", upstream.hits.Load())

	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (diagnostics:\n%s)", status, diagnostics)
	}
	if got := upstream.hits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0: a blocked request must never reach upstream", got)
	}
	if !strings.Contains(diagnostics, "by content policy: plugin_failure") {
		t.Errorf("diagnostics do not show a plugin_failure block; the 403 is not attributable to the policy failure path:\n%s", diagnostics)
	}
}

// TestRemoteRulesFailClosedNormalBodyAllowed is reverse gate A at the cli
// layer: the SAME pack with a normal body (a handful of matches, far below
// MaxMatches) under the same normal timeout must not be blocked. The placeholder
// in the upstream-received body proves the pack really ran, so the 403 in the
// oversized case cannot be produced by the pack's rules themselves.
func TestRemoteRulesFailClosedNormalBodyAllowed(t *testing.T) {
	publishFailClosedPack(t, t.TempDir())

	var stderr bytes.Buffer
	upstream, base, stop := startFailClosedDaemon(t, &stderr)
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json",
		failClosedBody(failClosedNormalMatches), nil)
	status := resp.StatusCode
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	received := upstream.received()
	t.Logf("diagnostics:\n%s", stderr.String())
	t.Logf("upstream body: %s", received)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got := upstream.hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1: the normal body must be forwarded", got)
	}
	if bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Errorf("upstream received the raw keyword token; the pack's redact rule did not run: %q", received)
	}
	if !strings.Contains(string(received), "__PII_custom_zz_remote_only") {
		t.Errorf("upstream body %q lacks the pack rule's placeholder", received)
	}
}
