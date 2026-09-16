package cli

// Restart semantics for the cached remote rule pack (task T10).
//
// RunServer reads the pack exactly once, inside the `if pipeline == nil` block
// that assembles the pipeline at startup, so a `rules sync` performed while the
// daemon is running cannot change its behaviour: the new pack only takes effect
// in the next process. This file pins that one-shot contract behaviourally,
// with the running daemon's own behaviour as the load-bearing assertion.

import (
	"bytes"
	"net/http"
	"testing"
)

// postKeywordToken posts remoteOnlyBody to base and returns the body the echo
// upstream received, failing unless the request was served with a 200. The echo
// upstream records the body before it writes the response, so reading after Do
// returns is race-free.
func postKeywordToken(t *testing.T, upstream *echoUpstream, base string) []byte {
	t.Helper()
	resp := postBody(t, base+"/v1/messages", "application/json", remoteOnlyBody(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s = %d, want 200", base+"/v1/messages", resp.StatusCode)
	}
	return upstream.received()
}

// TestRemoteRulesApplyOnceRestartRequired runs the whole contract in one test:
//
//  1. Daemon A starts against a cache root that is still empty — the pack is
//     published on the local fake backend but never synced — so only built-in
//     detectors act: the remote-only keyword token reaches the upstream RAW and
//     no placeholder is minted for it.
//  2. `rules sync` runs through the installed seam while A is STILL RUNNING and
//     writes the verified pack into A's cache root.
//  3. A serves the same request again with UNCHANGED behaviour: the token is
//     still raw upstream and still has no placeholder. This is the
//     no-hot-reload assertion; a mid-run pipeline rebuild would flip it.
//  4. A is stopped and B starts against the same seam and cache root; the same
//     request now reaches the upstream WITHOUT the raw token and WITH the
//     __PII_custom_zz_remote_only placeholder — the restart applied the pack.
//
// The final cross-assertion compares A's post-sync body with B's body, so the
// observable restart difference itself is asserted, not two isolated claims.
func TestRemoteRulesApplyOnceRestartRequired(t *testing.T) {
	b := newCLIBackend(t, 1, nil)
	b.publishWithConfig(t, 1, nil, remoteOnlyRules())
	root := t.TempDir()
	installRulesSeams(t, b, root)

	// Step 1: A starts with an empty cache -> built-in behavior.
	var stderrA bytes.Buffer
	upstreamA, baseA, stopA := startRulesDaemon(t, &stderrA)
	defer func() { _ = stopA() }()

	beforeSync := postKeywordToken(t, upstreamA, baseA)
	t.Logf("step 1: A (empty cache) upstream body = %s", beforeSync)
	if !bytes.Contains(beforeSync, []byte(remoteOnlyToken)) {
		t.Fatalf("A (empty cache) lost the raw keyword token: %q", beforeSync)
	}
	if runPlaceholderRe.Match(beforeSync) {
		t.Fatalf("A (empty cache) minted a placeholder with no active pack: %q", beforeSync)
	}

	// Step 2: sync while A is still running.
	syncTestPack(t)
	t.Logf("step 2: syncTestPack activated the pack under %s while A kept running", root)

	// Step 3: A's behavior is unchanged after the sync.
	afterSyncInA := postKeywordToken(t, upstreamA, baseA)
	t.Logf("step 3: A (still running, after sync) upstream body = %s", afterSyncInA)
	if !bytes.Contains(afterSyncInA, []byte(remoteOnlyToken)) {
		t.Fatalf("running A lost the raw keyword token after the sync: %q", afterSyncInA)
	}
	if runPlaceholderRe.Match(afterSyncInA) {
		t.Fatalf("running A minted a placeholder after the sync; the pipeline was rebuilt mid-run: %q", afterSyncInA)
	}

	// Step 4: stop A; B, started after the sync, applies the pack.
	if err := stopA(); err != nil {
		t.Fatalf("RunServer A returned %v after cancel, want nil", err)
	}
	t.Logf("step 4: A diagnostics after stop = %q", stderrA.String())

	var stderrB bytes.Buffer
	upstreamB, baseB, stopB := startRulesDaemon(t, &stderrB)
	defer func() { _ = stopB() }()

	restarted := postKeywordToken(t, upstreamB, baseB)
	if err := stopB(); err != nil {
		t.Fatalf("RunServer B returned %v after cancel, want nil", err)
	}
	diagnosticsB := stderrB.String()
	t.Logf("step 4: B (after sync) upstream body = %s", restarted)
	t.Logf("step 4: B diagnostics = %s", diagnosticsB)

	rawInA := bytes.Contains(afterSyncInA, []byte(remoteOnlyToken))
	rawInB := bytes.Contains(restarted, []byte(remoteOnlyToken))
	if rawInA == rawInB {
		t.Fatalf("A and B behaved identically (keyword raw = %v): A body %q; B body %q (diagnostics %q)",
			rawInA, afterSyncInA, restarted, diagnosticsB)
	}
	if !bytes.Contains(restarted, []byte("__PII_custom_zz_remote_only")) {
		t.Fatalf("B body %q lacks the keyword rule's placeholder (diagnostics %q)", restarted, diagnosticsB)
	}
	if !runPlaceholderRe.Match(restarted) {
		t.Fatalf("B body %q has no placeholder", restarted)
	}
}
