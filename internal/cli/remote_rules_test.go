package cli

// End-to-end attribution for the signed remote-rule pack (task T7).
//
// These tests drive the real RunServer path against a genuinely signed pack:
// rules_test.go's harness serves a pack signed by a temporary Ed25519 key over
// TLS, installRulesSeams points the CLI seams at it, and syncTestPack caches
// the verified bytes under a t.TempDir() root so Active() returns the pack at
// startup. Nothing here reads Pro-repo files or the developer's real cache.
//
// The pack carries two redact-action rules:
//
//   - "zz-remote-only" matches the keyword "zzremoteonlytoken": 17 ASCII
//     letters, no digits and none of "+ / _ =", so high_entropy's {28,}
//     candidate floor, its punctuation gate and every built-in prefix are blind
//     to it. Only the remote pack can match it, which makes its log
//     attribution "custom:zz-remote-only" unambiguous (no merged-span
//     tie-break can produce it).
//   - "cfat-vendor-token" matches the real vendor shape cfat_[A-Za-z0-9]{40}.
//     It is only the "a redaction did happen" witness: its replacement is not
//     attributed to the pack, because built-in detectors are expected to match
//     the same span.
//
// The redaction log is the CLI layer's only string channel and run.go installs
// it only when RunDeps.Stderr is non-nil and DisableRedactionLog is false, so
// every test here passes a real buffer and leaves the flag at its zero value.
// The reporter runs on request goroutines, so the buffer is read only after
// stop() has returned: no request goroutine can still be writing.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/rules"
)

// cfatVendorToken is a 40-character token body after the cfat_ prefix, shaped
// like a real vendor credential. Built-in detectors may match it as well; that
// is why it only witnesses that redaction happened.
const cfatVendorToken = "cfat_" + "ABCDEFGHIJ0123456789abcdefghij0123456789"

// remoteRulesPack returns the two-rule pack these tests publish: a keyword rule
// only the remote pack can match, plus a regex for a real vendor token shape.
func remoteRulesPack() rules.Config {
	return rules.Config{
		SchemaVersion: rules.SchemaVersion,
		Rules: []rules.Rule{
			{
				ID: "zz-remote-only", Type: rules.RuleKeyword,
				Keywords: []string{remoteOnlyToken}, Action: "redact",
			},
			{
				ID: "cfat-vendor-token", Type: rules.RuleRegex,
				Pattern: `cfat_[A-Za-z0-9]{40}`, Action: "redact",
			},
		},
	}
}

// remoteRulesBody carries both tokens in one leaf, so a single request
// exercises the keyword rule (attribution) and the regex rule (witness).
func remoteRulesBody() string {
	return fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`,
		remoteOnlyToken+" "+cfatVendorToken)
}

// publishRemotePack serves a genuinely signed pack (temporary Ed25519 key) at
// serial 1 and syncs it through the CLI seams into root, so Active() returns it
// at startup. It returns the backend for request counting.
func publishRemotePack(t *testing.T, root string) *cliBackend {
	t.Helper()
	b := newCLIBackend(t, 1, nil)
	b.publishWithConfig(t, 1, nil, remoteRulesPack())
	installRulesSeams(t, b, root)
	syncTestPack(t)
	return b
}

// TestRemoteRulesE2EAttribution is assertion (i): the pack synced at runtime is
// applied by the real RunServer path, its keyword hit is attributed in the
// captured diagnostics as custom:zz-remote-only, and the upstream-received body
// carries neither raw token — only placeholders.
func TestRemoteRulesE2EAttribution(t *testing.T) {
	publishRemotePack(t, t.TempDir())

	var stderr bytes.Buffer
	upstream, base, stop := startRulesDaemon(t, &stderr)
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json", remoteRulesBody(), nil)
	status := resp.StatusCode
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	received := upstream.received()
	diagnostics := stderr.String()
	t.Logf("diagnostics:\n%s", diagnostics)
	t.Logf("upstream body: %s", received)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !strings.Contains(diagnostics, "custom:zz-remote-only") {
		t.Errorf("diagnostics %q do not attribute a replaced span to custom:zz-remote-only", diagnostics)
	}
	if bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Errorf("upstream received the raw keyword token: %q", received)
	}
	if bytes.Contains(received, []byte(cfatVendorToken)) {
		t.Errorf("upstream received the raw cfat vendor token: %q", received)
	}
	if !runPlaceholderRe.Match(received) {
		t.Errorf("upstream body %q has no placeholder", received)
	}
	if !strings.Contains(string(received), "__PII_custom_zz_remote_only") {
		t.Errorf("upstream body %q lacks the keyword rule's placeholder", received)
	}
}

// TestRemoteRulesNoPackControl is assertions (ii) and (iii): with no active
// pack the identical request produces no custom attribution, and the keyword
// token reaches the upstream byte-for-byte raw with no placeholder minted for
// it — so the pack case above cannot pass on built-in detector behavior.
func TestRemoteRulesNoPackControl(t *testing.T) {
	installNoPackRulesClient(t)

	var stderr bytes.Buffer
	upstream, base, stop := startRulesDaemon(t, &stderr)
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json", remoteRulesBody(), nil)
	status := resp.StatusCode
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	received := upstream.received()
	diagnostics := stderr.String()
	t.Logf("diagnostics:\n%s", diagnostics)
	t.Logf("upstream body: %s", received)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if strings.Contains(diagnostics, "custom:zz-remote-only") {
		t.Errorf("diagnostics %q attribute a hit to custom:zz-remote-only with no pack active", diagnostics)
	}
	if !bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Errorf("control upstream body %q lost the keyword token; only a remote rule can redact it", received)
	}
	if strings.Contains(string(received), "__PII_custom_zz_remote_only") {
		t.Errorf("control upstream body %q contains the remote rule's placeholder with no pack active", received)
	}
}

// TestRemoteRulesTamperedCacheFallsBack is the malformed-input sanity probe:
// the pack is untrusted input, so bytes the issuer did not sign must be
// refused. After a successful sync the cached bundle's keyword is edited
// WITHOUT re-signing; the daemon must then start on the built-in defaults,
// leaving the keyword raw and producing no custom attribution. A bypassed
// verification path would apply the tampered pack and flip both expectations.
func TestRemoteRulesTamperedCacheFallsBack(t *testing.T) {
	root := t.TempDir()
	publishRemotePack(t, root)

	cache, err := rules.OpenFileCache(root)
	if err != nil {
		t.Fatalf("OpenFileCache: %v", err)
	}
	serial, ok, err := cache.Active()
	if err != nil || !ok {
		t.Fatalf("cache.Active() = (%d, %v, %v), want an active serial", serial, ok, err)
	}
	manifest, bundle, err := cache.Load(serial)
	if err != nil {
		t.Fatalf("cache.Load(%d): %v", serial, err)
	}
	var pack rules.Pack
	if err := json.Unmarshal(bundle, &pack); err != nil {
		t.Fatalf("unmarshal cached bundle: %v", err)
	}
	edited := false
	for i := range pack.Rules {
		if pack.Rules[i].ID == "zz-remote-only" {
			pack.Rules[i].Keywords = []string{"attacker-controlled-edit"}
			edited = true
		}
	}
	if !edited {
		t.Fatalf("cached pack has no zz-remote-only rule: %+v", pack.Rules)
	}
	tampered, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal tampered pack: %v", err)
	}
	if err := cache.Save(serial, manifest, tampered); err != nil {
		t.Fatalf("save tampered bundle: %v", err)
	}

	var stderr bytes.Buffer
	upstream, base, stop := startRulesDaemon(t, &stderr)
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json", remoteRulesBody(), nil)
	status := resp.StatusCode
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	received := upstream.received()
	diagnostics := stderr.String()
	t.Logf("diagnostics:\n%s", diagnostics)
	t.Logf("upstream body: %s", received)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Errorf("upstream body %q lost the keyword token; a tampered pack was applied", received)
	}
	if strings.Contains(diagnostics, "custom:zz-remote-only") {
		t.Errorf("diagnostics %q attribute a hit to the tampered pack's rule", diagnostics)
	}
}
