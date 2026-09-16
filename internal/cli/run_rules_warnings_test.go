package cli

// Warning-path regressions for the rules startup wiring (fix round 1):
//
//   - TestRunServerNilStderrRulesFallbackDoesNotPanic locks the nil-writer
//     guard in ruleWarn. RunDeps.Stderr is optional, and both fallback paths
//     must drop their warning when it is nil — never panic, never divert to
//     Stdout. Without a committed driver, deleting the guard left the package
//     green and re-introduced the startup panic silently.
//   - TestRunServerBadPackWarningDeduplicated locks the startup finding that a
//     bad-but-active pack is reported through two channels (the client Warn
//     callback and ActiveRules.Warnings) and that production's newRulesClient
//     wires the callback to the same sink. Startup must print each distinct
//     fallback line exactly once, with exactly one `tokenhush: ` prefix.
//
// Both tests read the diagnostics buffer only after stop() returned, when no
// request goroutine can still write to it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/rules"
)

// startRulesDaemonStreams is startRulesDaemon with both RunDeps streams under
// the test's control, so a test can pass a nil Stderr and still assert that
// Stdout stays clean. The config mirrors startRulesDaemon exactly.
func startRulesDaemonStreams(t *testing.T, stdout, stderr io.Writer) (*echoUpstream, string, func() error) {
	t.Helper()
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}
	base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: t.TempDir(), Stdout: stdout, Stderr: stderr})
	return upstream, base, stop
}

// damageActivePack re-signs the active pack with the harness key after editing
// its keyword rule: signature, freshness and schema still pass while the
// unchanged cached manifest no longer hashes the bundle, so every startup
// rejects it at the manifest/bundle integrity binding. It is the same tamper
// as TestBadPackFallback/corrupt_cached_bytes.
func damageActivePack(t *testing.T, b *cliBackend, cache *rules.FileCache) {
	t.Helper()
	serial, manifest, bundle := activePackBytes(t, cache)
	var pack rules.Pack
	if err := json.Unmarshal(bundle, &pack); err != nil {
		t.Fatalf("unmarshal cached bundle: %v", err)
	}
	edited := false
	for i := range pack.Rules {
		if pack.Rules[i].ID == "zz-remote-only" {
			pack.Rules[i].Keywords = append(pack.Rules[i].Keywords, "warning-path-tamper-marker")
			edited = true
		}
	}
	if !edited {
		t.Fatalf("cached pack has no zz-remote-only rule: %+v", pack.Rules)
	}
	if err := cache.Save(serial, manifest, signPackBytes(t, b.priv, pack)); err != nil {
		t.Fatalf("save damaged bundle: %v", err)
	}
}

// TestRunServerNilStderrRulesFallbackDoesNotPanic drives both rules-warning
// paths with RunDeps.Stderr == nil: the newRulesClient-error path and the
// present-but-unusable-pack path (Active() warning channel). Each must still
// become ready and serve a 200, and the warning must not surface on Stdout.
func TestRunServerNilStderrRulesFallbackDoesNotPanic(t *testing.T) {
	t.Run("rules_client_error", func(t *testing.T) {
		installTestRulesClientFunc(t, func(func(string)) (*rules.Client, error) {
			return nil, errors.New("nil-stderr test: rules cache root unavailable")
		})

		var stdout bytes.Buffer
		upstream, base, stop := startRulesDaemonStreams(t, &stdout, nil)
		defer func() { _ = stop() }()

		resp := postBody(t, base+"/v1/messages", "application/json", remoteOnlyBody(), nil)
		status := resp.StatusCode
		received := upstream.received()
		if err := stop(); err != nil {
			t.Fatalf("RunServer returned %v after cancel, want nil", err)
		}

		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if !bytes.Contains(received, []byte(remoteOnlyToken)) {
			t.Fatalf("upstream body %q lost the token with no rules active", received)
		}
		if strings.Contains(stdout.String(), "using built-in defaults") {
			t.Errorf("Stdout = %q, want the rules warning kept off Stdout", stdout.String())
		}
	})

	t.Run("unusable_active_pack", func(t *testing.T) {
		root := t.TempDir()
		b := publishRemotePack(t, root)
		cache := openTestCache(t, root)
		damageActivePack(t, b, cache)

		var stdout bytes.Buffer
		upstream, base, stop := startRulesDaemonStreams(t, &stdout, nil)
		defer func() { _ = stop() }()

		resp := postBody(t, base+"/v1/messages", "application/json", remoteOnlyBody(), nil)
		status := resp.StatusCode
		received := upstream.received()
		if err := stop(); err != nil {
			t.Fatalf("RunServer returned %v after cancel, want nil", err)
		}

		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if !bytes.Contains(received, []byte(remoteOnlyToken)) {
			t.Fatalf("upstream body %q lost the token; the damaged pack was applied", received)
		}
		if strings.Contains(stdout.String(), "using built-in defaults") {
			t.Errorf("Stdout = %q, want the rules warning kept off Stdout", stdout.String())
		}
	})
}

// TestRunServerBadPackWarningDeduplicated asserts that a damaged-but-active
// pack prints its fallback line exactly once, prefixed with exactly one
// `tokenhush: `. The seam here is deliberately production-shaped (it wires
// RunServer's warn sink itself): installTestRulesClient would let the
// prepopulation sync claim the client's Warn slot with a discard, which masks
// the callback channel and makes the assertion vacuous.
func TestRunServerBadPackWarningDeduplicated(t *testing.T) {
	root := t.TempDir()
	b := newCLIBackend(t, 1, nil)
	b.publishWithConfig(t, 1, nil, remoteRulesPack())
	cache := openTestCache(t, root)
	highWater, err := rules.OpenFileHighWater(filepath.Join(root, "highwater.json"))
	if err != nil {
		t.Fatalf("OpenFileHighWater: %v", err)
	}
	installTestRulesClientFunc(t, func(warn func(string)) (*rules.Client, error) {
		return &rules.Client{
			BaseURL: b.srv.URL,
			Channel: "stable",
			Verifier: &rules.Verifier{
				Keys:                 []rules.Key{{ID: "rules-cli-test", Public: b.pub}},
				CurrentBinaryVersion: "0.4.0",
				Now:                  func() time.Time { return cliNow },
			},
			Cache:      cache,
			HighWater:  highWater,
			HTTPClient: b.srv.Client(),
			Warn:       warn,
		}, nil
	})

	// Prepopulate the cache through a separate client instance so the
	// daemon's own instance is constructed with Warn still awaiting the
	// RunServer sink, exactly as in production.
	syncer, err := newRulesClient(func(string) {})
	if err != nil {
		t.Fatalf("newRulesClient: %v", err)
	}
	if _, err := syncer.Sync(context.Background(), false); err != nil {
		t.Fatalf("sync test pack: %v", err)
	}
	damageActivePack(t, b, cache)

	var stderr bytes.Buffer
	upstream, base, stop := startRulesDaemon(t, &stderr)
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json", remoteOnlyBody(), nil)
	status := resp.StatusCode
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	received := upstream.received()
	diagnostics := stderr.String()
	t.Logf("diagnostics:\n%s", diagnostics)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Fatalf("upstream body %q lost the token; the damaged pack was applied", received)
	}
	fallbackLines := 0
	for _, line := range strings.Split(diagnostics, "\n") {
		if !strings.Contains(line, "using built-in defaults") {
			continue
		}
		fallbackLines++
		if !strings.HasPrefix(line, "tokenhush: ") {
			t.Errorf("fallback line %q lacks the tokenhush: prefix", line)
		}
		if strings.HasPrefix(line, "tokenhush: tokenhush: ") {
			t.Errorf("fallback line %q is double-prefixed", line)
		}
	}
	if fallbackLines != 1 {
		t.Errorf("fallback warning printed %d times, want exactly 1:\n%s", fallbackLines, diagnostics)
	}
}
