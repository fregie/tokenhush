package cli

// Startup wiring tests: RunServer must apply the cached signed rule pack to the
// assembled pipeline, and startup must perform no egress.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/rules"
)

// remoteOnlyToken is pure ASCII letters, shorter than high_entropy's 28-byte
// candidate floor and free of the punctuation its gate requires, and it bears
// no built-in prefix. Only a remote rule can match it.
const remoteOnlyToken = "zzremoteonlytoken"

// remoteOnlyRules returns a pack whose keyword rule matches remoteOnlyToken.
func remoteOnlyRules() rules.Config {
	return rules.Config{
		SchemaVersion: rules.SchemaVersion,
		Rules: []rules.Rule{{
			ID: "zz-remote-only", Type: rules.RuleKeyword,
			Keywords: []string{remoteOnlyToken}, Action: "redact",
		}},
	}
}

// installNoPackRulesSeam points newRulesClient at an empty temp cache so a test
// that reaches RunServer never reads the developer's real rule cache. T6
// replaces these call-site installs with one default inside startTestDaemon.
func installNoPackRulesSeam(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	previous := newRulesClient
	t.Cleanup(func() { newRulesClient = previous })
	newRulesClient = func(warn func(string)) (*rules.Client, error) {
		cache, err := rules.OpenFileCache(root)
		if err != nil {
			return nil, err
		}
		highWater, err := rules.OpenFileHighWater(filepath.Join(root, "highwater.json"))
		if err != nil {
			return nil, err
		}
		return &rules.Client{
			BaseURL:   rules.DefaultBaseURL,
			Channel:   "stable",
			Verifier:  &rules.Verifier{Keys: rules.DefaultKeys(), CurrentBinaryVersion: Version},
			Cache:     cache,
			HighWater: highWater,
			Warn:      warn,
		}, nil
	}
}

// syncTestPack runs one sync against the installed seam backend so the cache
// under the seam's root holds a verified, active pack.
func syncTestPack(t *testing.T) {
	t.Helper()
	client, err := newRulesClient(func(string) {})
	if err != nil {
		t.Fatalf("newRulesClient: %v", err)
	}
	if _, err := client.Sync(context.Background(), false); err != nil {
		t.Fatalf("sync test pack: %v", err)
	}
}

// startRulesDaemon starts RunServer against a fresh echo upstream and returns
// the upstream, the daemon base URL and the stop function.
func startRulesDaemon(t *testing.T, stderr io.Writer) (*echoUpstream, string, func() error) {
	t.Helper()
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}
	base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: t.TempDir(), Stderr: stderr})
	return upstream, base, stop
}

func remoteOnlyBody() string {
	return fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`, remoteOnlyToken)
}

func TestRunServerInjectsCachedRemoteRules(t *testing.T) {
	b := newCLIBackend(t, 1, nil)
	b.publishWithConfig(t, 1, nil, remoteOnlyRules())
	installRulesSeams(t, b, t.TempDir())
	syncTestPack(t)

	before := b.requests()
	upstream, base, stop := startRulesDaemon(t, &bytes.Buffer{})
	defer func() { _ = stop() }()
	if got := b.requests(); got != before {
		t.Fatalf("startup made %d rule-service requests, want 0", got-before)
	}

	resp := postBody(t, base+"/v1/messages", "application/json", remoteOnlyBody(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	received := upstream.received()
	if bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Fatalf("upstream received the raw remote-only token: %q", received)
	}
	if !runPlaceholderRe.Match(received) {
		t.Fatalf("upstream body %q has no placeholder", received)
	}
}

// TestRunServerWithoutCachedPackLeavesRemoteOnlyTokenRaw is the control: with
// no active pack the very same token reaches the upstream untouched, so the
// replacement above can only come from the remote pack.
func TestRunServerWithoutCachedPackLeavesRemoteOnlyTokenRaw(t *testing.T) {
	b := newCLIBackend(t, 1, nil)
	installRulesSeams(t, b, t.TempDir())

	upstream, base, stop := startRulesDaemon(t, &bytes.Buffer{})
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json", remoteOnlyBody(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	received := upstream.received()
	if !bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Fatalf("control upstream body %q lost the remote-only token", received)
	}
	if runPlaceholderRe.Match(received) {
		t.Fatalf("control upstream body %q contains a placeholder; a built-in detector matched the token", received)
	}
}

// TestRunServerAppliesCachedPackWithSyncDisabled proves the env var only blocks
// sync requests: a pack already cached must still be applied at startup.
func TestRunServerAppliesCachedPackWithSyncDisabled(t *testing.T) {
	t.Setenv(EnvNoRuleSync, "1")

	b := newCLIBackend(t, 1, nil)
	b.publishWithConfig(t, 1, nil, remoteOnlyRules())
	installRulesSeams(t, b, t.TempDir())
	syncTestPack(t)

	upstream, base, stop := startRulesDaemon(t, &bytes.Buffer{})
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json", remoteOnlyBody(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	received := upstream.received()
	if bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Fatalf("upstream received the raw remote-only token despite the cached pack: %q", received)
	}
	if !runPlaceholderRe.Match(received) {
		t.Fatalf("upstream body %q has no placeholder", received)
	}
}

// TestRunServerStartsWithBuiltinsWhenRulesClientFails proves a rules-client
// failure is a warning, not a startup abort.
func TestRunServerStartsWithBuiltinsWhenRulesClientFails(t *testing.T) {
	previous := newRulesClient
	t.Cleanup(func() { newRulesClient = previous })
	newRulesClient = func(func(string)) (*rules.Client, error) {
		return nil, errors.New("rules cache root unavailable")
	}

	var stderr bytes.Buffer
	upstream, base, stop := startRulesDaemon(t, &stderr)
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
	if stderr.Len() == 0 {
		t.Fatal("no rules warning was written to stderr")
	}
	if !strings.Contains(stderr.String(), "rules cache root unavailable") {
		t.Errorf("stderr = %q, want it to name the client failure", stderr.String())
	}
}

func TestIsRulesError(t *testing.T) {
	wrapped := fmt.Errorf("compile remote rules: %w", fmt.Errorf("rule %q: %w", "zz", rules.ErrInvalidRegex))
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "wrapped compile sentinel", err: wrapped, want: true},
		{name: "direct schema sentinel", err: rules.ErrSchemaVersion, want: true},
		{name: "wrapped pack sentinel", err: fmt.Errorf("verify pack: %w", rules.ErrPackMalformed), want: true},
		{name: "placeholder engine error", err: proxy.ErrNilEngine, want: false},
		{name: "bare error", err: errors.New("boom"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRulesError(tt.err); got != tt.want {
				t.Fatalf("isRulesError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
