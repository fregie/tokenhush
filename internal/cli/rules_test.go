package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/rules"
)

// cliBackend serves signed rule manifests and bundles over TLS for the CLI
// tests. The serial is mutable so a test can publish a newer pack.
type cliBackend struct {
	srv  *httptest.Server
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey

	hits atomic.Int64

	mu          sync.Mutex
	manifest    []byte
	bundle      []byte
	revocations []byte
}

// cliNow is the fixed clock the CLI rule tests verify freshness against.
var cliNow = time.Unix(1_800_000_000, 0)

func newCLIBackend(t *testing.T, serial uint64, revoked []uint64) *cliBackend {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b := &cliBackend{pub: pub, priv: priv}
	b.publish(t, serial, revoked)
	mux := http.NewServeMux()
	mux.HandleFunc(rules.ManifestPath, func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		b.mu.Lock()
		body := b.manifest
		b.mu.Unlock()
		_, _ = w.Write(body)
	})
	mux.HandleFunc(rules.BundlePath, func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		b.mu.Lock()
		body := b.bundle
		b.mu.Unlock()
		_, _ = w.Write(body)
	})
	mux.HandleFunc(rules.RevocationsPath, func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		b.mu.Lock()
		body := b.revocations
		b.mu.Unlock()
		_, _ = w.Write(body)
	})
	b.srv = httptest.NewTLSServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

// requests reports how many rule-service requests this backend has served, so
// a test can prove a code path performed no egress.
func (b *cliBackend) requests() int64 { return b.hits.Load() }

// publish serves the default test pack: one warn-action ticket regex rule,
// which never reaches the redaction pipeline and therefore cannot change the
// data plane.
func (b *cliBackend) publish(t *testing.T, serial uint64, revoked []uint64) {
	t.Helper()
	b.publishWithConfig(t, serial, revoked, rules.Config{
		SchemaVersion: rules.SchemaVersion,
		Rules: []rules.Rule{{
			ID: "ticket", Type: rules.RuleRegex, Pattern: `PROJ-[0-9]{4,}`, Action: "warn",
		}},
	})
}

// publishWithConfig signs and serves cfg as the pack at serial.
func (b *cliBackend) publishWithConfig(t *testing.T, serial uint64, revoked []uint64, cfg rules.Config) {
	t.Helper()
	pack := rules.Pack{
		Channel:          "stable",
		MinBinaryVersion: "0.3.0",
		Serial:           serial,
		KeyID:            "rules-cli-test",
		NotBefore:        cliNow.Add(-time.Hour),
		Expires:          cliNow.Add(24 * time.Hour),
		Config:           cfg,
	}
	pack.Signature = signB64(b.priv, rules.PackSigningInput(pack))
	bundle, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	sum := sha256.Sum256(bundle)
	manifest := rules.Manifest{
		Channel:          "stable",
		SchemaVersion:    rules.SchemaVersion,
		MinBinaryVersion: "0.3.0",
		Serial:           serial,
		KeyID:            "rules-cli-test",
		NotBefore:        cliNow.Add(-time.Hour),
		Expires:          cliNow.Add(24 * time.Hour),
		BundleSHA256:     hex.EncodeToString(sum[:]),
		Bundle:           "rules/stable/pack.json",
		RevokedSerials:   revoked,
	}
	manifest.Signature = signB64(b.priv, rules.ManifestSigningInput(manifest))
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	revocations := rules.RevocationList{
		Channel:   "stable",
		Serial:    1,
		KeyID:     "rules-cli-test",
		NotBefore: cliNow.Add(-time.Hour),
		Expires:   cliNow.Add(24 * time.Hour),
	}
	revocations.Signature = signB64(b.priv, rules.RevocationSigningInput(revocations))
	rawRevocations, err := json.Marshal(revocations)
	if err != nil {
		t.Fatalf("marshal revocations: %v", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.manifest, b.bundle, b.revocations = rawManifest, bundle, rawRevocations
}

func signB64(priv ed25519.PrivateKey, input []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, input))
}

// installRulesSeams points the CLI at backend b and a temp cache root through
// the canonical test override, which restores the seam on cleanup.
func installRulesSeams(t *testing.T, b *cliBackend, root string) {
	t.Helper()
	cache, err := rules.OpenFileCache(root)
	if err != nil {
		t.Fatalf("OpenFileCache: %v", err)
	}
	hw, err := rules.OpenFileHighWater(filepath.Join(root, "highwater.json"))
	if err != nil {
		t.Fatalf("OpenFileHighWater: %v", err)
	}
	installTestRulesClient(t, &rules.Client{
		BaseURL: b.srv.URL,
		Channel: "stable",
		Verifier: &rules.Verifier{
			Keys:                 []rules.Key{{ID: "rules-cli-test", Public: b.pub}},
			CurrentBinaryVersion: "0.4.0",
			Now:                  func() time.Time { return cliNow },
		},
		Cache:      cache,
		HighWater:  hw,
		HTTPClient: b.srv.Client(),
	})
}

func TestRulesSyncInstallsAndReports(t *testing.T) {
	b := newCLIBackend(t, 7, nil)
	root := t.TempDir()
	installRulesSeams(t, b, root)

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"rules", "sync"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("rules sync exit = %d (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated to serial 7") {
		t.Fatalf("stdout = %q, want updated serial 7", stdout.String())
	}
}

func TestRulesSyncCheckWritesNothing(t *testing.T) {
	b := newCLIBackend(t, 7, nil)
	root := t.TempDir()
	installRulesSeams(t, b, root)

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"rules", "sync", "--check"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("rules sync --check exit = %d (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "update available") {
		t.Fatalf("stdout = %q, want update available", stdout.String())
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("--check wrote %d entries, want 0", len(entries))
	}
}

func TestRulesSyncOfflineUsesCache(t *testing.T) {
	b := newCLIBackend(t, 7, nil)
	root := t.TempDir()
	installRulesSeams(t, b, root)

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"rules", "sync"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("first sync exit = %d", code)
	}
	b.srv.Close()
	stdout.Reset()
	stderr.Reset()

	if code := Run([]string{"rules", "sync"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("offline sync exit = %d (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "offline; using cached serial 7") {
		t.Fatalf("stdout = %q, want cached serial 7", stdout.String())
	}
}

// TestRulesSyncBadSignatureFails is the CLI failure acceptance: a tampered pack
// is rejected with a non-zero exit and a visible fallback warning.
func TestRulesSyncBadSignatureFails(t *testing.T) {
	b := newCLIBackend(t, 7, nil)
	root := t.TempDir()
	installRulesSeams(t, b, root)

	// Flip the manifest bundle path without re-signing: valid JSON, bad sig.
	var m rules.Manifest
	b.mu.Lock()
	if err := json.Unmarshal(b.manifest, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m.Bundle = "rules/stable/tampered.json"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b.manifest = raw
	b.mu.Unlock()

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"rules", "sync"}, &stdout, &stderr); code != ExitFailure {
		t.Fatalf("bad-signature sync exit = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "falling back") {
		t.Fatalf("stderr = %q, want fallback warning", stderr.String())
	}
}

func TestRulesRollback(t *testing.T) {
	b := newCLIBackend(t, 5, nil)
	root := t.TempDir()
	installRulesSeams(t, b, root)

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"rules", "sync"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("sync 5 exit = %d (stderr %q)", code, stderr.String())
	}
	b.publish(t, 7, nil)
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"rules", "sync"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("sync 7 exit = %d (stderr %q)", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	if code := Run([]string{"rules", "rollback"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("rollback exit = %d (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "active serial 5") {
		t.Fatalf("rollback stdout = %q, want active serial 5", stdout.String())
	}
}

func TestRulesUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"rules"}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("rules exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "Usage of rules") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"rules", "bogus"}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("rules bogus exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "unknown subcommand") {
		t.Fatalf("stderr = %q, want unknown subcommand", stderr.String())
	}
}

// TestRulesSyncDisabledByEnv proves the disclosed off switch: with
// TOKENHUSH_NO_RULE_SYNC set, `rules sync` returns before any client is built,
// so no network request can leave the machine.
func TestRulesSyncDisabledByEnv(t *testing.T) {
	t.Setenv(EnvNoRuleSync, "1")
	installTestRulesClientFunc(t, func(func(string)) (*rules.Client, error) {
		t.Fatal("rules sync built a client despite TOKENHUSH_NO_RULE_SYNC")
		return nil, nil
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"rules", "sync"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("disabled rules sync exit = %d (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "disabled by "+EnvNoRuleSync) {
		t.Fatalf("stdout = %q, want the disabled notice", stdout.String())
	}
}
