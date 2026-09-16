package cli

// Fallback matrix for a damaged-but-ACTIVE cached rule pack (task T8).
//
// Active() re-verifies the cached bytes on every startup and never returns an
// error for a bad pack: every problem becomes a warning plus the built-in
// defaults (pkg/rules/activate.go). The observable contract of a damaged cache
// entry is therefore "the daemon starts anyway, warns, uses the built-ins and
// loads no remote rule". This file pins that contract for the four ways a pack
// can be unusable:
//
//   - corrupt_cached_bytes: the bundle no longer hashes to the bundle_sha256
//     the cached manifest points at. The bundle is re-signed with the harness
//     key so signature, freshness and schema checks still pass: the rejection
//     must come from the manifest/bundle integrity binding itself.
//   - bad_signature: the bundle carries a valid base64 signature made with a
//     different Ed25519 key while the key id still names the trusted harness
//     key.
//   - bad_schema_version: a hand-built, correctly signed pack claiming
//     schema_version 2. publishWithConfig always stamps the supported version,
//     so this fixture cannot come from it; the manifest is schema 1 and hashes
//     the bundle, so the flow reaches pack validation, whose schema check is
//     the same one rules.Compile applies.
//   - rules_client_error: newRulesClient itself fails (the cache root cannot be
//     created). This is the only case driven through an error return rather
//     than Active()'s warning channel, and even it must not abort startup:
//     run.go warns and keeps the built-in defaults.
//
// Each case gets a fresh temp cache root, so no case can mask another, and
// each case asserts its own observable conclusion: the status, the built-in
// detectors redacting a synthetic ghp_ token, the fallback warning on stderr
// ("using built-in defaults", never silent), and no remote rule loaded (no
// custom: attribution; the damaged pack's keyword token goes upstream raw).
// The diagnostics buffer is read only after stop() returned, when no request
// goroutine can still write to it.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/rules"
)

// Synthetic GitHub token, assembled from fragments like runSecret so no
// contiguous ghp_ literal lands in the tree; the joined value still matches the
// built-in gh[pousr]_[A-Za-z0-9]{20,} prefix (pkg/redact/prefix.go).
const (
	badPackGHHead = "ghp"
	badPackGHBody = "AbCdEfGhIjKlMnOpQrSt" // 20 alphanumerics
)

func badPackGitHubToken() string { return badPackGHHead + "_" + badPackGHBody }

// badPackBody carries the built-in-hit token plus the damaged pack's
// remote-only keyword token: the first proves the built-in detectors survived
// the fallback, the second proves no remote rule was loaded (it must go raw).
func badPackBody() string {
	return fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`,
		remoteOnlyToken+" "+badPackGitHubToken())
}

// badPackRun starts the daemon against a fresh echo upstream, posts one request
// and returns the raw observations. stop() must run before the diagnostics
// buffer is read: the redaction reporter runs on request goroutines.
func badPackRun(t *testing.T) (status int, received []byte, diagnostics string) {
	t.Helper()
	var stderr bytes.Buffer
	upstream, base, stop := startRulesDaemon(t, &stderr)
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json", badPackBody(), nil)
	status = resp.StatusCode
	if err := stop(); err != nil {
		t.Fatalf("RunServer returned %v after cancel, want nil", err)
	}
	received = upstream.received()
	diagnostics = stderr.String()
	t.Logf("diagnostics:\n%s", diagnostics)
	t.Logf("upstream body: %s", received)
	return status, received, diagnostics
}

// assertFallbackToBuiltins checks the fallback contract shared by the three
// damaged-pack cases. wantWarning pins the rejection layer the case targets,
// so a case cannot silently degrade into another case's failure path.
func assertFallbackToBuiltins(t *testing.T, status int, received []byte, diagnostics, wantWarning string) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: a damaged pack must not stop the daemon from serving.\ndiagnostics:\n%s", status, diagnostics)
	}
	if strings.Contains(diagnostics, "custom:") {
		t.Errorf("diagnostics attribute a hit to a remote rule (custom:), want built-in-only attribution:\ndiagnostics:\n%s", diagnostics)
	}
	if !strings.Contains(diagnostics, "using built-in defaults") {
		t.Errorf("diagnostics do not contain %q: the fallback warning must never be silent.\ndiagnostics:\n%s", "using built-in defaults", diagnostics)
	}
	if wantWarning != "" && !strings.Contains(diagnostics, wantWarning) {
		t.Errorf("diagnostics do not contain the rejection this case targets (%q):\ndiagnostics:\n%s", wantWarning, diagnostics)
	}
	if bytes.Contains(received, []byte(badPackGitHubToken())) {
		t.Errorf("upstream received the raw ghp_ token; the built-in redaction stopped working:\nupstream body: %s", received)
	}
	if !runPlaceholderRe.Match(received) {
		t.Errorf("upstream body %q contains no placeholder; the built-in detectors did not run", received)
	}
	if !bytes.Contains(received, []byte(remoteOnlyToken)) {
		t.Errorf("upstream body %q lost the remote-only token; a damaged pack was applied", received)
	}
}

// openTestCache opens the temp cache root the installed seams point at.
func openTestCache(t *testing.T, root string) *rules.FileCache {
	t.Helper()
	cache, err := rules.OpenFileCache(root)
	if err != nil {
		t.Fatalf("OpenFileCache: %v", err)
	}
	return cache
}

// activePackBytes returns the active serial and its cached raw bytes. It fails
// when no pack is active: Active() reports (ActiveRules{}, nil) with no warning
// for an entry that is merely present, so an unactivated fixture would
// exercise nothing.
func activePackBytes(t *testing.T, cache *rules.FileCache) (serial uint64, manifest, bundle []byte) {
	t.Helper()
	serial, ok, err := cache.Active()
	if err != nil || !ok {
		t.Fatalf("cache.Active() = (%d, %v, %v), want an active serial", serial, ok, err)
	}
	manifest, bundle, err = cache.Load(serial)
	if err != nil {
		t.Fatalf("cache.Load(%d): %v", serial, err)
	}
	return serial, manifest, bundle
}

// signPackBytes re-signs pack with priv and returns the marshaled bundle bytes.
func signPackBytes(t *testing.T, priv ed25519.PrivateKey, pack rules.Pack) []byte {
	t.Helper()
	pack.Signature = signB64(priv, rules.PackSigningInput(pack))
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal signed pack: %v", err)
	}
	return raw
}

func TestBadPackFallback(t *testing.T) {
	t.Run("corrupt_cached_bytes", func(t *testing.T) {
		root := t.TempDir()
		b := publishRemotePack(t, root)
		cache := openTestCache(t, root)
		serial, manifest, bundle := activePackBytes(t, cache)

		var pack rules.Pack
		if err := json.Unmarshal(bundle, &pack); err != nil {
			t.Fatalf("unmarshal cached bundle: %v", err)
		}
		edited := false
		for i := range pack.Rules {
			if pack.Rules[i].ID == "zz-remote-only" {
				pack.Rules[i].Keywords = append(pack.Rules[i].Keywords, "badpack-tamper-marker")
				edited = true
			}
		}
		if !edited {
			t.Fatalf("cached pack has no zz-remote-only rule: %+v", pack.Rules)
		}
		// Re-sign with the harness key so signature, freshness and schema all
		// pass; the UNCHANGED cached manifest keeps pointing at the original
		// bytes, so the rejection must come from the bundle hash binding.
		if err := cache.Save(serial, manifest, signPackBytes(t, b.priv, pack)); err != nil {
			t.Fatalf("save damaged bundle: %v", err)
		}

		status, received, diagnostics := badPackRun(t)
		assertFallbackToBuiltins(t, status, received, diagnostics, "fails integrity checks")
	})

	t.Run("bad_signature", func(t *testing.T) {
		root := t.TempDir()
		publishRemotePack(t, root)
		cache := openTestCache(t, root)
		serial, manifest, bundle := activePackBytes(t, cache)

		var pack rules.Pack
		if err := json.Unmarshal(bundle, &pack); err != nil {
			t.Fatalf("unmarshal cached bundle: %v", err)
		}
		// Same content and same key id, signed by a key the verifier does not
		// trust: only the signature check can refuse this bundle.
		_, roguePriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if err := cache.Save(serial, manifest, signPackBytes(t, roguePriv, pack)); err != nil {
			t.Fatalf("save wrongly signed bundle: %v", err)
		}

		status, received, diagnostics := badPackRun(t)
		assertFallbackToBuiltins(t, status, received, diagnostics, "signature does not verify")
	})

	t.Run("bad_schema_version", func(t *testing.T) {
		root := t.TempDir()
		b := publishRemotePack(t, root)
		cache := openTestCache(t, root)
		serial, _, _ := activePackBytes(t, cache)

		// publishWithConfig always stamps rules.SchemaVersion, so the schema-2
		// pack and its manifest must be built and signed by hand with the
		// harness key. The manifest stays schema 1 and hashes the bundle, so
		// manifest verification passes and the schema check on the PACK is
		// what rejects the pair.
		pack := rules.Pack{
			Channel:          "stable",
			MinBinaryVersion: "0.3.0",
			Serial:           serial,
			KeyID:            "rules-cli-test",
			NotBefore:        cliNow.Add(-time.Hour),
			Expires:          cliNow.Add(24 * time.Hour),
			Config: rules.Config{
				SchemaVersion: 2,
				Rules: []rules.Rule{{
					ID: "zz-remote-only", Type: rules.RuleKeyword,
					Keywords: []string{remoteOnlyToken}, Action: "redact",
				}},
			},
		}
		bundle := signPackBytes(t, b.priv, pack)
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
		}
		manifest.Signature = signB64(b.priv, rules.ManifestSigningInput(manifest))
		rawManifest, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		if err := cache.Save(serial, rawManifest, bundle); err != nil {
			t.Fatalf("save schema-2 pack: %v", err)
		}

		status, received, diagnostics := badPackRun(t)
		assertFallbackToBuiltins(t, status, received, diagnostics, "unsupported schema version")
	})

	t.Run("rules_client_error", func(t *testing.T) {
		const clientErr = "badpack test: rules cache root not creatable"
		installTestRulesClientFunc(t, func(func(string)) (*rules.Client, error) {
			return nil, errors.New(clientErr)
		})

		status, _, diagnostics := badPackRun(t)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200: a rules-client failure must not abort startup.\ndiagnostics:\n%s", status, diagnostics)
		}
		if strings.TrimSpace(diagnostics) == "" {
			t.Fatal("no rules warning was written to stderr; the client failure must not be silent")
		}
		if !strings.Contains(diagnostics, clientErr) {
			t.Errorf("diagnostics %q do not name the client failure %q", diagnostics, clientErr)
		}
	})
}
