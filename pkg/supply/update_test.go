// update_test.go is the W5.6 suite: the full signed update sequence against a
// stub issuer, the nine ordered checks, the two-phase commit with a kill
// injected at every commit step, the OD-1 version gates and the D17
// install-source delegation. Nothing here opens a socket: the fetchers are
// map-backed stubs, the verifier holds one in-process key pair, and the
// install is a temp directory.
package supply

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	updateTestKeyID       = "upd-2026-09"
	updateTestArtifactURL = "https://cdn.example.test/tokenhush/0.6.0/tokenhush-linux-amd64"
	updateTestVersion     = "0.6.0"
	updateTestSerial      = 7
)

var (
	updateTestOriginal = []byte("TOKENHUSH-0.5.0-ORIGINAL-BINARY")
	updateTestArtifact = []byte("TOKENHUSH-0.6.0-SIGNED-ARTIFACT")
	errInjectedCrash   = errors.New("test: injected crash at a commit step")
)

// updateKeyVerifier is a stub Verifier bound to one in-process key that
// accepts the two update domains and records the order it saw them.
type updateKeyVerifier struct {
	keyID   string
	public  string
	domains []string
}

func (v *updateKeyVerifier) Verify(domain, keyID string, signingInput, sig []byte) error {
	if keyID != v.keyID || (domain != DomainUpdateManifest && domain != DomainUpdateRevocations) {
		return ErrWrongKey
	}
	v.domains = append(v.domains, domain)
	return VerifyEd25519(v.public, signingInput, sig)
}

// updateHarness is the stub issuer and the temp install: one key pair, a
// verifier over it, two map-backed fetchers (documents and artifact) and a
// binary at <install>/tokenhush holding the previous release.
type updateHarness struct {
	t         *testing.T
	dataDir   string
	install   string
	target    string
	priv      ed25519.PrivateKey
	verifier  *updateKeyVerifier
	docs      *rulesFetcher
	artifacts *rulesFetcher
	now       time.Time
	goos      string
	goarch    string
}

func newUpdateHarness(t *testing.T) *updateHarness {
	t.Helper()
	public, priv := substrateKeyPair(t)
	install := t.TempDir()
	target := filepath.Join(install, "tokenhush")
	updateWriteBinary(t, target, updateTestOriginal)
	artifacts := newRulesFetcher()
	artifacts.set(updateTestArtifactURL, updateTestArtifact)
	return &updateHarness{
		t: t, dataDir: t.TempDir(), install: install, target: target,
		priv: priv, verifier: &updateKeyVerifier{keyID: updateTestKeyID, public: public},
		docs: newRulesFetcher(), artifacts: artifacts,
		now: time.Unix(fixtureNotBefore+3600, 0).UTC(), goos: "linux", goarch: "amd64",
	}
}

// publish wires one signed manifest, one signed revocations document and the
// artifact body into the stub issuer. mutate can adjust the manifest before it
// is signed; the digest defaults to the published artifact.
func (h *updateHarness) publish(mutate func(*UpdateManifestPayload)) UpdateManifestPayload {
	h.t.Helper()
	h.publishRevocations(nil, nil)
	manifest := UpdateManifestPayload{
		Version: updateTestVersion, OS: h.goos, Arch: h.goarch, URL: updateTestArtifactURL,
		SHA256: testHexHash(updateTestArtifact), Channel: updateChannel, Serial: updateTestSerial,
		KeyID:     updateTestKeyID,
		NotBefore: time.Unix(fixtureNotBefore, 0).UTC(), Expires: time.Unix(fixtureExpires, 0).UTC(),
	}
	if mutate != nil {
		mutate(&manifest)
	}
	h.docs.set(updateManifestURL, h.signManifest(manifest))
	h.artifacts.set(manifest.URL, updateTestArtifact)
	return manifest
}

// publishRevocations serves a signed revocations document with the given
// revoked serials and versions.
func (h *updateHarness) publishRevocations(serials []uint64, versions []string) {
	h.t.Helper()
	doc := updateRevocationsPayload(3, serials, versions)
	doc.KeyID = updateTestKeyID
	h.docs.set(updateRevocationsURL, h.signRevocations(doc))
}

// signManifest signs the frozen projection and renders the wire document.
func (h *updateHarness) signManifest(manifest UpdateManifestPayload) []byte {
	h.t.Helper()
	manifest.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(h.priv, UpdateManifestSigningInput(manifest)))
	return updateMarshal(h.t, manifest)
}

// signRevocations signs the frozen projection and renders the wire document.
func (h *updateHarness) signRevocations(doc UpdateRevocationsPayload) []byte {
	h.t.Helper()
	doc.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(h.priv, UpdateRevocationsSigningInput(doc)))
	return updateMarshal(h.t, doc)
}

// tamperManifest re-serves the signed manifest with one field changed after
// signing, so the signature no longer covers the document.
func (h *updateHarness) tamperManifest() {
	h.t.Helper()
	raw := h.docs.bodies[updateManifestURL]
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		h.t.Fatalf("unmarshal signed manifest: %v", err)
	}
	fields["version"] = json.RawMessage(`"9.9.9"`)
	h.docs.set(updateManifestURL, updateMarshal(h.t, fields))
}

// newUpdater builds an updater over the harness seams.
func (h *updateHarness) newUpdater(mutate func(*UpdateConfig)) *Updater {
	h.t.Helper()
	cfg := UpdateConfig{
		DataDir: h.dataDir, Target: h.target, Source: SourceSelfManaged,
		Fetcher: h.docs, ArtifactFetcher: h.artifacts, Verifier: h.verifier,
		Now: func() time.Time { return h.now }, BinaryVersion: Version,
		GOOS: h.goos, GOARCH: h.goarch, Out: io.Discard,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	updater, err := NewUpdater(cfg)
	if err != nil {
		h.t.Fatalf("NewUpdater: %v", err)
	}
	return updater
}

// highWater reads the persisted anti-rollback mark back from disk.
func (h *updateHarness) highWater() int64 {
	h.t.Helper()
	mark, err := NewUpdateHighWater(h.dataDir)
	if err != nil {
		h.t.Fatalf("NewUpdateHighWater: %v", err)
	}
	return mark.Current()
}

func (h *updateHarness) assertTargetBytes(want []byte) {
	h.t.Helper()
	got, err := os.ReadFile(h.target)
	if err != nil {
		h.t.Fatalf("read target: %v", err)
	}
	if !bytes.Equal(got, want) {
		h.t.Errorf("target bytes = %q, want %q", got, want)
	}
}

// assertNoStaging proves no commit artifact was left beside the binary.
func (h *updateHarness) assertNoStaging() {
	h.t.Helper()
	for _, suffix := range []string{candidateSuffix, journalSuffix} {
		if fileExists(h.target + suffix) {
			h.t.Errorf("staging file %s left behind", h.target+suffix)
		}
	}
}

// updateWriteBinary writes an executable test binary.
func updateWriteBinary(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// updateMarshal renders a document or fails the test.
func updateMarshal(t *testing.T, doc any) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

// runnable reads path and fails the test unless it is a non-empty executable:
// the property Recover must always restore.
func runnable(t *testing.T, path string) []byte {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Size() == 0 {
		t.Fatalf("%s is empty", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s is not executable (%v)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

// TestUpdateSequence is the QA happy path: the ordered sequence against the
// stub issuer, then the on-disk result and a no-op Recover.
func TestUpdateSequence(t *testing.T) {
	h := newUpdateHarness(t)
	h.publish(nil)
	updater := h.newUpdater(nil)
	result, err := updater.Update(context.Background(), false)
	if err != nil {
		t.Fatalf("Update = %v, want nil", err)
	}
	if result.Status != UpdateInstalled || result.Version != updateTestVersion || result.Serial != updateTestSerial {
		t.Fatalf("result = %+v, want installed %s serial %d", result, updateTestVersion, updateTestSerial)
	}
	if got := h.docs.calls; len(got) != 2 || got[0] != updateRevocationsURL || got[1] != updateManifestURL {
		t.Errorf("document fetch order = %v, want revocations then manifest", got)
	}
	if got := h.verifier.domains; len(got) != 2 || got[0] != DomainUpdateRevocations || got[1] != DomainUpdateManifest {
		t.Errorf("verification order = %v, want revocations then manifest", got)
	}
	if got := h.artifacts.calls; len(got) != 1 || got[0] != updateTestArtifactURL {
		t.Errorf("artifact fetches = %v, want exactly the signed url", got)
	}
	h.assertTargetBytes(updateTestArtifact)
	if got := runnable(t, h.target); !bytes.Equal(got, updateTestArtifact) {
		t.Errorf("installed binary = %q, want the artifact", got)
	}
	if got := runnable(t, h.target+lastKnownGoodSuffix); !bytes.Equal(got, updateTestOriginal) {
		t.Errorf("last-known-good = %q, want the previous binary", got)
	}
	if got := h.highWater(); got != updateTestSerial {
		t.Errorf("high-water = %d, want %d", got, updateTestSerial)
	}
	h.assertNoStaging()
	recovered, err := Recover(h.target)
	if err != nil || recovered != RecoveryNone {
		t.Errorf("Recover after a clean commit = (%q, %v), want (none, nil)", recovered, err)
	}
	t.Logf("QA happy: sequence installed %s (serial %d), high-water advanced and Recover is a no-op", updateTestVersion, updateTestSerial)
}

// TestUpdateHashMismatchLeavesBinaryIdentical is the mandatory failure path: a
// tampered artifact changes nothing on disk.
func TestUpdateHashMismatchLeavesBinaryIdentical(t *testing.T) {
	h := newUpdateHarness(t)
	h.publish(nil)
	h.artifacts.set(updateTestArtifactURL, []byte("TAMPERED-ARTIFACT"))
	updater := h.newUpdater(nil)
	_, err := updater.Update(context.Background(), false)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Update with a tampered artifact = %v, want ErrDigestMismatch", err)
	}
	h.assertTargetBytes(updateTestOriginal)
	h.assertNoStaging()
	if got := h.highWater(); got != 0 {
		t.Errorf("high-water = %d, want 0: a rejected artifact must not advance it", got)
	}
	if got := runnable(t, h.target); !bytes.Equal(got, updateTestOriginal) {
		t.Errorf("running binary = %q, want the byte-identical original", got)
	}
	t.Logf("QA failure: tampered artifact -> %v, on-disk binary byte-identical", err)
}

// TestUpdateRejections covers the ordered checks that must refuse before any
// install: channel, revocation, replay, signature and artifact URL.
func TestUpdateRejections(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*updateHarness)
		want  error
	}{
		{"manifest channel", func(h *updateHarness) {
			h.publish(func(m *UpdateManifestPayload) { m.Channel = "beta" })
		}, ErrUpdateChannel},
		{"revocations channel", func(h *updateHarness) {
			h.publish(nil)
			doc := updateRevocationsPayload(3, nil, nil)
			doc.KeyID, doc.Channel = updateTestKeyID, "beta"
			h.docs.set(updateRevocationsURL, h.signRevocations(doc))
		}, ErrUpdateChannel},
		{"revoked serial", func(h *updateHarness) {
			h.publish(nil)
			h.publishRevocations([]uint64{updateTestSerial}, nil)
		}, ErrRevokedSerial},
		{"revoked version", func(h *updateHarness) {
			h.publish(nil)
			h.publishRevocations(nil, []string{updateTestVersion})
		}, ErrRevokedVersion},
		{"revoked by the manifest's own list", func(h *updateHarness) {
			h.publish(func(m *UpdateManifestPayload) { m.RevokedSerials = []uint64{updateTestSerial} })
		}, ErrRevokedSerial},
		{"tampered manifest signature", func(h *updateHarness) {
			h.publish(nil)
			h.tamperManifest()
		}, ErrBadSignature},
		{"artifact url is not https", func(h *updateHarness) {
			h.publish(func(m *UpdateManifestPayload) { m.URL = "http://cdn.example.test/tokenhush" })
		}, ErrMalformedDoc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpdateHarness(t)
			tc.setup(h)
			updater := h.newUpdater(nil)
			if _, err := updater.Update(context.Background(), false); !errors.Is(err, tc.want) {
				t.Fatalf("Update = %v, want %v", err, tc.want)
			}
			h.assertTargetBytes(updateTestOriginal)
			h.assertNoStaging()
			if got := h.highWater(); got != 0 {
				t.Errorf("high-water = %d, want 0 after a rejection", got)
			}
			if got := h.artifacts.invoked(); got != 0 {
				t.Errorf("artifact fetches = %d, want 0: the artifact is fetched only after every earlier check", got)
			}
		})
	}
}

// TestUpdatePlatformMismatch refuses a foreign artifact before the download.
func TestUpdatePlatformMismatch(t *testing.T) {
	h := newUpdateHarness(t)
	h.publish(func(m *UpdateManifestPayload) { m.OS, m.Arch = "darwin", "arm64" })
	updater := h.newUpdater(nil)
	_, err := updater.Update(context.Background(), false)
	if !errors.Is(err, ErrPlatformMismatch) {
		t.Fatalf("Update = %v, want ErrPlatformMismatch", err)
	}
	if got := h.artifacts.invoked(); got != 0 {
		t.Errorf("artifact fetches = %d, want 0: the platform is checked before the download", got)
	}
	h.assertTargetBytes(updateTestOriginal)
	if got := h.highWater(); got != 0 {
		t.Errorf("high-water = %d, want 0", got)
	}
	t.Logf("QA failure: platform mismatch -> %v, no install", err)
}

// TestUpdateAntiRollback covers the replay rule on both sides of the mark.
func TestUpdateAntiRollback(t *testing.T) {
	t.Run("a serial below the mark is a replay", func(t *testing.T) {
		h := newUpdateHarness(t)
		h.publish(nil)
		mark, err := NewUpdateHighWater(h.dataDir)
		if err != nil {
			t.Fatalf("NewUpdateHighWater: %v", err)
		}
		if err := mark.Advance(9); err != nil {
			t.Fatalf("Advance(9): %v", err)
		}
		updater := h.newUpdater(nil)
		if _, err := updater.Update(context.Background(), false); !errors.Is(err, ErrReplay) {
			t.Fatalf("Update below the mark = %v, want ErrReplay", err)
		}
		if got := h.artifacts.invoked(); got != 0 {
			t.Errorf("artifact fetches = %d, want 0", got)
		}
		h.assertTargetBytes(updateTestOriginal)
	})
	t.Run("the mark serial is up to date", func(t *testing.T) {
		h := newUpdateHarness(t)
		h.publish(nil)
		mark, err := NewUpdateHighWater(h.dataDir)
		if err != nil {
			t.Fatalf("NewUpdateHighWater: %v", err)
		}
		if err := mark.Advance(updateTestSerial); err != nil {
			t.Fatalf("Advance(%d): %v", updateTestSerial, err)
		}
		updater := h.newUpdater(nil)
		result, err := updater.Update(context.Background(), false)
		if err != nil {
			t.Fatalf("Update at the mark = %v, want nil", err)
		}
		if result.Status != UpdateUpToDate {
			t.Errorf("status = %q, want up-to-date", result.Status)
		}
		if got := h.artifacts.invoked(); got != 0 {
			t.Errorf("artifact fetches = %d, want 0: a replay never re-downloads", got)
		}
		h.assertTargetBytes(updateTestOriginal)
	})
}

// TestUpdateVersionGate pins OD-1: the v0.5.0 line satisfies the signed
// fixtures' min_binary_version 0.3.0, a higher requirement is refused, and a
// downgrade needs the flag AND the environment opt-in.
func TestUpdateVersionGate(t *testing.T) {
	t.Run("the od1 fixture requirement is accepted", func(t *testing.T) {
		if Version != "0.5.0" {
			t.Fatalf("Version = %q, want the OD-1 v0.5.0 line", Version)
		}
		binary, err := parseVersion(Version)
		if err != nil {
			t.Fatalf("parseVersion(%q): %v", Version, err)
		}
		if err := checkMinBinaryVersion("0.3.0", binary); err != nil {
			t.Errorf("min_binary_version 0.3.0 = %v, want accepted for a v0.5.0 binary", err)
		}
		if err := checkMinBinaryVersion("9.9.9", binary); !errors.Is(err, ErrMinBinaryVersion) {
			t.Errorf("min_binary_version 9.9.9 = %v, want ErrMinBinaryVersion", err)
		}
	})
	run := func(t *testing.T, allow bool, env string) (UpdateResult, error, *updateHarness) {
		t.Helper()
		h := newUpdateHarness(t)
		h.publish(func(m *UpdateManifestPayload) { m.Version = "0.4.0" })
		updater := h.newUpdater(func(cfg *UpdateConfig) {
			cfg.AllowDowngrade = allow
			cfg.LookupEnv = func(key string) (string, bool) {
				if key == EnvAllowDowngrade && env != "" {
					return env, true
				}
				return "", false
			}
		})
		result, err := updater.Update(context.Background(), false)
		return result, err, h
	}
	t.Run("a downgrade without the flag and env is refused", func(t *testing.T) {
		_, err, h := run(t, false, "")
		if !errors.Is(err, ErrDowngrade) {
			t.Fatalf("Update downgrade = %v, want ErrDowngrade", err)
		}
		h.assertTargetBytes(updateTestOriginal)
	})
	t.Run("the flag alone is not enough", func(t *testing.T) {
		if _, err, _ := run(t, true, ""); !errors.Is(err, ErrDowngrade) {
			t.Fatalf("Update with the flag only = %v, want ErrDowngrade", err)
		}
	})
	t.Run("the env alone is not enough", func(t *testing.T) {
		if _, err, _ := run(t, false, "1"); !errors.Is(err, ErrDowngrade) {
			t.Fatalf("Update with the env only = %v, want ErrDowngrade", err)
		}
	})
	t.Run("the flag and the env together admit the downgrade", func(t *testing.T) {
		result, err, h := run(t, true, "true")
		if err != nil {
			t.Fatalf("Update with the flag and env = %v, want nil", err)
		}
		if result.Status != UpdateInstalled || result.Version != "0.4.0" {
			t.Fatalf("result = %+v, want installed 0.4.0", result)
		}
		h.assertTargetBytes(updateTestArtifact)
	})
	if AllowDowngradeEnabled(func(string) (string, bool) { return "", false }) {
		t.Error("AllowDowngradeEnabled with no env value = true, want false")
	}
}

// TestUpdateCheckWritesNoState pins the --check contract: a verdict, no
// download, no mark advance, no journal and no new file anywhere.
func TestUpdateCheckWritesNoState(t *testing.T) {
	h := newUpdateHarness(t)
	h.publish(nil)
	var out bytes.Buffer
	updater := h.newUpdater(func(cfg *UpdateConfig) { cfg.Out = &out })
	result, err := updater.Update(context.Background(), true)
	if err != nil {
		t.Fatalf("Update(check) = %v, want nil", err)
	}
	if result.Status != UpdateChecked || result.Version != updateTestVersion || result.Serial != updateTestSerial {
		t.Fatalf("result = %+v, want a checked verdict for %s serial %d", result, updateTestVersion, updateTestSerial)
	}
	if !strings.Contains(out.String(), "--check made no changes") {
		t.Errorf("check output = %q, want the no-changes statement", out.String())
	}
	if got := h.artifacts.invoked(); got != 0 {
		t.Errorf("artifact fetches = %d, want 0: --check downloads nothing", got)
	}
	if got := h.highWater(); got != 0 {
		t.Errorf("high-water = %d, want 0: --check advances nothing", got)
	}
	h.assertTargetBytes(updateTestOriginal)
	h.assertNoStaging()
	entries, err := os.ReadDir(h.dataDir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", h.dataDir, err)
	}
	if len(entries) != 0 {
		t.Errorf("data dir entries = %v, want none: --check wrote state", entries)
	}
	names, err := os.ReadDir(h.install)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", h.install, err)
	}
	if len(names) != 1 || names[0].Name() != "tokenhush" {
		t.Errorf("install dir entries = %v, want only the running binary", names)
	}
}

// TestUpdateSourceDetection covers all four enum values without a real brew or
// scoop, and the frozen spellings.
func TestUpdateSourceDetection(t *testing.T) {
	cases := []struct {
		name string
		goos string
		exe  string
		env  map[string]string
		home string
		want InstallSource
	}{
		{"homebrew caskroom", "darwin", "/opt/homebrew/Caskroom/tokenhush/0.5.0/tokenhush", map[string]string{"HOMEBREW_PREFIX": "/opt/homebrew"}, "/Users/dev", SourceHomebrew},
		{"homebrew cellar", "linux", "/home/linuxbrew/.linuxbrew/Cellar/tokenhush/0.5.0/bin/tokenhush", nil, "/home/dev", SourceHomebrew},
		{"scoop apps", "windows", `C:\Users\dev\scoop\apps\tokenhush\current\tokenhush.exe`, nil, `C:\Users\dev`, SourceScoop},
		{"scoop root env", "windows", `D:\tools\tokenhush.exe`, map[string]string{"SCOOP": `D:\tools`}, "", SourceScoop},
		{"self-managed install script", "linux", "/home/dev/.local/bin/tokenhush", nil, "/home/dev", SourceSelfManaged},
		{"unknown system path", "linux", "/usr/bin/tokenhush", nil, "/home/dev", SourceUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(key string) string { return tc.env[key] }
			if got := DetectSource(tc.goos, tc.exe, getenv, tc.home); got != tc.want {
				t.Errorf("DetectSource(%q) = %q, want %q", tc.exe, got, tc.want)
			}
		})
	}
	for _, value := range []InstallSource{SourceHomebrew, SourceScoop, SourceSelfManaged, SourceUnknown} {
		switch string(value) {
		case "homebrew", "scoop", "self-managed", "unknown":
		default:
			t.Errorf("install source %q is not one of the four frozen spellings", value)
		}
	}
	if got := DefaultSource(); got == "" {
		t.Error("DefaultSource() = \"\", want one of the four sources")
	}
}

// TestUpdateSourceDelegation is D17: the package managers get the exact argv
// and the binary is never self-replaced, while an unknown install gets
// guidance only.
func TestUpdateSourceDelegation(t *testing.T) {
	delegated := func(t *testing.T, source InstallSource, wantArgv []string) {
		t.Helper()
		h := newUpdateHarness(t)
		h.publish(nil)
		var argv []string
		updater := h.newUpdater(func(cfg *UpdateConfig) {
			cfg.Source = source
			cfg.Runner = func(_ context.Context, command []string) error {
				argv = command
				return nil
			}
		})
		result, err := updater.Update(context.Background(), false)
		if err != nil {
			t.Fatalf("Update(%s) = %v, want nil", source, err)
		}
		if result.Status != UpdateDelegated {
			t.Errorf("status = %q, want delegated", result.Status)
		}
		if !slices.Equal(argv, wantArgv) || !slices.Equal(result.Command, wantArgv) {
			t.Errorf("delegated argv = %v (result %v), want exactly %v", argv, result.Command, wantArgv)
		}
		h.assertTargetBytes(updateTestOriginal)
		h.assertNoStaging()
		if got := h.docs.invoked() + h.artifacts.invoked(); got != 0 {
			t.Errorf("fetches = %d, want 0: a delegated install never consults the update channel", got)
		}
	}
	t.Run("homebrew delegates to brew upgrade --cask", func(t *testing.T) {
		delegated(t, SourceHomebrew, []string{"brew", "upgrade", "--cask", "tokenhush"})
	})
	t.Run("scoop delegates to scoop update", func(t *testing.T) {
		delegated(t, SourceScoop, []string{"scoop", "update", "tokenhush"})
	})
	t.Run("check only reports the delegated command", func(t *testing.T) {
		h := newUpdateHarness(t)
		h.publish(nil)
		called := false
		var out bytes.Buffer
		updater := h.newUpdater(func(cfg *UpdateConfig) {
			cfg.Source = SourceHomebrew
			cfg.Out = &out
			cfg.Runner = func(context.Context, []string) error {
				called = true
				return errors.New("must not run")
			}
		})
		result, err := updater.Update(context.Background(), true)
		if err != nil {
			t.Fatalf("Update(check, homebrew) = %v, want nil", err)
		}
		if called {
			t.Error("--check ran the package manager")
		}
		if result.Status != UpdateChecked || !strings.Contains(out.String(), "brew upgrade --cask tokenhush") {
			t.Errorf("check result = %+v (out %q), want the planned command named", result, out.String())
		}
		h.assertTargetBytes(updateTestOriginal)
	})
	t.Run("unknown prints guidance and never replaces", func(t *testing.T) {
		h := newUpdateHarness(t)
		h.publish(nil)
		var out bytes.Buffer
		updater := h.newUpdater(func(cfg *UpdateConfig) {
			cfg.Source = SourceUnknown
			cfg.Out = &out
			cfg.Runner = func(context.Context, []string) error {
				t.Error("an unknown install ran a package manager")
				return nil
			}
		})
		result, err := updater.Update(context.Background(), false)
		if err != nil {
			t.Fatalf("Update(unknown) = %v, want nil", err)
		}
		if result.Status != UpdateManual {
			t.Errorf("status = %q, want manual", result.Status)
		}
		for _, want := range []string{"brew upgrade --cask tokenhush", "scoop update tokenhush", "install script"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("guidance = %q, want it to mention %q", out.String(), want)
			}
		}
		h.assertTargetBytes(updateTestOriginal)
		h.assertNoStaging()
	})
	t.Run("an unrecognised source value is never self-replaced", func(t *testing.T) {
		h := newUpdateHarness(t)
		h.publish(nil)
		updater := h.newUpdater(func(cfg *UpdateConfig) {
			cfg.Source = InstallSource("bogus")
			cfg.Runner = func(context.Context, []string) error {
				t.Error("an unrecognised install ran a package manager")
				return nil
			}
		})
		result, err := updater.Update(context.Background(), false)
		if err != nil || result.Status != UpdateManual {
			t.Fatalf("Update(bogus source) = (%+v, %v), want manual guidance", result, err)
		}
		h.assertTargetBytes(updateTestOriginal)
		h.assertNoStaging()
	})
}

// TestUpdateRecoverAfterInterruptedCommit injects a kill at every commit step
// and proves Recover leaves a runnable binary each time.
func TestUpdateRecoverAfterInterruptedCommit(t *testing.T) {
	cases := []struct {
		name      string
		step      string
		want      RecoveryResult
		wantBytes []byte
	}{
		{"candidate staged before the journal", stepCandidateStaged, RecoveryCleaned, updateTestOriginal},
		{"journal written before the backup rename", stepJournalWritten, RecoveryCompleted, updateTestArtifact},
		{"killed between the two renames", stepBackedUp, RecoveryCompleted, updateTestArtifact},
		{"killed after the install rename", stepInstalled, RecoveryCleaned, updateTestArtifact},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpdateHarness(t)
			h.publish(nil)
			updater := h.newUpdater(nil)
			updater.kill = func(step string) error {
				if step == tc.step {
					return errInjectedCrash
				}
				return nil
			}
			if _, err := updater.Update(context.Background(), false); !errors.Is(err, errInjectedCrash) {
				t.Fatalf("Update with a kill at %q = %v, want the injected crash", tc.step, err)
			}
			recovered, err := Recover(h.target)
			if err != nil {
				t.Fatalf("Recover after a kill at %q: %v", tc.step, err)
			}
			if recovered != tc.want {
				t.Errorf("Recover after a kill at %q = %q, want %q", tc.step, recovered, tc.want)
			}
			if got := runnable(t, h.target); !bytes.Equal(got, tc.wantBytes) {
				t.Errorf("recovered binary = %q, want %q (neither truncated nor missing)", got, tc.wantBytes)
			}
			again, err := Recover(h.target)
			if err != nil || again != RecoveryNone {
				t.Errorf("second Recover = (%q, %v), want (none, nil)", again, err)
			}
			t.Logf("QA failure: kill at %q -> Recover %q -> runnable %d-byte binary", tc.step, recovered, len(tc.wantBytes))
		})
	}
	t.Run("a missing target with a last-known-good backup is restored", func(t *testing.T) {
		h := newUpdateHarness(t)
		if err := os.Rename(h.target, h.target+lastKnownGoodSuffix); err != nil {
			t.Fatalf("simulate a missing target: %v", err)
		}
		recovered, err := Recover(h.target)
		if err != nil {
			t.Fatalf("Recover: %v", err)
		}
		if recovered != RecoveryRolledBack {
			t.Errorf("Recover = %q, want rolled-back", recovered)
		}
		if got := runnable(t, h.target); !bytes.Equal(got, updateTestOriginal) {
			t.Errorf("restored binary = %q, want the last-known-good", got)
		}
	})
}
