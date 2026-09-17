package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/supply"
)

// updateTestVersion is the candidate the stub issuer publishes: above the
// running 0.5.0, so the OD-1 gate admits it.
const updateTestVersion = "0.6.0"

// updateTestURLs are the two frozen update document URLs the command fetches.
func updateTestURLs() (revocations, manifest string) {
	return supply.BaseURL + supply.UpdateRevocationsPath + supply.ChannelQuery,
		supply.BaseURL + supply.UpdateManifestPath + supply.ChannelQuery
}

// updateTestRevocations renders a signed revocation document that revokes
// nothing.
func updateTestRevocations() []byte {
	window := rulesTestNow()
	raw, err := json.Marshal(supply.UpdateRevocationsPayload{
		Channel: "stable", Serial: 3, KeyID: rulesTestKeyID,
		NotBefore: window.Add(-time.Hour), Expires: window.Add(time.Hour),
		RevokedSerials: []uint64{}, RevokedVersions: []string{}, Signature: stubSignature(),
	})
	if err != nil {
		panic(err)
	}
	return raw
}

// updateTestManifest renders a signed manifest for the running platform whose
// artifact would be the next release.
func updateTestManifest() []byte {
	window := rulesTestNow()
	raw, err := json.Marshal(supply.UpdateManifestPayload{
		Version: updateTestVersion, OS: runtime.GOOS, Arch: runtime.GOARCH,
		URL:       "https://cdn.example.test/tokenhush/" + updateTestVersion,
		SHA256:    fmt.Sprintf("%x", sha256.Sum256([]byte("artifact"))),
		Channel:   "stable",
		Serial:    5,
		KeyID:     rulesTestKeyID,
		NotBefore: window.Add(-time.Hour),
		Expires:   window.Add(time.Hour),
		Signature: stubSignature(),
	})
	if err != nil {
		panic(err)
	}
	return raw
}

// updateTestEnv is the close-to-end CLI harness for the update command: stub
// document and artifact fetchers, a stub verifier, a temp data dir and a temp
// install target, an injectable environment, install source and runner.
type updateTestEnv struct {
	dataDir   string
	target    string
	original  []byte
	docs      *stubFetcher
	artifacts *stubFetcher
	verifier  *stubVerifier
	env       map[string]string
	source    supply.InstallSource
	argv      [][]string
}

func newUpdateTestEnv(t *testing.T) *updateTestEnv {
	t.Helper()
	target := filepath.Join(t.TempDir(), "tokenhush")
	original := []byte("TOKENHUSH-0.5.0-ORIGINAL-BINARY")
	if err := os.WriteFile(target, original, 0o755); err != nil {
		t.Fatalf("write the install target: %v", err)
	}
	return &updateTestEnv{
		dataDir: t.TempDir(), target: target, original: original,
		docs: newStubFetcher(), artifacts: newStubFetcher(), verifier: &stubVerifier{},
		env: map[string]string{}, source: supply.SourceSelfManaged,
	}
}

// publish wires one signed manifest and one signed revocation document into the
// stub issuer.
func (e *updateTestEnv) publish() {
	revocations, manifest := updateTestURLs()
	e.docs.set(revocations, updateTestRevocations())
	e.docs.set(manifest, updateTestManifest())
}

func (e *updateTestEnv) seams() updateSeams {
	return updateSeams{
		lookupEnv: func(name string) (string, bool) { value, ok := e.env[name]; return value, ok },
		dataDir:   func() (string, error) { return e.dataDir, nil },
		docs:      func() supply.Fetcher { return e.docs },
		artifacts: func() supply.Fetcher { return e.artifacts },
		verifier:  e.verifier,
		now:       rulesTestNow,
		source:    e.source,
		runner: func(_ context.Context, argv []string) error {
			e.argv = append(e.argv, argv)
			return nil
		},
		target: e.target,
	}
}

// assertTargetUntouched proves the install was never self-replaced.
func (e *updateTestEnv) assertTargetUntouched(t *testing.T) {
	t.Helper()
	current, err := os.ReadFile(e.target)
	if err != nil {
		t.Fatalf("read the install target: %v", err)
	}
	if !bytes.Equal(current, e.original) {
		t.Errorf("the install target changed: %q, want the untouched %q", current, e.original)
	}
}

// assertNothingWritten proves no state landed in the data dir.
func (e *updateTestEnv) assertNothingWritten(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(e.dataDir)
	if err != nil {
		t.Fatalf("read data dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the command wrote %d entries into the data dir", len(entries))
	}
}

// TestUpdateCheckReportsWithoutWriting is the QA happy path: the signed
// sequence reports the available release and writes nothing.
func TestUpdateCheckReportsWithoutWriting(t *testing.T) {
	env := newUpdateTestEnv(t)
	env.publish()
	var stdout, stderr bytes.Buffer
	if code := updateWith([]string{"--check"}, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("update --check = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "is available") || !strings.Contains(stdout.String(), "made no changes") {
		t.Errorf("stdout = %q, want the available verdict and the no-change note", stdout.String())
	}
	if env.docs.invoked() != 2 {
		t.Errorf("document fetches = %d, want the revocations and the manifest", env.docs.invoked())
	}
	if env.artifacts.invoked() != 0 {
		t.Errorf("artifact fetches = %d, want 0 for --check", env.artifacts.invoked())
	}
	env.assertNothingWritten(t)
	env.assertTargetUntouched(t)
}

// TestUpdateSwitchSendsNoRequest pins the disclosed switch: the command returns
// before the fetchers even exist.
func TestUpdateSwitchSendsNoRequest(t *testing.T) {
	env := newUpdateTestEnv(t)
	env.publish()
	env.env[noUpdateCheckEnv] = "1"
	for _, args := range [][]string{nil, {"--check"}} {
		var stdout, stderr bytes.Buffer
		if code := updateWith(args, &stdout, &stderr, env.seams()); code != exitOK {
			t.Fatalf("update %v with the switch = %d, want 0 (stderr %q)", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "no request was sent") {
			t.Errorf("stdout = %q, want the no-request message", stdout.String())
		}
	}
	if env.docs.invoked() != 0 || env.artifacts.invoked() != 0 {
		t.Errorf("fetches = %d documents / %d artifacts, want 0", env.docs.invoked(), env.artifacts.invoked())
	}
	if len(env.argv) != 0 {
		t.Errorf("the runner ran %v, want nothing", env.argv)
	}
	env.assertNothingWritten(t)
	env.assertTargetUntouched(t)
}

// TestUpdateHomebrewDelegatesAndNeverSelfReplaces: a Homebrew install hands the
// upgrade to brew with the exact argv and tokenhush never self-replaces.
func TestUpdateHomebrewDelegatesAndNeverSelfReplaces(t *testing.T) {
	env := newUpdateTestEnv(t)
	env.source = supply.SourceHomebrew
	env.publish()
	var stdout, stderr bytes.Buffer
	if code := updateWith(nil, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("update (homebrew) = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "delegated the upgrade") {
		t.Errorf("stdout = %q, want the delegation verdict", stdout.String())
	}
	want := []string{"brew", "upgrade", "--cask", "tokenhush"}
	if len(env.argv) != 1 || !slices.Equal(env.argv[0], want) {
		t.Errorf("runner argv = %v, want exactly [%v]", env.argv, want)
	}
	if env.docs.invoked() != 0 {
		t.Errorf("document fetches = %d, want 0: a package manager owns its upgrade", env.docs.invoked())
	}
	env.assertTargetUntouched(t)
}

// TestUpdateHomebrewCheckReportsTheCommand: --check reports the exact command
// without running the package manager.
func TestUpdateHomebrewCheckReportsTheCommand(t *testing.T) {
	env := newUpdateTestEnv(t)
	env.source = supply.SourceHomebrew
	var stdout, stderr bytes.Buffer
	if code := updateWith([]string{"--check"}, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("update --check (homebrew) = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "brew upgrade --cask tokenhush") {
		t.Errorf("stdout = %q, want the exact delegated command", stdout.String())
	}
	if len(env.argv) != 0 {
		t.Errorf("the runner ran %v, want nothing for --check", env.argv)
	}
	env.assertTargetUntouched(t)
}

// TestUpdateScoopDelegates: the other owning manager gets its exact argv too.
func TestUpdateScoopDelegates(t *testing.T) {
	env := newUpdateTestEnv(t)
	env.source = supply.SourceScoop
	var stdout, stderr bytes.Buffer
	if code := updateWith(nil, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("update (scoop) = %d, want 0 (stderr %q)", code, stderr.String())
	}
	want := []string{"scoop", "update", "tokenhush"}
	if len(env.argv) != 1 || !slices.Equal(env.argv[0], want) {
		t.Errorf("runner argv = %v, want exactly [%v]", env.argv, want)
	}
	if env.docs.invoked() != 0 {
		t.Errorf("document fetches = %d, want 0: a package manager owns its upgrade", env.docs.invoked())
	}
	env.assertTargetUntouched(t)
}

// TestUpdateUnknownSourcePrintsManualGuidance: an unrecognised install is told
// how to upgrade and is never self-replaced.
func TestUpdateUnknownSourcePrintsManualGuidance(t *testing.T) {
	env := newUpdateTestEnv(t)
	env.source = supply.SourceUnknown
	var stdout, stderr bytes.Buffer
	if code := updateWith(nil, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("update (unknown source) = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Upgrade manually") {
		t.Errorf("stdout = %q, want the manual-upgrade guidance", stdout.String())
	}
	if env.docs.invoked() != 0 {
		t.Errorf("document fetches = %d, want 0 for an unrecognised install", env.docs.invoked())
	}
	env.assertTargetUntouched(t)
}

// TestUpdateUsageErrors pins the usage exits: no base URL and no key is
// configurable from the CLI.
func TestUpdateUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"extra"},
		{"--base-url", "https://evil.test"},
		{"--key", "deadbeef"},
	} {
		var stdout, stderr bytes.Buffer
		if code := updateCommand(args, &stdout, &stderr); code != exitUsage {
			t.Errorf("update %v = %d, want %d (stderr %q)", args, code, exitUsage, stderr.String())
		}
	}
}
