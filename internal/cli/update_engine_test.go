package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/update"
)

// The trusted test root and the update key its key list advertises. The private
// halves live only in this test, so the CLI's real online path is exercised
// against keys the production embedded root would never trust.
const (
	checkRootID = "root-test"
	checkUpdID  = "upd-test"
	checkChan   = "stable"
)

// updateBackend is a fake update service served over TLS by httptest: the key
// list, manifest, independent revocation document and artifact, with hit
// counters so a test can prove what was and was not fetched.
type updateBackend struct {
	srv          *httptest.Server
	keyListRaw   []byte
	manifestRaw  []byte
	revRaw       []byte
	artifact     []byte
	keyListHits  int
	manifestHits int
	revHits      int
	artifactHits int
}

func newUpdateBackend(t *testing.T) *updateBackend {
	t.Helper()
	b := &updateBackend{}
	mux := http.NewServeMux()
	mux.HandleFunc(update.KeyListPath, func(w http.ResponseWriter, r *http.Request) {
		b.keyListHits++
		if b.keyListRaw == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b.keyListRaw)
	})
	mux.HandleFunc(update.ManifestPath, func(w http.ResponseWriter, r *http.Request) {
		b.manifestHits++
		if b.manifestRaw == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b.manifestRaw)
	})
	mux.HandleFunc(update.RevocationsPath, func(w http.ResponseWriter, r *http.Request) {
		b.revHits++
		if b.revRaw == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b.revRaw)
	})
	mux.HandleFunc("/artifacts/", func(w http.ResponseWriter, r *http.Request) {
		b.artifactHits++
		if b.artifact == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b.artifact)
	})
	b.srv = httptest.NewTLSServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return raw
}

// updateTestKeys returns the trusted root pair and the advertised update pair.
func updateTestKeys() (ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey) {
	rootPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{90}, ed25519.SeedSize))
	updPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	return rootPriv.Public().(ed25519.PublicKey), rootPriv, updPriv.Public().(ed25519.PublicKey), updPriv
}

func signUpdateKeyList(t *testing.T, rootPriv ed25519.PrivateKey, updPub ed25519.PublicKey, from, until time.Time) []byte {
	t.Helper()
	kl := update.KeyList{
		Serial:    1,
		NotBefore: from,
		Expires:   until,
		Keys: []update.UpdateKey{{
			KeyID: checkUpdID, PublicKey: base64URL(updPub), NotBefore: from, Expires: until,
		}},
	}
	kl.KeyID = checkRootID
	kl.Signature = base64URL(ed25519.Sign(rootPriv, update.KeyListSigningInput(kl)))
	return mustJSON(t, kl)
}

func signUpdateManifest(t *testing.T, updPriv ed25519.PrivateKey, artifact []byte, url string, from, until time.Time) []byte {
	t.Helper()
	sum := sha256.Sum256(artifact)
	m := update.Manifest{
		Version:   "0.4.0",
		OS:        "linux",
		Arch:      "amd64",
		URL:       url,
		SHA256:    hex.EncodeToString(sum[:]),
		Channel:   checkChan,
		Serial:    10,
		NotBefore: from,
		Expires:   until,
	}
	m.KeyID = checkUpdID
	m.Signature = base64URL(ed25519.Sign(updPriv, update.ManifestSigningInput(m)))
	return mustJSON(t, m)
}

func signUpdateRevocations(t *testing.T, updPriv ed25519.PrivateKey, from, until time.Time) []byte {
	t.Helper()
	rev := update.RevocationList{Channel: checkChan, Serial: 1, NotBefore: from, Expires: until}
	rev.KeyID = checkUpdID
	rev.Signature = base64URL(ed25519.Sign(updPriv, update.RevocationSigningInput(rev)))
	return mustJSON(t, rev)
}

// newTestUpdateEngine builds a real checker/applier over the httptest backend,
// trusting the injected test root instead of the embedded production root.
func newTestUpdateEngine(t *testing.T, b *updateBackend, src update.Source, check bool) *updateEngine {
	t.Helper()
	rootPub, _, _, _ := updateTestKeys()
	verifier := &update.Verifier{
		Roots:          []update.Key{{ID: checkRootID, Public: rootPub}},
		CurrentVersion: "0.3.0",
		HighWater:      update.NewMemHighWater(),
	}
	checker, err := update.NewChecker(update.CheckConfig{
		Source:     src,
		Channel:    checkChan,
		BaseURL:    b.srv.URL,
		Verifier:   verifier,
		HTTPClient: b.srv.Client(),
		GOOS:       "linux",
		GOARCH:     "amd64",
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	eng := &updateEngine{checker: checker}
	if check {
		return eng
	}
	applier, err := update.NewApplier(update.ApplyConfig{
		Source:     src,
		Channel:    checkChan,
		BaseURL:    b.srv.URL,
		Target:     src.Exe,
		Verifier:   verifier,
		HTTPClient: b.srv.Client(),
		GOOS:       "linux",
		GOARCH:     "amd64",
	})
	if err != nil {
		t.Fatalf("NewApplier: %v", err)
	}
	eng.applier = applier
	return eng
}

func writeSelfManagedBinary(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	exe := filepath.Join(dir, ".local", "bin", "tokenhush")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("ORIGINAL-BINARY-0.3.0")
	if err := os.WriteFile(exe, original, 0o755); err != nil {
		t.Fatal(err)
	}
	return exe, original
}

// TestUpdateCommandSelfManagedCheckReportsAvailableWithoutWriting asserts a
// self-managed --check verifies the key list and manifest, reports the
// available update, and writes nothing.
func TestUpdateCommandSelfManagedCheckReportsAvailableWithoutWriting(t *testing.T) {
	_, rootPriv, updPub, updPriv := updateTestKeys()
	from, until := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

	dir := t.TempDir()
	exe, _ := writeSelfManagedBinary(t, dir)
	before := snapshotTree(t, dir)

	b := newUpdateBackend(t)
	b.keyListRaw = signUpdateKeyList(t, rootPriv, updPub, from, until)
	b.manifestRaw = signUpdateManifest(t, updPriv, []byte("NEW"), b.srv.URL+"/artifacts/tokenhush", from, until)

	src := update.Source{Kind: update.SourceSelfManaged, Exe: exe}
	stubUpdate(t, src, failIfRun(t))
	stubUpdateEngine(t, func(s update.Source, check bool) (*updateEngine, error) {
		if !check {
			t.Error("--check must build a check-only engine")
		}
		return newTestUpdateEngine(t, b, s, true), nil
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update", "--check"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "update available: 0.4.0") {
		t.Errorf("stdout = %q, want an availability report", stdout.String())
	}
	if after := snapshotTree(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("--check must not write: before=%v after=%v", before, after)
	}
	if b.artifactHits != 0 {
		t.Fatalf("--check fetched the artifact %d times, want 0", b.artifactHits)
	}
}

// TestUpdateCommandSelfManagedCheckRejectsUntrustedKeyList asserts a key list
// signed by a root outside the trusted set stops the check before the manifest
// is fetched, and the install tree stays byte-for-byte untouched.
func TestUpdateCommandSelfManagedCheckRejectsUntrustedKeyList(t *testing.T) {
	_, _, updPub, updPriv := updateTestKeys()
	attackerPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, ed25519.SeedSize))
	from, until := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

	dir := t.TempDir()
	exe, _ := writeSelfManagedBinary(t, dir)
	before := snapshotTree(t, dir)

	b := newUpdateBackend(t)
	b.keyListRaw = signUpdateKeyList(t, attackerPriv, updPub, from, until)
	b.manifestRaw = signUpdateManifest(t, updPriv, []byte("NEW"), b.srv.URL+"/artifacts/tokenhush", from, until)

	src := update.Source{Kind: update.SourceSelfManaged, Exe: exe}
	stubUpdate(t, src, failIfRun(t))
	stubUpdateEngine(t, func(s update.Source, check bool) (*updateEngine, error) {
		return newTestUpdateEngine(t, b, s, check), nil
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update", "--check"}, &stdout, &stderr); code != ExitFailure {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, ExitFailure, stderr.String())
	}
	if b.manifestHits != 0 {
		t.Fatalf("manifest fetched %d times, want 0: the key list must verify first", b.manifestHits)
	}
	if after := snapshotTree(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("a rejected check must not write: before=%v after=%v", before, after)
	}
}

// TestUpdateCommandSelfManagedInstallAppliesVerifiedUpdate asserts a
// self-managed `update` installs the signed release through the two-phase
// applier.
func TestUpdateCommandSelfManagedInstallAppliesVerifiedUpdate(t *testing.T) {
	_, rootPriv, updPub, updPriv := updateTestKeys()
	from, until := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

	dir := t.TempDir()
	exe, _ := writeSelfManagedBinary(t, dir)
	artifact := []byte("NEW-BINARY-0.4.0")

	b := newUpdateBackend(t)
	b.artifact = artifact
	b.keyListRaw = signUpdateKeyList(t, rootPriv, updPub, from, until)
	b.manifestRaw = signUpdateManifest(t, updPriv, artifact, b.srv.URL+"/artifacts/tokenhush", from, until)
	b.revRaw = signUpdateRevocations(t, updPriv, from, until)

	src := update.Source{Kind: update.SourceSelfManaged, Exe: exe}
	stubUpdate(t, src, failIfRun(t))
	stubUpdateEngine(t, func(s update.Source, check bool) (*updateEngine, error) {
		if check {
			t.Error("an install must build the full engine")
		}
		return newTestUpdateEngine(t, b, s, false), nil
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, artifact) {
		t.Fatalf("target = %q, want the downloaded artifact", got)
	}
}

// TestUpdateCommandSelfManagedInstallRejectedKeepsBinary asserts a tampered
// manifest is refused and the running binary is left byte-for-byte unchanged.
func TestUpdateCommandSelfManagedInstallRejectedKeepsBinary(t *testing.T) {
	_, rootPriv, updPub, updPriv := updateTestKeys()
	from, until := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

	dir := t.TempDir()
	exe, original := writeSelfManagedBinary(t, dir)

	b := newUpdateBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	b.keyListRaw = signUpdateKeyList(t, rootPriv, updPub, from, until)
	b.manifestRaw = signUpdateManifest(t, updPriv, b.artifact, b.srv.URL+"/artifacts/tokenhush", from, until)
	b.revRaw = signUpdateRevocations(t, updPriv, from, until)

	var tampered update.Manifest
	if err := json.Unmarshal(b.manifestRaw, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Version = "9.9.9"
	b.manifestRaw = mustJSON(t, tampered)

	src := update.Source{Kind: update.SourceSelfManaged, Exe: exe}
	stubUpdate(t, src, failIfRun(t))
	stubUpdateEngine(t, func(s update.Source, check bool) (*updateEngine, error) {
		return newTestUpdateEngine(t, b, s, false), nil
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update"}, &stdout, &stderr); code != ExitFailure {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, ExitFailure, stderr.String())
	}
	if got, err := os.ReadFile(exe); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("a rejected install must leave the binary unchanged: got %q err %v", got, err)
	}
	if b.artifactHits != 0 {
		t.Fatalf("a rejected manifest must not trigger a download, hits=%d", b.artifactHits)
	}
}

// TestUpdateCommandSelfManagedDisabledMakesNoRequestForInstall is the install
// half of the switch guard: with the switch set, `update` builds no engine.
func TestUpdateCommandSelfManagedDisabledMakesNoRequestForInstall(t *testing.T) {
	t.Setenv(EnvNoUpdateCheck, "1")
	stubUpdate(t, update.Source{Kind: update.SourceSelfManaged, Exe: "/home/me/.local/bin/tokenhush"}, failIfRun(t))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), EnvNoUpdateCheck) {
		t.Errorf("output must name the switch, got %q", stdout.String())
	}
}
