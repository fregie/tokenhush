package update

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// applyBackend is a fake update service served over TLS by httptest. It lets
// the engine run its real HTTP path (fetch, verify, download, hash) without
// ever touching the network.
type applyBackend struct {
	srv          *httptest.Server
	artifact     []byte
	manifestRaw  []byte
	revRaw       []byte
	manifestHits int
	revHits      int
	artifactHits int
}

func newApplyBackend(t *testing.T) *applyBackend {
	t.Helper()
	b := &applyBackend{}
	mux := http.NewServeMux()
	mux.HandleFunc(ManifestPath, func(w http.ResponseWriter, r *http.Request) {
		b.manifestHits++
		if b.manifestRaw == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b.manifestRaw)
	})
	mux.HandleFunc(RevocationsPath, func(w http.ResponseWriter, r *http.Request) {
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

func (b *applyBackend) artifactURL() string { return b.srv.URL + "/artifacts/tokenhush" }

func engineVerifier(t *testing.T, current string) (*Verifier, testKey, testKey) {
	t.Helper()
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = current
	installKeyList(t, v, root, upd)
	return v, root, upd
}

func engineManifest(artifact []byte, url string) Manifest {
	m := baseManifest()
	m.URL = url
	m.SHA256 = sha256Hex(artifact)
	return m
}

func emptyRevocations() RevocationList {
	return RevocationList{Channel: "stable", Serial: 1, NotBefore: validFrom(), Expires: validUntil()}
}

func newEngine(t *testing.T, v *Verifier, b *applyBackend, target, goos string) *Applier {
	t.Helper()
	a, err := NewApplier(ApplyConfig{
		Source:     Source{Kind: SourceSelfManaged, Exe: target},
		Channel:    "stable",
		BaseURL:    b.srv.URL,
		Verifier:   v,
		HTTPClient: b.srv.Client(),
		GOOS:       goos,
	})
	if err != nil {
		t.Fatalf("NewApplier: %v", err)
	}
	return a
}

// assertUnchanged proves a rejected update left the original binary
// byte-for-byte identical with no staging residue.
func assertUnchanged(t *testing.T, target string, original []byte, b *applyBackend, wantArtifactHits int) {
	t.Helper()
	if got := readBinary(t, target); !bytes.Equal(got, original) {
		t.Fatalf("original binary changed: got %q, want %q", got, original)
	}
	l := mustLayout(t, target)
	if fileExists(l.new) || fileExists(l.journal) {
		t.Fatal("a rejected update must not leave staging files")
	}
	if b.artifactHits != wantArtifactHits {
		t.Fatalf("artifact hits = %d, want %d", b.artifactHits, wantArtifactHits)
	}
}

// TestApplyHappyPathInstallsVerifiedUpdateAndRollsBack is the happy path: a
// valid manifest + independent revocation document upgrades the binary and
// keeps the original as last-known-good, and Rollback restores it.
func TestApplyHappyPathInstallsVerifiedUpdateAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	res, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != ApplyUpdated || res.Version != "0.4.0" || res.Serial != 10 {
		t.Fatalf("result = %+v, want updated 0.4.0 serial 10", res)
	}
	if got := readBinary(t, target); !bytes.Equal(got, b.artifact) {
		t.Fatalf("target = %q, want the downloaded artifact", got)
	}
	l := mustLayout(t, target)
	if got := readBinary(t, l.lkg); !bytes.Equal(got, original) {
		t.Fatalf("last-known-good = %q, want the original binary", got)
	}
	if fileExists(l.new) || fileExists(l.journal) {
		t.Fatal("a completed apply must leave no staging files")
	}
	if err := Rollback(target); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := readBinary(t, target); !bytes.Equal(got, original) {
		t.Fatalf("after rollback target = %q, want the original binary", got)
	}
}

// TestApplyBadSignatureLeavesOriginalUntouched asserts a tampered manifest is
// rejected by the reused B4 verifier before the artifact is ever fetched.
func TestApplyBadSignatureLeavesOriginalUntouched(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	tampered := upd.signManifest(t, m)
	tampered.Version = "9.9.9"
	b.manifestRaw = marshalDoc(t, tampered)
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	_, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Apply error = %v, want ErrBadSignature", err)
	}
	assertUnchanged(t, target, original, b, 0)
}

// TestApplyBadHashLeavesOriginalUntouched asserts a downloaded artifact whose
// digest differs from the signed manifest is discarded and never swapped in.
func TestApplyBadHashLeavesOriginalUntouched(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("TAMPERED-AT-REST")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest([]byte("WHAT-THE-MANIFEST-PROMISED"), b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	_, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("Apply error = %v, want ErrHashMismatch", err)
	}
	assertUnchanged(t, target, original, b, 1)
}

// TestApplyRevokedVersionIsRejected asserts the independent revocation document
// is the kill-switch: a revoked version is refused before download.
func TestApplyRevokedVersionIsRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	rev := emptyRevocations()
	rev.RevokedVersions = []string{"0.4.0"}
	b.revRaw = marshalDoc(t, upd.signRevocations(t, rev))

	_, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("Apply error = %v, want ErrRevoked", err)
	}
	assertUnchanged(t, target, original, b, 0)
}

// TestApplyRevokedSerialIsRejected covers the serial half of the kill-switch.
func TestApplyRevokedSerialIsRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	rev := emptyRevocations()
	rev.RevokedSerials = []uint64{10}
	b.revRaw = marshalDoc(t, upd.signRevocations(t, rev))

	_, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("Apply error = %v, want ErrRevoked", err)
	}
	assertUnchanged(t, target, original, b, 0)
}

// TestApplyRejectsForgedRevocationDocument asserts the kill-switch is verified
// with the same update trust root and fetched before the manifest, so a forged
// revocation document fails closed without ever trusting the manifest.
func TestApplyRejectsForgedRevocationDocument(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	forged := upd.signRevocations(t, emptyRevocations())
	forged.Serial = 99
	b.revRaw = marshalDoc(t, forged)

	_, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Apply error = %v, want ErrBadSignature", err)
	}
	if b.manifestHits != 0 {
		t.Fatalf("manifest was fetched %d times, want 0: the revocation doc must be verified first", b.manifestHits)
	}
	assertUnchanged(t, target, original, b, 0)
}

// TestApplyUpToDateDoesNotDownload asserts an equal-version manifest is a
// no-op: no artifact is fetched and the binary is untouched.
func TestApplyUpToDateDoesNotDownload(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.4.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("SAME-VERSION-BUILD")
	v, _, upd := engineVerifier(t, "0.4.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	res, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != ApplyUpToDate {
		t.Fatalf("result = %+v, want up-to-date", res)
	}
	assertUnchanged(t, target, original, b, 0)
}

// TestApplyWindowsStagesThenCompletesOnRecover asserts the Windows path never
// replaces the running binary in-process: it stages a pending-restart journal
// and a later Recover completes the swap.
func TestApplyWindowsStagesThenCompletesOnRecover(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	res, err := newEngine(t, v, b, target, "windows").Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Status != ApplyPending {
		t.Fatalf("result = %+v, want pending-restart", res)
	}
	l := mustLayout(t, target)
	if !bytes.Equal(readBinary(t, target), original) {
		t.Fatal("the Windows path must not replace the running binary in-process")
	}
	if !fileExists(l.new) || !fileExists(l.journal) {
		t.Fatal("the Windows path must stage a candidate and a journal")
	}
	if !bytes.Equal(readBinary(t, l.lkg), original) {
		t.Fatal("the Windows path must copy the current binary to last-known-good")
	}

	got, err := Recover(target)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != RecoveryCompleted {
		t.Fatalf("Recover = %q, want %q", got, RecoveryCompleted)
	}
	if !bytes.Equal(readBinary(t, target), b.artifact) {
		t.Fatal("Recover must complete the pending Windows swap")
	}
	if !bytes.Equal(readBinary(t, l.lkg), original) {
		t.Fatal("Recover must preserve last-known-good")
	}
}

// TestApplyReplayIsIdempotentAndRollbackIsRejected asserts a second run with
// the unchanged (already accepted) documents reports up-to-date without
// re-downloading, while a genuinely older manifest is still refused.
func TestApplyReplayIsIdempotentAndRollbackIsRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))
	a := newEngine(t, v, b, target, "linux")

	if res, err := a.Apply(context.Background()); err != nil || res.Status != ApplyUpdated {
		t.Fatalf("first Apply = (%+v, %v), want updated", res, err)
	}
	if res, err := a.Apply(context.Background()); err != nil || res.Status != ApplyUpToDate {
		t.Fatalf("second Apply = (%+v, %v), want up-to-date (replay tolerated)", res, err)
	}
	if b.artifactHits != 1 {
		t.Fatalf("artifact hits = %d, want 1: the second run must not re-download", b.artifactHits)
	}

	rollback := engineManifest(b.artifact, b.artifactURL())
	rollback.Version, rollback.Serial = "0.4.1", 9
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, rollback))
	if res, err := a.Apply(context.Background()); !errors.Is(err, ErrReplayed) {
		t.Fatalf("older-serial Apply = (%+v, %v), want ErrReplayed", res, err)
	}
}

// TestApplyFailedDownloadDoesNotSuppressRetry reproduces the high-water
// suppression bug: verification advances the manifest high-water mark, so a
// download that fails *after* verification must not make every later run report
// up-to-date. Once the artifact is reachable again the update must install.
func TestApplyFailedDownloadDoesNotSuppressRetry(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))
	a := newEngine(t, v, b, target, "linux")

	// First run: the artifact endpoint is unavailable, so the download fails
	// after the manifest already advanced the high-water mark.
	artifact := b.artifact
	b.artifact = nil
	if _, err := a.Apply(context.Background()); err == nil {
		t.Fatal("first Apply must fail when the artifact is unreachable")
	}
	if got := readBinary(t, target); !bytes.Equal(got, original) {
		t.Fatalf("failed download changed the binary: %q", got)
	}

	// Second run: the artifact is back. The update must install rather than be
	// silently reported as up-to-date because the serial was already seen.
	b.artifact = artifact
	res, err := a.Apply(context.Background())
	if err != nil {
		t.Fatalf("retry Apply: %v", err)
	}
	if res.Status != ApplyUpdated {
		t.Fatalf("retry Apply = %+v, want updated (a failed download must not suppress the update)", res)
	}
	if got := readBinary(t, target); !bytes.Equal(got, artifact) {
		t.Fatalf("retry did not install the artifact: %q", got)
	}
}

// TestApplyRejectsUntrustedTLSCertificate asserts the default client refuses an
// unknown origin: httptest's self-signed certificate is not trusted, so nothing
// is fetched and the binary is untouched.
func TestApplyRejectsUntrustedTLSCertificate(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	a, err := NewApplier(ApplyConfig{
		Source:   Source{Kind: SourceSelfManaged, Exe: target},
		Channel:  "stable",
		BaseURL:  b.srv.URL,
		Verifier: v,
		GOOS:     "linux",
	})
	if err != nil {
		t.Fatalf("NewApplier: %v", err)
	}
	if _, err := a.Apply(context.Background()); err == nil {
		t.Fatal("Apply must fail when the server certificate is not trusted")
	}
	assertUnchanged(t, target, original, b, 0)
}

// TestApplyAbortsWhenRevocationsUnavailable asserts the independent kill-switch
// is a hard precondition: an unreachable revocation feed fails closed without
// ever trusting the manifest.
func TestApplyAbortsWhenRevocationsUnavailable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.4.0", 10
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = nil

	_, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("Apply error = %v, want ErrHTTPStatus", err)
	}
	if b.manifestHits != 0 {
		t.Fatalf("manifest fetched %d times, want 0: revocations must be available first", b.manifestHits)
	}
	assertUnchanged(t, target, original, b, 0)
}

// TestApplyRejectsChannelMismatch asserts a valid document for another channel
// is refused: the signature proves authenticity, not the requested channel.
func TestApplyRejectsChannelMismatch(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-BINARY-0.3.0")
	writeBinary(t, target, original)

	b := newApplyBackend(t)
	b.artifact = []byte("NEW-BINARY-0.4.0")
	v, _, upd := engineVerifier(t, "0.3.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial, m.Channel = "0.4.0", 10, "beta"
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	_, err := newEngine(t, v, b, target, "linux").Apply(context.Background())
	if !errors.Is(err, ErrChannelMismatch) {
		t.Fatalf("Apply error = %v, want ErrChannelMismatch", err)
	}
	assertUnchanged(t, target, original, b, 0)
}

// TestApplyRefusesNonSelfManagedWithoutNetworkOrDisk is the structural
// guarantee for the "brew never self-replaces" acceptance: construction fails
// before any HTTP call or write, and the install tree is untouched.
func TestApplyRefusesNonSelfManagedWithoutNetworkOrDisk(t *testing.T) {
	for _, kind := range []SourceKind{SourceBrew, SourceScoop, SourceUnknown} {
		t.Run(string(kind), func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "tokenhush")
			original := []byte("MANAGER-OWNED-BINARY")
			writeBinary(t, target, original)

			b := newApplyBackend(t)
			b.artifact = []byte("ROGUE-SELF-REPLACE")
			b.manifestRaw = []byte("{}")
			b.revRaw = []byte("{}")

			_, err := NewApplier(ApplyConfig{
				Source:     Source{Kind: kind, Exe: target},
				Channel:    "stable",
				BaseURL:    b.srv.URL,
				Verifier:   &Verifier{},
				HTTPClient: b.srv.Client(),
			})
			if !errors.Is(err, ErrNotSelfManaged) {
				t.Fatalf("NewApplier error = %v, want ErrNotSelfManaged", err)
			}
			if b.manifestHits+b.revHits+b.artifactHits != 0 {
				t.Fatalf("refusal must not make any HTTP call: %d", b.manifestHits+b.revHits+b.artifactHits)
			}
			assertUnchanged(t, target, original, b, 0)
			if dirEntries, err := os.ReadDir(dir); err != nil || len(dirEntries) != 1 {
				t.Fatalf("refusal must not write to disk: entries=%v err=%v", dirEntries, err)
			}
		})
	}
}
