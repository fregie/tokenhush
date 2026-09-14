package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// checkBackend is a fake update service served over TLS by httptest. It lets
// the check client run its real HTTP path (key list, then manifest) without
// touching the network.
type checkBackend struct {
	srv          *httptest.Server
	keyListRaw   []byte
	manifestRaw  []byte
	keyListHits  int
	manifestHits int
}

func newCheckBackend(t *testing.T) *checkBackend {
	t.Helper()
	b := &checkBackend{}
	mux := http.NewServeMux()
	mux.HandleFunc(KeyListPath, func(w http.ResponseWriter, r *http.Request) {
		b.keyListHits++
		if b.keyListRaw == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b.keyListRaw)
	})
	mux.HandleFunc(ManifestPath, func(w http.ResponseWriter, r *http.Request) {
		b.manifestHits++
		if b.manifestRaw == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b.manifestRaw)
	})
	b.srv = httptest.NewTLSServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

func newCheckerFor(t *testing.T, v *Verifier, b *checkBackend, goos, goarch string) *Checker {
	t.Helper()
	c, err := NewChecker(CheckConfig{
		Source:     Source{Kind: SourceSelfManaged, Exe: "/home/me/.local/bin/tokenhush"},
		Channel:    DefaultChannel,
		BaseURL:    b.srv.URL,
		Verifier:   v,
		HTTPClient: b.srv.Client(),
		GOOS:       goos,
		GOARCH:     goarch,
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	return c
}

func keyListFor(upd testKey, serial uint64) KeyList {
	return KeyList{
		Serial:    serial,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{upd.updateKey()},
	}
}

// TestCheckerRefreshesKeysThenVerifiesManifest is the happy path: the root-
// signed key list installs the update key, and the manifest it signs is then
// accepted.
func TestCheckerRefreshesKeysThenVerifiesManifest(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = "0.3.0"

	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, root.signKeyList(t, keyListFor(upd, 1)))
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, baseManifest()))

	res, err := newCheckerFor(t, v, b, "linux", "amd64").Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.UpdateAvailable || res.LatestVersion != "0.4.0" || res.CurrentVersion != "0.3.0" {
		t.Fatalf("result = %+v, want update available 0.3.0 -> 0.4.0", res)
	}
	if b.keyListHits != 1 || b.manifestHits != 1 {
		t.Fatalf("hits keylist=%d manifest=%d, want 1/1", b.keyListHits, b.manifestHits)
	}
}

// TestCheckerRefusesManifestBeforeKeyList asserts the ordering: with no key
// list the client has no update key, so it must never fetch or accept the
// manifest.
func TestCheckerRefusesManifestBeforeKeyList(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)

	b := newCheckBackend(t)
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, baseManifest()))

	_, err := newCheckerFor(t, v, b, "linux", "amd64").Check(context.Background())
	if !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("Check error = %v, want ErrHTTPStatus (key list unavailable)", err)
	}
	if b.manifestHits != 0 {
		t.Fatalf("manifest fetched %d times, want 0: the key list must be applied first", b.manifestHits)
	}
}

// TestCheckerRejectsUntrustedKeyList asserts a key list signed by a root the
// client does not trust cannot install an update key.
func TestCheckerRejectsUntrustedKeyList(t *testing.T) {
	trusted := newTestKey("root-1", 90)
	attacker := newTestKey("root-evil", 91)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, trusted)

	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, attacker.signKeyList(t, keyListFor(upd, 1)))
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, baseManifest()))

	_, err := newCheckerFor(t, v, b, "linux", "amd64").Check(context.Background())
	if !errors.Is(err, ErrUnknownKey) && !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Check error = %v, want a key rejection", err)
	}
	if b.manifestHits != 0 {
		t.Fatalf("manifest fetched %d times, want 0", b.manifestHits)
	}
}

// TestCheckerRejectsTamperedKeyList asserts a key list modified after signing
// fails verification.
func TestCheckerRejectsTamperedKeyList(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)

	tampered := root.signKeyList(t, keyListFor(upd, 1))
	tampered.Serial = 2
	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, tampered)
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, baseManifest()))

	_, err := newCheckerFor(t, v, b, "linux", "amd64").Check(context.Background())
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Check error = %v, want ErrBadSignature", err)
	}
	if b.manifestHits != 0 {
		t.Fatalf("manifest fetched %d times, want 0", b.manifestHits)
	}
}

// TestCheckerRejectsExpiredKeyList asserts an expired key list is refused.
func TestCheckerRejectsExpiredKeyList(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)

	kl := keyListFor(upd, 1)
	kl.Expires = fixedNow.Add(-time.Minute)
	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, root.signKeyList(t, kl))
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, baseManifest()))

	_, err := newCheckerFor(t, v, b, "linux", "amd64").Check(context.Background())
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Check error = %v, want ErrExpired", err)
	}
	if b.manifestHits != 0 {
		t.Fatalf("manifest fetched %d times, want 0", b.manifestHits)
	}
}

// TestCheckerRejectsReplayedKeyList asserts an older key list cannot be
// replayed to revive a rotated-out update key, and that the manifest is never
// fetched once the key list is rejected.
func TestCheckerRejectsReplayedKeyList(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = "0.3.0"

	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, root.signKeyList(t, keyListFor(upd, 5)))
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, baseManifest()))
	c := newCheckerFor(t, v, b, "linux", "amd64")

	if _, err := c.Check(context.Background()); err != nil {
		t.Fatalf("first Check: %v", err)
	}

	b.keyListRaw = marshalDoc(t, root.signKeyList(t, keyListFor(upd, 4)))
	if _, err := c.Check(context.Background()); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replayed key list error = %v, want ErrReplayed", err)
	}
	if b.manifestHits != 1 {
		t.Fatalf("manifest hits = %d, want 1: a rejected key list must stop the check", b.manifestHits)
	}
}

// TestCheckerToleratesIdenticalKeyListRefetch asserts the online client treats
// an identical re-fetch of the current key list as a replay rather than an
// attack, so a second run against an unchanged channel still installs the keys.
func TestCheckerToleratesIdenticalKeyListRefetch(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)

	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, root.signKeyList(t, keyListFor(upd, 5)))
	c := newCheckerFor(t, v, b, "linux", "amd64")

	if err := c.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("first RefreshKeys: %v", err)
	}
	if err := c.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("identical re-fetch rejected: %v", err)
	}
}

// TestCheckerRejectsManifestChannelMismatch asserts a valid document for
// another channel is refused.
func TestCheckerRejectsManifestChannelMismatch(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = "0.3.0"

	m := baseManifest()
	m.Channel = "beta"
	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, root.signKeyList(t, keyListFor(upd, 1)))
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))

	_, err := newCheckerFor(t, v, b, "linux", "amd64").Check(context.Background())
	if !errors.Is(err, ErrChannelMismatch) {
		t.Fatalf("Check error = %v, want ErrChannelMismatch", err)
	}
}

// TestCheckerReportsPlatformMismatch asserts a validly signed manifest for
// another os/arch is reported as not applicable instead of offered.
func TestCheckerReportsPlatformMismatch(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = "0.3.0"

	m := baseManifest()
	m.OS, m.Arch = "plan9", "mips"
	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, root.signKeyList(t, keyListFor(upd, 1)))
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))

	res, err := newCheckerFor(t, v, b, "linux", "amd64").Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.PlatformMismatch || res.UpdateAvailable {
		t.Fatalf("result = %+v, want platform mismatch with no update offered", res)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("a platform mismatch must warn, never stay silent")
	}
}

// TestCheckerReportsUpToDate asserts an equal version reports no update.
func TestCheckerReportsUpToDate(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = "0.4.0"

	b := newCheckBackend(t)
	b.keyListRaw = marshalDoc(t, root.signKeyList(t, keyListFor(upd, 1)))
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, baseManifest()))

	res, err := newCheckerFor(t, v, b, "linux", "amd64").Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.UpdateAvailable {
		t.Fatalf("result = %+v, want up to date", res)
	}
}

// TestNewCheckerRefusesNonSelfManaged asserts a package-managed install can
// never enter the online check path.
func TestNewCheckerRefusesNonSelfManaged(t *testing.T) {
	_, err := NewChecker(CheckConfig{
		Source:   Source{Kind: SourceBrew, Exe: "/opt/homebrew/bin/tokenhush"},
		Channel:  DefaultChannel,
		BaseURL:  DefaultBaseURL,
		Verifier: &Verifier{},
	})
	if !errors.Is(err, ErrNotSelfManaged) {
		t.Fatalf("NewChecker error = %v, want ErrNotSelfManaged", err)
	}
}
