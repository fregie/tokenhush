package rules

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testNow is the fixed clock every client test verifies freshness against.
var testNow = time.Unix(1_800_000_000, 0)

// fakeRuleBackend serves signed rule manifests and bundles over TLS so tests
// exercise the real HTTP client without touching the network.
type fakeRuleBackend struct {
	srv         *httptest.Server
	keyID       string
	pub         ed25519.PublicKey
	priv        ed25519.PrivateKey
	manifest    []byte
	bundle      []byte
	revocations []byte

	mu             sync.Mutex
	manifestStatus int
	bundleStatus   int
	revStatus      int
	manifestCalls  int
	bundleCalls    int
}

// sharedTestKey is the single rule key every fake backend signs with, so packs
// cached by one backend still verify under another (as a real rotation-stable
// key would).
var (
	clientKeyOnce sync.Once
	clientPub     ed25519.PublicKey
	clientPriv    ed25519.PrivateKey
)

func sharedTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	clientKeyOnce.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		clientPub, clientPriv = pub, priv
	})
	return clientPub, clientPriv
}

func newFakeBackend(t *testing.T, serial uint64, revoked []uint64) *fakeRuleBackend {
	t.Helper()
	pub, priv := sharedTestKey()
	b := &fakeRuleBackend{keyID: "rules-test", pub: pub, priv: priv}
	pack := Pack{
		Channel:          "stable",
		MinBinaryVersion: "0.3.0",
		Serial:           serial,
		KeyID:            b.keyID,
		NotBefore:        testNow.Add(-time.Hour),
		Expires:          testNow.Add(24 * time.Hour),
		Config: Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
			ID: "ticket", Type: RuleRegex, Pattern: `PROJ-[0-9]{4,}`, Action: "warn",
		}}},
	}
	pack.Signature = signInput(priv, PackSigningInput(pack))
	b.bundle = mustJSON(t, pack)

	sum := sha256.Sum256(b.bundle)
	manifest := Manifest{
		Channel:          "stable",
		SchemaVersion:    SchemaVersion,
		MinBinaryVersion: "0.3.0",
		Serial:           serial,
		KeyID:            b.keyID,
		NotBefore:        testNow.Add(-time.Hour),
		Expires:          testNow.Add(24 * time.Hour),
		BundleSHA256:     hex.EncodeToString(sum[:]),
		Bundle:           "rules/stable/" + itoa(serial) + ".json",
		RevokedSerials:   revoked,
	}
	manifest.Signature = signInput(priv, ManifestSigningInput(manifest))
	b.manifest = mustJSON(t, manifest)
	b.revocations = mustJSON(t, signedRevocations(priv, b.keyID, 1, nil))

	mux := http.NewServeMux()
	mux.HandleFunc(ManifestPath, func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.manifestCalls++
		status := b.manifestStatus
		body := b.manifest
		b.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write(body)
	})
	mux.HandleFunc(BundlePath, func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.bundleCalls++
		status := b.bundleStatus
		body := b.bundle
		b.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write(body)
	})
	mux.HandleFunc(RevocationsPath, func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		status := b.revStatus
		body := b.revocations
		b.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write(body)
	})
	b.srv = httptest.NewTLSServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

// signedRevocations builds and signs an independent revocation document.
func signedRevocations(priv ed25519.PrivateKey, keyID string, serial uint64, revoked []uint64) RevocationList {
	rev := RevocationList{
		Channel:        "stable",
		Serial:         serial,
		KeyID:          keyID,
		NotBefore:      testNow.Add(-time.Hour),
		Expires:        testNow.Add(24 * time.Hour),
		RevokedSerials: revoked,
	}
	rev.Signature = signInput(priv, RevocationSigningInput(rev))
	return rev
}

// setRevocations replaces the served independent revocation document.
func (b *fakeRuleBackend) setRevocations(rev RevocationList) {
	raw, err := json.Marshal(rev)
	if err != nil {
		panic(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revocations = raw
}

// setRevStatus makes the revocation endpoint return a non-200 status.
func (b *fakeRuleBackend) setRevStatus(status int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revStatus = status
}

func (b *fakeRuleBackend) calls() (manifest, bundle int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.manifestCalls, b.bundleCalls
}

func itoa(n uint64) string {
	return strconv.FormatUint(n, 10)
}

type warnRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnRecorder) warn(msg string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, msg)
}

func (w *warnRecorder) all() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.msgs...)
}

func (w *warnRecorder) contains(substr string) bool {
	for _, m := range w.all() {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

func newTestClient(t *testing.T, b *fakeRuleBackend, root string, warn *warnRecorder, now time.Time) *Client {
	t.Helper()
	cache, err := OpenFileCache(root)
	if err != nil {
		t.Fatalf("OpenFileCache: %v", err)
	}
	hw, err := OpenFileHighWater(filepath.Join(root, "highwater.json"))
	if err != nil {
		t.Fatalf("OpenFileHighWater: %v", err)
	}
	var sink func(string)
	if warn != nil {
		sink = warn.warn
	}
	return &Client{
		BaseURL: b.srv.URL,
		Channel: "stable",
		Verifier: &Verifier{
			Keys:                 []Key{{ID: b.keyID, Public: b.pub}},
			CurrentBinaryVersion: "0.4.0",
			Now:                  func() time.Time { return now },
		},
		Cache:      cache,
		HighWater:  hw,
		HTTPClient: b.srv.Client(),
		Warn:       sink,
	}
}

func TestSyncInstallsVerifiedPack(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	res, err := c.Sync(context.Background(), false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.Status != SyncUpdated || res.Serial != 7 {
		t.Fatalf("Sync() = %+v, want updated serial 7", res)
	}
	active, ok, err := c.Cache.Active()
	if err != nil || !ok || active != 7 {
		t.Fatalf("Active() = (%d,%v,%v), want 7,true,nil", active, ok, err)
	}
	highest, ok, _ := c.HighWater.Highest(KindRules)
	if !ok || highest != 7 {
		t.Fatalf("high-water = %d,%v, want 7,true", highest, ok)
	}
	state, err := c.Active()
	if err != nil || state.Config == nil || state.Serial != 7 {
		t.Fatalf("Active() = %+v,%v, want serial 7", state, err)
	}
	if len(warn.all()) != 0 {
		t.Fatalf("warnings = %v, want none", warn.all())
	}
}

// TestSyncRejectsBadSignatureAndFallsBack is the B7 failure acceptance: a
// tampered manifest is rejected and the client falls back to built-in defaults
// with a warning.
func TestSyncRejectsBadSignatureAndFallsBack(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	_, err := c.Sync(context.Background(), false)
	if err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	tampered := append([]byte(nil), b.manifest...)
	var m Manifest
	if err := json.Unmarshal(tampered, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	m.Bundle = "rules/stable/999.json"
	tampered = mustJSON(t, m)
	b.mu.Lock()
	b.manifest = tampered
	b.mu.Unlock()
	res, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrPackBadSignature) {
		t.Fatalf("Sync() error = %v, want ErrPackBadSignature", err)
	}
	if res.Status != SyncBuiltin {
		t.Fatalf("status = %v, want builtin-default", res.Status)
	}
	if !warn.contains("falling back") {
		t.Fatalf("warnings = %v, want a fallback warning", warn.all())
	}
	if _, ok, _ := c.Cache.Active(); ok {
		t.Fatal("active pack must be cleared after a rejected manifest")
	}
}

// TestSyncRejectsRevokedSerialAndFallsBack: a candidate whose serial is on the
// persisted revocation list is refused.
func TestSyncRejectsRevokedSerialAndFallsBack(t *testing.T) {
	b := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	if err := c.Cache.SetRevoked(RevokedList{Serials: []uint64{5}}); err != nil {
		t.Fatalf("SetRevoked: %v", err)
	}
	res, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrPackRevoked) {
		t.Fatalf("Sync() error = %v, want ErrPackRevoked", err)
	}
	if res.Status != SyncBuiltin {
		t.Fatalf("status = %v, want builtin-default", res.Status)
	}
	if !warn.contains("revoked") {
		t.Fatalf("warnings = %v, want a revocation warning", warn.all())
	}
	_, calls := b.calls()
	if calls != 0 {
		t.Fatalf("bundle calls = %d, want 0 (revoked before download)", calls)
	}
}

func TestSyncRejectsRollbackAndFallsBack(t *testing.T) {
	b := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	if err := c.HighWater.Advance(KindRules, 7); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	res, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrPackReplayed) {
		t.Fatalf("Sync() error = %v, want ErrPackReplayed", err)
	}
	if res.Status != SyncBuiltin {
		t.Fatalf("status = %v, want builtin-default", res.Status)
	}
}

// TestSyncReplayKeepsVerifiedActivePack is the N1 regression: a replayed older
// (validly signed) manifest must not clear the verified active pack, or a
// client that is served serial 4 after installing serial 5 would stay on the
// built-in defaults forever once the channel recovers to serial 5.
func TestSyncReplayKeepsVerifiedActivePack(t *testing.T) {
	root := t.TempDir()
	warn := &warnRecorder{}

	b5 := newFakeBackend(t, 5, nil)
	c := newTestClient(t, b5, root, warn, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("install serial 5: %v", err)
	}

	b4 := newFakeBackend(t, 4, nil)
	c4 := newTestClient(t, b4, root, warn, testNow)
	if _, err := c4.Sync(context.Background(), false); !errors.Is(err, ErrPackReplayed) {
		t.Fatalf("Sync() error = %v, want ErrPackReplayed", err)
	}
	if active, ok, _ := c4.Cache.Active(); !ok || active != 5 {
		t.Fatalf("active = %d,%v, want the verified serial 5 pack preserved after a rollback refusal", active, ok)
	}

	b5b := newFakeBackend(t, 5, nil)
	c5 := newTestClient(t, b5b, root, warn, testNow)
	res, err := c5.Sync(context.Background(), false)
	if err != nil {
		t.Fatalf("recovered Sync() error = %v", err)
	}
	if res.Status != SyncCurrent || res.Serial != 5 {
		t.Fatalf("recovered Sync() = %+v, want current serial 5", res)
	}
	state, err := c5.Active()
	if err != nil || state.Config == nil || state.Serial != 5 {
		t.Fatalf("Active() = %+v,%v, want the verified serial 5 pack", state, err)
	}
}

func TestSyncRejectsIncompatibleMinBinary(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	c.Verifier.CurrentBinaryVersion = "0.1.0"
	res, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrIncompatibleBinary) {
		t.Fatalf("Sync() error = %v, want ErrIncompatibleBinary", err)
	}
	if res.Status != SyncBuiltin {
		t.Fatalf("status = %v, want builtin-default", res.Status)
	}
}

func TestSyncRejectsBundleHashMismatch(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	// Re-sign a manifest that points at the wrong bundle hash.
	var m Manifest
	if err := json.Unmarshal(b.manifest, &m); err != nil {
		t.Fatal(err)
	}
	m.BundleSHA256 = strings.Repeat("a", 64)
	m.Signature = signInput(b.priv, ManifestSigningInput(m))
	b.mu.Lock()
	b.manifest = mustJSON(t, m)
	b.mu.Unlock()

	_, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrBundleHashMismatch) {
		t.Fatalf("Sync() error = %v, want ErrBundleHashMismatch", err)
	}
	if _, ok, _ := c.Cache.Active(); ok {
		t.Fatal("active must be cleared on bundle hash mismatch")
	}
}

func TestSyncOfflineUsesCache(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}
	b.srv.Close()

	res, err := c.Sync(context.Background(), false)
	if err != nil {
		t.Fatalf("offline Sync() error = %v", err)
	}
	if res.Status != SyncCached || res.Serial != 7 {
		t.Fatalf("offline Sync() = %+v, want cached serial 7", res)
	}
	if !warn.contains("using cached serial 7") {
		t.Fatalf("warnings = %v, want cached-use warning", warn.all())
	}
}

func TestSyncOfflineWithoutCacheUsesBuiltin(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	b.srv.Close()

	res, err := c.Sync(context.Background(), false)
	if err != nil {
		t.Fatalf("offline Sync() error = %v", err)
	}
	if res.Status != SyncBuiltin {
		t.Fatalf("offline Sync() = %+v, want builtin-default", res)
	}
	if !warn.contains("built-in defaults") {
		t.Fatalf("warnings = %v, want built-in warning", warn.all())
	}
}

func TestSyncCheckWritesNothing(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	c := newTestClient(t, b, root, &warnRecorder{}, testNow)
	res, err := c.Sync(context.Background(), true)
	if err != nil {
		t.Fatalf("check Sync() error = %v", err)
	}
	if res.Status != SyncAvailable || res.Serial != 7 {
		t.Fatalf("check Sync() = %+v, want available serial 7", res)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("--check wrote %d entries, want 0", len(entries))
	}
	if manifestCalls, bundleCalls := b.calls(); manifestCalls != 1 || bundleCalls != 0 {
		t.Fatalf("calls = (%d,%d), want (1,0)", manifestCalls, bundleCalls)
	}
}

func TestSyncEvictsRevokedCachedPack(t *testing.T) {
	// First install serial 5.
	b5 := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b5, root, warn, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("install 5: %v", err)
	}
	if _, _, err := c.Cache.Load(5); err != nil {
		t.Fatalf("serial 5 missing after install: %v", err)
	}

	// Now a newer manifest revokes serial 5.
	b7 := newFakeBackend(t, 7, []uint64{5})
	c2 := newTestClient(t, b7, root, warn, testNow)
	res, err := c2.Sync(context.Background(), false)
	if err != nil {
		t.Fatalf("install 7: %v", err)
	}
	if res.Status != SyncUpdated || res.Serial != 7 {
		t.Fatalf("Sync() = %+v, want updated serial 7", res)
	}
	if _, _, err := c2.Cache.Load(5); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("revoked serial 5 still cached: %v", err)
	}
}

func TestActiveFallsBackWhenCacheExpired(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	c := newTestClient(t, b, root, &warnRecorder{}, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// Re-open with a clock after the pack expiry.
	warn := &warnRecorder{}
	later := newTestClient(t, b, root, warn, testNow.Add(48*time.Hour))
	state, err := later.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if state.Config != nil {
		t.Fatalf("expired cache must fall back to built-in, got %+v", state)
	}
	if !warn.contains("built-in defaults") {
		t.Fatalf("warnings = %v, want fallback warning", warn.all())
	}
}

func TestActiveFallsBackOnRevokedCache(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if err := c.Cache.SetRevoked(RevokedList{Serials: []uint64{7}}); err != nil {
		t.Fatalf("SetRevoked: %v", err)
	}
	state, err := c.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if state.Config != nil {
		t.Fatalf("revoked cache must fall back to built-in, got %+v", state)
	}
	if !warn.contains("revoked") {
		t.Fatalf("warnings = %v, want revocation warning", warn.all())
	}
}

func TestRollbackSelectsPreviousPack(t *testing.T) {
	root := t.TempDir()
	warn := &warnRecorder{}

	b5 := newFakeBackend(t, 5, nil)
	c := newTestClient(t, b5, root, warn, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("install 5: %v", err)
	}
	b7 := newFakeBackend(t, 7, nil)
	c2 := newTestClient(t, b7, root, warn, testNow)
	if _, err := c2.Sync(context.Background(), false); err != nil {
		t.Fatalf("install 7: %v", err)
	}

	res, err := c2.Rollback()
	if err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if res.Config == nil || res.Serial != 5 {
		t.Fatalf("Rollback() = %+v, want serial 5", res)
	}
	if active, ok, _ := c2.Cache.Active(); !ok || active != 5 {
		t.Fatalf("active = %d,%v, want 5,true", active, ok)
	}

	// A second rollback clears to the built-in defaults.
	res, err = c2.Rollback()
	if err != nil {
		t.Fatalf("second Rollback() error = %v", err)
	}
	if res.Config != nil {
		t.Fatalf("second Rollback() = %+v, want built-in", res)
	}
}

func TestRollbackNothingWhenBuiltin(t *testing.T) {
	b := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	c := newTestClient(t, b, root, &warnRecorder{}, testNow)
	if _, err := c.Rollback(); !errors.Is(err, ErrNothingToRollback) {
		t.Fatalf("Rollback() error = %v, want ErrNothingToRollback", err)
	}
}

func TestSyncCurrentIsIdempotent(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	c := newTestClient(t, b, root, &warnRecorder{}, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("first Sync() error = %v", err)
	}
	res, err := c.Sync(context.Background(), false)
	if err != nil {
		t.Fatalf("second Sync() error = %v", err)
	}
	if res.Status != SyncCurrent || res.Serial != 7 {
		t.Fatalf("second Sync() = %+v, want current serial 7", res)
	}
}

func TestSyncRejectsChannelMismatch(t *testing.T) {
	b := newFakeBackend(t, 7, nil)
	root := t.TempDir()
	c := newTestClient(t, b, root, &warnRecorder{}, testNow)
	c.Channel = "beta"
	_, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrChannelMismatch) {
		t.Fatalf("Sync() error = %v, want ErrChannelMismatch", err)
	}
}

// TestSyncFreezeCannotHideIndependentRevocation is the B7 gap regression: a
// pack is revoked by the independent kill-switch document while the client is
// still served the identical (frozen) manifest. A revocation carried only by a
// newer manifest could never reach this client; the independent document must.
func TestSyncFreezeCannotHideIndependentRevocation(t *testing.T) {
	b := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}
	if _, _, err := c.Cache.Load(5); err != nil {
		t.Fatalf("serial 5 missing after install: %v", err)
	}

	// Same manifest serial 5 (frozen feed), but the separate kill-switch now
	// revokes serial 5 with a higher revocation serial.
	_, priv := sharedTestKey()
	b.setRevocations(signedRevocations(priv, b.keyID, 2, []uint64{5}))

	res, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrPackRevoked) {
		t.Fatalf("Sync() error = %v, want ErrPackRevoked", err)
	}
	if res.Status != SyncBuiltin {
		t.Fatalf("status = %v, want builtin-default", res.Status)
	}
	if _, _, err := c.Cache.Load(5); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("revoked serial 5 still cached: %v", err)
	}
	state, err := c.Active()
	if err != nil || state.Config != nil {
		t.Fatalf("Active() = %+v,%v, want built-in defaults after revocation", state, err)
	}
}

// TestSyncRejectsRevocationsRollback asserts the independent revocation
// document is anti-rollback protected by its own high-water mark, so an
// attacker cannot replay an older (non-revoking) document.
func TestSyncRejectsRevocationsRollback(t *testing.T) {
	b := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	_, priv := sharedTestKey()
	b.setRevocations(signedRevocations(priv, b.keyID, 5, nil))
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}
	manifestCalls, _ := b.calls()

	b.setRevocations(signedRevocations(priv, b.keyID, 4, nil))
	res, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrPackReplayed) {
		t.Fatalf("Sync() error = %v, want ErrPackReplayed", err)
	}
	if res.Status != SyncBuiltin {
		t.Fatalf("status = %v, want builtin-default", res.Status)
	}
	if after, _ := b.calls(); after != manifestCalls {
		t.Fatalf("manifest fetched after a revocation rollback: %d -> %d", manifestCalls, after)
	}
}

// TestSyncRejectsForgedRevocationsBeforeManifest asserts the independent
// kill-switch is verified first and with the rule trust root: a forged document
// fails closed without the manifest ever being trusted.
func TestSyncRejectsForgedRevocationsBeforeManifest(t *testing.T) {
	b := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	c := newTestClient(t, b, root, &warnRecorder{}, testNow)
	_, priv := sharedTestKey()
	forged := signedRevocations(priv, b.keyID, 2, nil)
	forged.Serial = 99
	b.setRevocations(forged)

	_, err := c.Sync(context.Background(), false)
	if !errors.Is(err, ErrPackBadSignature) {
		t.Fatalf("Sync() error = %v, want ErrPackBadSignature", err)
	}
	if calls, _ := b.calls(); calls != 0 {
		t.Fatalf("manifest fetched %d times, want 0: revocations must verify first", calls)
	}
}

// TestSyncCheckHonoursIndependentRevocation asserts --check uses the independent
// kill-switch and still writes nothing.
func TestSyncCheckHonoursIndependentRevocation(t *testing.T) {
	b := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	c := newTestClient(t, b, root, &warnRecorder{}, testNow)
	_, priv := sharedTestKey()
	b.setRevocations(signedRevocations(priv, b.keyID, 2, []uint64{5}))

	res, err := c.Sync(context.Background(), true)
	if !errors.Is(err, ErrPackRevoked) {
		t.Fatalf("check Sync() error = %v, want ErrPackRevoked", err)
	}
	if res.Status != SyncBuiltin {
		t.Fatalf("status = %v, want builtin-default", res.Status)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("--check wrote %d entries, want 0", len(entries))
	}
}

// TestSyncOfflineWhenRevocationsUnreachable asserts the client fails closed to
// the verified cache when the independent kill-switch feed is unavailable,
// rather than accepting a pack whose revocation status is unknown.
func TestSyncOfflineWhenRevocationsUnreachable(t *testing.T) {
	b := newFakeBackend(t, 5, nil)
	root := t.TempDir()
	warn := &warnRecorder{}
	c := newTestClient(t, b, root, warn, testNow)
	if _, err := c.Sync(context.Background(), false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}
	b.setRevStatus(http.StatusInternalServerError)

	res, err := c.Sync(context.Background(), false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.Status != SyncCached || res.Serial != 5 {
		t.Fatalf("Sync() = %+v, want cached serial 5", res)
	}
}
