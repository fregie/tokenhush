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
	srv      *httptest.Server
	keyID    string
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	manifest []byte
	bundle   []byte

	mu             sync.Mutex
	manifestStatus int
	bundleStatus   int
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
	b.srv = httptest.NewTLSServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

func (b *fakeRuleBackend) setManifestStatus(status int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.manifestStatus = status
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

func mustReadCache(t *testing.T, root string, serial uint64) ([]byte, []byte) {
	t.Helper()
	cache, err := OpenFileCache(root)
	if err != nil {
		t.Fatalf("OpenFileCache: %v", err)
	}
	m, b, err := cache.Load(serial)
	if err != nil {
		t.Fatalf("Load(%d): %v", serial, err)
	}
	return m, b
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
