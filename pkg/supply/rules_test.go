package supply

// rules_test.go is the W5.5 suite: the full sync sequence against a stub
// issuer, the four rejection classes with the previous pack retained, the
// transport fallback, the anti-rollback replay rule, the OD-2 command gate and
// the OD-3 allowlist-neutral floor. Nothing here opens a socket: the fetcher
// is a map-backed stub and the verifier holds one in-process key pair, so a
// request can only happen if the code under test invokes the seam.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/filter"
)

// Fixture rule ids and documents. Every pack is schema v1, exactly like a real
// signed pack: the OD-4 signal lives in the MANIFEST, never in pack content.
const (
	rulesTestKeyID       = "rules-2026-09"
	rulesPackBody        = `{"id":"proj","type":"regex","pattern":"PROJ-[0-9]{4,}","action":"warn"}`
	rulesPackToken       = `{"id":"tok","type":"prefix","action":"redact"}`
	rulesPackSecret      = `{"id":"secret","type":"keyword","keywords":["secret","token"],"action":"block"}`
	rulesPackAllow       = `{"id":"allowlisted","type":"keyword","keywords":["example"],"action":"warn","allowlist":["example.com"]}`
	rulesPackAllowAction = `{"id":"allow.all","type":"prefix","action":"allow"}`
	rulesPackCommand     = `{"id":"cmd.aws","type":"command","action":"block","command":"aws","subcommand":"s3","verbs":["rm","delete"],"targets":["s3://prod"]}`
	rulesPackCommand2    = `{"id":"cmd.gcloud","type":"command","action":"block","command":"gcloud","subcommand":"compute"}`
)

// rulesPackDoc renders a wire rules-pack document. An empty minVersion means
// "0.3.0" and an empty envelope adds no envelope keys beyond the frozen ones.
func rulesPackDoc(serial uint64, minVersion, envelope, rules string) string {
	if minVersion == "" {
		minVersion = "0.3.0"
	}
	doc := `{"channel":"stable","schema_version":1,"min_binary_version":"` + minVersion + `",` +
		`"serial":` + strconv.FormatUint(serial, 10) + `,"key_id":"` + rulesTestKeyID + `",` +
		`"not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z",`
	if envelope != "" {
		doc += envelope + ","
	}
	return doc + `"rules":[` + rules + `]}`
}

// rulesSignPackDoc produces the signed bundle for a rendered pack document:
// the signature covers the frozen tokenhush-rules-pack-v1 projection of the
// payload as decoded, never the document bytes.
func rulesSignPackDoc(t *testing.T, priv ed25519.PrivateKey, docJSON string) []byte {
	t.Helper()
	decoded, err := DecodeRulesPack([]byte(docJSON))
	if err != nil {
		t.Fatalf("DecodeRulesPack(fixture): %v", err)
	}
	signature, err := json.Marshal(base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, RulesPackSigningInput(decoded))))
	if err != nil {
		t.Fatalf("marshal signature: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(docJSON), &fields); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	fields["signature"] = signature
	signed, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal signed fixture: %v", err)
	}
	return signed
}

// rulesStripSignature removes the signature key from a signed document, the
// unsigned-bundle rejection fixture.
func rulesStripSignature(t *testing.T, doc []byte) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(doc, &fields); err != nil {
		t.Fatalf("unmarshal signed fixture: %v", err)
	}
	delete(fields, "signature")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal stripped fixture: %v", err)
	}
	return stripped
}

// rulesSignManifestDoc signs a rules manifest and renders the wire document.
func rulesSignManifestDoc(t *testing.T, priv ed25519.PrivateKey, manifest RulesManifestPayload) []byte {
	t.Helper()
	signRulesManifest(t, &manifest, priv)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return raw
}

// rulesKeyVerifier is a stub Verifier bound to one in-process key. It accepts
// the two rules domains and records the order, so the suite can assert the
// pack is verified only after the manifest.
type rulesKeyVerifier struct {
	keyID   string
	public  string
	domains []string
}

func (v *rulesKeyVerifier) Verify(domain, keyID string, signingInput, sig []byte) error {
	if keyID != v.keyID || (domain != DomainRulesManifest && domain != DomainRulesPack) {
		return ErrWrongKey
	}
	v.domains = append(v.domains, domain)
	return VerifyEd25519(v.public, signingInput, sig)
}

// rulesFetcher is the stub issuer's transport: a URL-keyed body map with an
// injectable per-URL failure and a call log, so a test can prove the code
// under test never fetched.
type rulesFetcher struct {
	bodies map[string][]byte
	fail   map[string]error
	calls  []string
}

func newRulesFetcher() *rulesFetcher {
	return &rulesFetcher{bodies: map[string][]byte{}, fail: map[string]error{}}
}

func (f *rulesFetcher) set(url string, body []byte) { f.bodies[url] = body }

func (f *rulesFetcher) Get(_ context.Context, url string) ([]byte, error) {
	f.calls = append(f.calls, url)
	if err, ok := f.fail[url]; ok {
		return nil, err
	}
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("rulesFetcher: no body for %s", url)
	}
	return body, nil
}

func (f *rulesFetcher) invoked() int { return len(f.calls) }

// rulesHarness is the stub issuer: one key pair, a verifier over it, a
// map-backed fetcher and a temp data dir.
type rulesHarness struct {
	t        *testing.T
	dataDir  string
	priv     ed25519.PrivateKey
	verifier *rulesKeyVerifier
	fetcher  *rulesFetcher
	now      time.Time
}

func newRulesHarness(t *testing.T) *rulesHarness {
	t.Helper()
	public, priv := substrateKeyPair(t)
	return &rulesHarness{
		t:        t,
		dataDir:  t.TempDir(),
		priv:     priv,
		verifier: &rulesKeyVerifier{keyID: rulesTestKeyID, public: public},
		fetcher:  newRulesFetcher(),
		now:      time.Unix(fixtureNotBefore+3600, 0).UTC(),
	}
}

// newSync returns a sync layer over the harness seams. HighWater is left nil,
// so the frozen file store under the data dir is exercised.
func (h *rulesHarness) newSync(t *testing.T) *RulesSync {
	t.Helper()
	syncer, err := NewRulesSync(RulesSyncConfig{
		DataDir:  h.dataDir,
		Fetcher:  h.fetcher,
		Verifier: h.verifier,
		Now:      func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatalf("NewRulesSync: %v", err)
	}
	return syncer
}

// publishBundle wires one signed manifest and its bundle into the stub issuer.
// mutate can adjust the manifest before it is signed.
func (h *rulesHarness) publishBundle(serial uint64, schemaVersion int, bundle []byte, mutate func(*RulesManifestPayload)) {
	h.t.Helper()
	manifest := RulesManifestPayload{
		Channel: rulesChannel, SchemaVersion: schemaVersion, MinBinaryVersion: "0.3.0",
		Serial: serial, KeyID: rulesTestKeyID,
		NotBefore: EpochSeconds(fixtureNotBefore), Expires: EpochSeconds(fixtureExpires),
		BundleSHA256: testHexHash(bundle), Bundle: "rules/stable/bundle.json",
	}
	if mutate != nil {
		mutate(&manifest)
	}
	h.fetcher.set(manifestURL, rulesSignManifestDoc(h.t, h.priv, manifest))
	h.fetcher.set(bundleURL, bundle)
}

// publishPack signs a rendered pack document and publishes it.
func (h *rulesHarness) publishPack(serial uint64, schemaVersion int, packDoc string) {
	h.t.Helper()
	h.publishBundle(serial, schemaVersion, rulesSignPackDoc(h.t, h.priv, packDoc), nil)
}

// seed activates serial 7 with two evaluable rules, the baseline every
// rejection case starts from.
func (h *rulesHarness) seed(t *testing.T) *RulesSync {
	t.Helper()
	h.publishPack(7, 1, rulesPackDoc(7, "", "", rulesPackBody+","+rulesPackToken))
	syncer := h.newSync(t)
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("seeding Sync = %v, want nil", err)
	}
	return syncer
}

// assertRetained proves a rejection left the previous verified pack in force,
// on disk as well as in memory.
func (h *rulesHarness) assertRetained(t *testing.T, syncer *RulesSync, wantSerial uint64, wantRules int) {
	t.Helper()
	state := syncer.Active()
	if state.Serial != wantSerial {
		t.Errorf("active serial = %d, want %d retained", state.Serial, wantSerial)
	}
	if state.Pack == nil || state.Pack.Len() != wantRules {
		t.Errorf("active pack rules = %v, want the previous %d-rule pack", state.Pack, wantRules)
	}
	cached, err := NewRulesCache(h.dataDir).ActiveSerial()
	if err != nil {
		t.Fatalf("ActiveSerial: %v", err)
	}
	if cached != wantSerial {
		t.Errorf("cached serial = %d, want %d retained", cached, wantSerial)
	}
}

// noCacheDir proves a rejected pack never reached the cache.
func (h *rulesHarness) noCacheDir(t *testing.T, serial uint64) {
	t.Helper()
	path := filepath.Join(h.dataDir, "rules", strconv.FormatUint(serial, 10))
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("rejected pack wrote %s (stat err = %v)", path, err)
	}
}

func readFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

// TestRulesSyncSequence is the QA happy path: the full sequence against the
// stub issuer, then the frozen cache layout.
func TestRulesSyncSequence(t *testing.T) {
	h := newRulesHarness(t)
	h.publishPack(7, 1, rulesPackDoc(7, "", "", rulesPackBody+","+rulesPackToken))
	syncer := h.newSync(t)
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("Sync(happy path) = %v, want nil", err)
	}
	if want := []string{manifestURL, bundleURL}; !slices.Equal(h.fetcher.calls, want) {
		t.Errorf("fetch order = %v, want %v", h.fetcher.calls, want)
	}
	if want := []string{DomainRulesManifest, DomainRulesPack}; !slices.Equal(h.verifier.domains, want) {
		t.Errorf("verification order = %v, want %v", h.verifier.domains, want)
	}
	state := syncer.Active()
	if state.Source != SourceRemote || state.Serial != 7 {
		t.Fatalf("active = {%s %d}, want {remote 7}", state.Source, state.Serial)
	}
	if state.Pack == nil || state.Pack.Len() != 2 {
		t.Fatalf("active pack = %v, want 2 evaluable rules", state.Pack)
	}
	if len(state.Warnings) != 0 {
		t.Errorf("warnings = %q, want none", state.Warnings)
	}
	root := filepath.Join(h.dataDir, "rules")
	if pointer := readFixtureFile(t, filepath.Join(root, "active")); string(pointer) != `{"serial":7}` {
		t.Errorf("active pointer = %s, want {\"serial\":7}", pointer)
	}
	for _, rel := range []string{"active", "7/manifest.json", "7/bundle.json"} {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("stat %s: %v", rel, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %v, want 0600", rel, perm)
		}
	}
	cache := NewRulesCache(h.dataDir)
	if serial, err := cache.ActiveSerial(); err != nil || serial != 7 {
		t.Errorf("ActiveSerial = %d, %v; want 7, nil", serial, err)
	}
	if want := filepath.Join(h.dataDir, "rules", "revoked.json"); cache.RevocationsPath() != want {
		t.Errorf("RevocationsPath = %s, want %s", cache.RevocationsPath(), want)
	}
	mark, err := NewRulesHighWater(h.dataDir)
	if err != nil {
		t.Fatalf("NewRulesHighWater: %v", err)
	}
	if mark.Current() != 7 {
		t.Errorf("high-water = %d, want 7", mark.Current())
	}
	t.Logf("QA happy: fetch %v, verify %v, cache 0600 under %s, active 7, high-water 7",
		h.fetcher.calls, h.verifier.domains, root)
}

// TestRulesSyncRejections covers the four mandatory rejection classes plus the
// envelope refusals. Every case starts from the verified serial 7 and proves
// the rejected pack never displaced it, in memory or on disk.
func TestRulesSyncRejections(t *testing.T) {
	cases := []struct {
		name    string
		serial  uint64
		want    error
		publish func(h *rulesHarness)
	}{
		{
			name: "unsigned bundle", serial: 8, want: ErrBadSignature,
			publish: func(h *rulesHarness) {
				signed := rulesSignPackDoc(h.t, h.priv, rulesPackDoc(8, "", "", rulesPackBody))
				h.publishBundle(8, 1, rulesStripSignature(h.t, signed), nil)
			},
		},
		{
			name: "floor: baseline detector disabled", serial: 8, want: filter.ErrFloorDisablesDetector,
			publish: func(h *rulesHarness) {
				h.publishPack(8, 1, rulesPackDoc(8, "", `"detectors":{"prefix":false}`, rulesPackBody))
			},
		},
		{
			name: "floor: required category dropped", serial: 8, want: filter.ErrFloorRemovesCategory,
			publish: func(h *rulesHarness) {
				h.publishPack(8, 1, rulesPackDoc(8, "", `"disabled_categories":["api_key"]`, rulesPackBody))
			},
		},
		{
			name: "floor: allow action", serial: 8, want: filter.ErrFloorAutoAllow,
			publish: func(h *rulesHarness) {
				h.publishPack(8, 1, rulesPackDoc(8, "", "", rulesPackAllowAction))
			},
		},
		{
			name: "serial mismatch", serial: 8, want: ErrSerialMismatch,
			publish: func(h *rulesHarness) {
				h.publishBundle(8, 1, rulesSignPackDoc(h.t, h.priv, rulesPackDoc(9, "", "", rulesPackBody)), nil)
			},
		},
		{
			name: "bundle digest mismatch", serial: 8, want: ErrDigestMismatch,
			publish: func(h *rulesHarness) {
				h.publishPack(8, 1, rulesPackDoc(8, "", "", rulesPackBody))
				manifest, err := DecodeRulesManifest(h.fetcher.bodies[manifestURL])
				if err != nil {
					h.t.Fatalf("decode manifest fixture: %v", err)
				}
				manifest.BundleSHA256 = testHexHash([]byte("a different bundle"))
				h.fetcher.set(manifestURL, rulesSignManifestDoc(h.t, h.priv, manifest))
			},
		},
		{
			name: "bundle digest not hex", serial: 8, want: ErrDigestMismatch,
			publish: func(h *rulesHarness) {
				h.publishPack(8, 1, rulesPackDoc(8, "", "", rulesPackBody))
				manifest, err := DecodeRulesManifest(h.fetcher.bodies[manifestURL])
				if err != nil {
					h.t.Fatalf("decode manifest fixture: %v", err)
				}
				manifest.BundleSHA256 = "zzzz"
				h.fetcher.set(manifestURL, rulesSignManifestDoc(h.t, h.priv, manifest))
			},
		},
		{
			name: "revoked serial", serial: 8, want: ErrRevokedSerial,
			publish: func(h *rulesHarness) {
				h.publishBundle(8, 1, rulesSignPackDoc(h.t, h.priv, rulesPackDoc(8, "", "", rulesPackBody)),
					func(m *RulesManifestPayload) { m.RevokedSerials = []uint64{8} })
			},
		},
		{
			name: "wrong channel", serial: 8, want: ErrChannelMismatch,
			publish: func(h *rulesHarness) {
				h.publishBundle(8, 1, rulesSignPackDoc(h.t, h.priv, rulesPackDoc(8, "", "", rulesPackBody)),
					func(m *RulesManifestPayload) { m.Channel = "beta" })
			},
		},
		{
			name: "unknown manifest schema version", serial: 8, want: ErrSchemaVersion,
			publish: func(h *rulesHarness) {
				h.publishBundle(8, 3, rulesSignPackDoc(h.t, h.priv, rulesPackDoc(8, "", "", rulesPackBody)), nil)
			},
		},
		{
			name: "expired manifest", serial: 8, want: ErrExpired,
			publish: func(h *rulesHarness) {
				h.publishBundle(8, 1, rulesSignPackDoc(h.t, h.priv, rulesPackDoc(8, "", "", rulesPackBody)),
					func(m *RulesManifestPayload) {
						m.NotBefore = EpochSeconds(fixtureNotBefore - 7200)
						m.Expires = EpochSeconds(fixtureNotBefore - 3600)
					})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRulesHarness(t)
			syncer := h.seed(t)
			tc.publish(h)
			err := syncer.Sync(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("defective sync = %v, want %v", err, tc.want)
			}
			h.assertRetained(t, syncer, 7, 2)
			h.noCacheDir(t, tc.serial)
			t.Logf("QA failure: %s -> %v (pack 7 retained)", tc.name, err)
		})
	}
}

// TestRulesSyncVersionGate covers the minimum-binary-version gate: the fixture
// 0.3.0 is satisfied by the v0.5.0 binary, a higher requirement is refused,
// and a manifest requirement refuses before the bundle is ever fetched.
func TestRulesSyncVersionGate(t *testing.T) {
	if Version != "0.5.0" {
		t.Fatalf("Version = %q, want the OD-1 v0.5.0 line", Version)
	}
	t.Run("an empty requirement gates nothing", func(t *testing.T) {
		if err := checkMinBinaryVersion("", version{0, 5, 0}); err != nil {
			t.Errorf("checkMinBinaryVersion(\"\") = %v, want nil", err)
		}
	})
	t.Run("a higher pack requirement is refused with the pack retained", func(t *testing.T) {
		h := newRulesHarness(t)
		syncer := h.seed(t)
		h.publishPack(8, 1, rulesPackDoc(8, "9.9.9", "", rulesPackBody))
		err := syncer.Sync(context.Background())
		if !errors.Is(err, ErrMinBinaryVersion) {
			t.Fatalf("future pack = %v, want ErrMinBinaryVersion", err)
		}
		h.assertRetained(t, syncer, 7, 2)
		t.Logf("QA failure: pack requiring 9.9.9 -> %v (pack 7 retained)", err)
	})
	t.Run("a higher manifest requirement refuses before the bundle fetch", func(t *testing.T) {
		h := newRulesHarness(t)
		h.publishBundle(7, 1, rulesSignPackDoc(t, h.priv, rulesPackDoc(7, "", "", rulesPackBody)),
			func(m *RulesManifestPayload) { m.MinBinaryVersion = "9.9.9" })
		syncer := h.newSync(t)
		err := syncer.Sync(context.Background())
		if !errors.Is(err, ErrMinBinaryVersion) {
			t.Fatalf("future manifest = %v, want ErrMinBinaryVersion", err)
		}
		if want := []string{manifestURL}; !slices.Equal(h.fetcher.calls, want) {
			t.Errorf("fetched %v, want the manifest only", h.fetcher.calls)
		}
	})
	t.Run("a malformed requirement is refused typedly", func(t *testing.T) {
		h := newRulesHarness(t)
		h.publishPack(7, 1, rulesPackDoc(7, "not-a-version", "", rulesPackBody))
		syncer := h.newSync(t)
		err := syncer.Sync(context.Background())
		if !errors.Is(err, ErrBadVersion) {
			t.Fatalf("malformed requirement = %v, want ErrBadVersion", err)
		}
		if state := syncer.Active(); state.Serial != 0 {
			t.Errorf("active serial = %d, want the built-ins", state.Serial)
		}
	})
}

// TestRulesSyncTransportFallback proves the fallback ladder: the active pack,
// then the cached verified pack, then the built-ins, with the transport error
// still returned.
func TestRulesSyncTransportFallback(t *testing.T) {
	t.Run("cached pack after a transport failure", func(t *testing.T) {
		h := newRulesHarness(t)
		h.seed(t)
		h.fetcher.fail[manifestURL] = errors.New("dial tcp: connection refused")
		fresh := h.newSync(t)
		err := fresh.Sync(context.Background())
		if err == nil {
			t.Fatal("Sync(transport failure) = nil, want the transport error")
		}
		state := fresh.Active()
		if state.Source != SourceCache || state.Serial != 7 || state.Pack == nil || state.Pack.Len() != 2 {
			t.Fatalf("fallback = {%s %d %v}, want the cached pack 7", state.Source, state.Serial, state.Pack)
		}
		t.Logf("QA failure: transport failure -> %v; cached pack %d activated", err, state.Serial)
	})
	t.Run("built-ins with an empty cache", func(t *testing.T) {
		h := newRulesHarness(t)
		h.fetcher.fail[manifestURL] = errors.New("no route to host")
		syncer := h.newSync(t)
		err := syncer.Sync(context.Background())
		if err == nil {
			t.Fatal("Sync(transport failure, empty cache) = nil, want the transport error")
		}
		state := syncer.Active()
		if state.Source != SourceBuiltin || state.Serial != 0 || state.Pack != nil {
			t.Fatalf("empty-cache fallback = {%s %d %v}, want the built-ins", state.Source, state.Serial, state.Pack)
		}
		t.Logf("QA failure: transport failure with an empty cache -> %v; built-ins stay active", err)
	})
	t.Run("bundle transport failure keeps the active pack", func(t *testing.T) {
		h := newRulesHarness(t)
		syncer := h.seed(t)
		h.publishPack(8, 1, rulesPackDoc(8, "", "", rulesPackBody+","+rulesPackToken+","+rulesPackSecret))
		h.fetcher.fail[bundleURL] = errors.New("unexpected EOF")
		if err := syncer.Sync(context.Background()); err == nil {
			t.Fatal("Sync(bundle failure) = nil, want the transport error")
		}
		h.assertRetained(t, syncer, 7, 2)
		if state := syncer.Active(); state.Source != SourceRemote {
			t.Errorf("source = %s, want the already-active pack kept as-is", state.Source)
		}
	})
}

// TestRulesSyncReplay pins the anti-rollback rule: a replayed manifest keeps
// the active pack and never re-fetches the bundle, and a lower serial is a
// typed replay rejection.
func TestRulesSyncReplay(t *testing.T) {
	t.Run("a replayed manifest keeps the active pack", func(t *testing.T) {
		h := newRulesHarness(t)
		syncer := h.seed(t)
		before := h.fetcher.invoked()
		h.publishPack(7, 1, rulesPackDoc(7, "", "", rulesPackBody+","+rulesPackToken+","+rulesPackSecret))
		if err := syncer.Sync(context.Background()); err != nil {
			t.Fatalf("replayed manifest = %v, want nil", err)
		}
		if got := h.fetcher.calls[before:]; !slices.Equal(got, []string{manifestURL}) {
			t.Errorf("replay fetched %v, want the manifest only", got)
		}
		h.assertRetained(t, syncer, 7, 2)
		t.Logf("QA: replayed manifest -> fetched %v, active pack 7 unchanged", h.fetcher.calls[before:])
	})
	t.Run("a serial below the mark is rejected", func(t *testing.T) {
		h := newRulesHarness(t)
		syncer := h.seed(t)
		h.publishPack(4, 1, rulesPackDoc(4, "", "", rulesPackBody))
		err := syncer.Sync(context.Background())
		if !errors.Is(err, ErrReplay) {
			t.Fatalf("lower serial = %v, want ErrReplay", err)
		}
		h.assertRetained(t, syncer, 7, 2)
		t.Logf("QA failure: replayed serial 4 below the mark -> %v (pack 7 retained)", err)
	})
}

// TestRulesCommandGate is the OD-2 decision: accepted with a warning while the
// manifest schema_version is 1, refused with the dedicated command-gate reason
// once it is 2, and never silently dropped in either case.
func TestRulesCommandGate(t *testing.T) {
	commandPack := rulesPackDoc(7, "", "", rulesPackBody+","+rulesPackCommand+","+rulesPackCommand2)
	t.Run("a v1 manifest accepts the command pack with a warning", func(t *testing.T) {
		h := newRulesHarness(t)
		h.publishPack(7, 1, commandPack)
		syncer := h.newSync(t)
		if err := syncer.Sync(context.Background()); err != nil {
			t.Fatalf("command pack under a v1 manifest = %v, want accepted", err)
		}
		state := syncer.Active()
		if state.Serial != 7 || state.Pack == nil || state.Pack.Len() != 1 {
			t.Fatalf("active = {%d %v}, want serial 7 with the one non-command rule", state.Serial, state.Pack)
		}
		commands := state.Pack.Commands()
		if !slices.Equal(commands.RuleIDs, []string{"cmd.aws", "cmd.gcloud"}) || commands.Count != 2 {
			t.Errorf("command signal = %+v, want both command ids counted", commands)
		}
		if len(state.Warnings) != 1 {
			t.Fatalf("warnings = %q, want exactly one", state.Warnings)
		}
		for _, want := range []string{"cmd.aws", "cmd.gcloud", "does nothing in this rewrite"} {
			if !strings.Contains(state.Warnings[0], want) {
				t.Errorf("warning %q must name %q", state.Warnings[0], want)
			}
		}
		t.Logf("QA: v1 command pack accepted, 1 rule active, 2 counted; %s", state.Warnings[0])
	})
	t.Run("a v2 manifest refuses with the command gate and keeps the previous pack", func(t *testing.T) {
		h := newRulesHarness(t)
		syncer := h.seed(t)
		h.publishPack(8, 2, rulesPackDoc(8, "", "", rulesPackBody+","+rulesPackCommand+","+rulesPackCommand2))
		err := syncer.Sync(context.Background())
		if !errors.Is(err, ErrCommandGate) {
			t.Fatalf("command pack under a v2 manifest = %v, want ErrCommandGate", err)
		}
		if errors.Is(err, ErrSchemaVersion) {
			t.Fatalf("the command gate must not be ErrSchemaVersion: %v", err)
		}
		for _, id := range []string{"cmd.aws", "cmd.gcloud"} {
			if !strings.Contains(err.Error(), id) {
				t.Errorf("refusal %q must name %q", err, id)
			}
		}
		h.assertRetained(t, syncer, 7, 2)
		h.noCacheDir(t, 8)
		t.Logf("QA failure: v2 command pack -> %v (pack 7 retained)", err)
	})
	t.Run("a v2 manifest still accepts a pack without command rules", func(t *testing.T) {
		h := newRulesHarness(t)
		h.publishPack(7, 2, rulesPackDoc(7, "", "", rulesPackBody+","+rulesPackToken))
		syncer := h.newSync(t)
		if err := syncer.Sync(context.Background()); err != nil {
			t.Fatalf("open gate, no command rules = %v, want nil", err)
		}
		if got := syncer.Active().Serial; got != 7 {
			t.Errorf("active serial = %d, want 7", got)
		}
	})
	t.Run("the warning survives a cache reload", func(t *testing.T) {
		h := newRulesHarness(t)
		h.publishPack(7, 1, commandPack)
		syncer := h.newSync(t)
		if err := syncer.Sync(context.Background()); err != nil {
			t.Fatalf("Sync: %v", err)
		}
		fresh := h.newSync(t)
		if err := fresh.Startup(); err != nil {
			t.Fatalf("Startup: %v", err)
		}
		state := fresh.Active()
		if state.Source != SourceCache || state.Serial != 7 || len(state.Warnings) != 1 {
			t.Fatalf("reloaded = {%s %d %q}, want the cached pack with its warning",
				state.Source, state.Serial, state.Warnings)
		}
	})
}

// TestRulesFloorAllowlistNeutral is the OD-3 requirement: a pack carrying a
// global and a per-rule allowlist is ACCEPTED, so the floor can never be
// "helpfully" tightened into rejecting real signed packs.
func TestRulesFloorAllowlistNeutral(t *testing.T) {
	h := newRulesHarness(t)
	envelope := `"detectors":{"email":true,"prefix":true},"disabled_categories":["internal_only"],` +
		`"allowlist":["example.com"],"blocklist":["TOKENHUSH_BLOCK"]`
	h.publishPack(7, 1, rulesPackDoc(7, "", envelope, rulesPackBody+","+rulesPackAllow))
	syncer := h.newSync(t)
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatalf("a pack carrying global and per-rule allowlists = %v, want accepted (OD-3)", err)
	}
	if state := syncer.Active(); state.Serial != 7 || state.Pack == nil || state.Pack.Len() != 2 {
		t.Fatalf("active = {%d %v}, want serial 7 with both rules", state.Serial, state.Pack)
	}
	t.Logf("QA: OD-3 floor accepted the global+per-rule allowlist pack at serial 7")
}

// TestRulesNoSync pins the operator opt-out: the disabled path returns before
// any request, and any other value leaves the sync running.
func TestRulesNoSync(t *testing.T) {
	t.Run("TOKENHUSH_NO_RULE_SYNC=1 returns before any fetch", func(t *testing.T) {
		h := newRulesHarness(t)
		h.publishPack(7, 1, rulesPackDoc(7, "", "", rulesPackBody))
		t.Setenv(noRuleSyncEnv, "1")
		syncer := h.newSync(t)
		if err := syncer.Sync(context.Background()); err != nil {
			t.Fatalf("disabled Sync = %v, want nil", err)
		}
		if got := h.fetcher.invoked(); got != 0 {
			t.Fatalf("TOKENHUSH_NO_RULE_SYNC=1 still invoked the fetcher %d times: %v", got, h.fetcher.calls)
		}
		if state := syncer.Active(); state.Source != SourceBuiltin || state.Serial != 0 {
			t.Errorf("disabled state = {%s %d}, want the built-ins", state.Source, state.Serial)
		}
		t.Logf("QA failure: TOKENHUSH_NO_RULE_SYNC=1 -> sync returned, fetcher calls 0, built-ins active")
	})
	t.Run("another value leaves the sync enabled", func(t *testing.T) {
		h := newRulesHarness(t)
		h.publishPack(7, 1, rulesPackDoc(7, "", "", rulesPackBody))
		t.Setenv(noRuleSyncEnv, "0")
		syncer := h.newSync(t)
		if err := syncer.Sync(context.Background()); err != nil {
			t.Fatalf("Sync with %s=0 = %v, want nil", noRuleSyncEnv, err)
		}
		if got := h.fetcher.invoked(); got != 2 {
			t.Errorf("fetcher calls = %d, want the manifest and the bundle", got)
		}
	})
}

// TestRulesStartupCacheOnly pins the startup contract: the local cache is the
// only input, no fetcher is ever invoked, and a corrupt cache fails closed.
func TestRulesStartupCacheOnly(t *testing.T) {
	t.Run("a cache hit activates the stored pack without a fetch", func(t *testing.T) {
		h := newRulesHarness(t)
		h.seed(t)
		h.fetcher.calls = nil
		fresh := h.newSync(t)
		if err := fresh.Startup(); err != nil {
			t.Fatalf("Startup: %v", err)
		}
		if got := h.fetcher.invoked(); got != 0 {
			t.Fatalf("startup fetched %d documents: %v", got, h.fetcher.calls)
		}
		state := fresh.Active()
		if state.Source != SourceCache || state.Serial != 7 || state.Pack == nil || state.Pack.Len() != 2 {
			t.Fatalf("startup = {%s %d %v}, want the cached pack 7", state.Source, state.Serial, state.Pack)
		}
		t.Logf("QA: startup read only the cache (fetcher calls 0), pack %d active", state.Serial)
	})
	t.Run("an empty cache keeps the built-ins", func(t *testing.T) {
		h := newRulesHarness(t)
		syncer := h.newSync(t)
		if err := syncer.Startup(); err != nil {
			t.Fatalf("Startup on an empty cache = %v, want nil", err)
		}
		if state := syncer.Active(); state.Source != SourceBuiltin || state.Pack != nil {
			t.Errorf("startup = {%s %v}, want the built-ins", state.Source, state.Pack)
		}
		if got := h.fetcher.invoked(); got != 0 {
			t.Errorf("startup fetched %d documents, want none", got)
		}
	})
	t.Run("a corrupt cache fails closed", func(t *testing.T) {
		h := newRulesHarness(t)
		root := filepath.Join(h.dataDir, "rules")
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "active"), []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write pointer: %v", err)
		}
		syncer := h.newSync(t)
		if err := syncer.Startup(); !errors.Is(err, ErrCacheCorrupt) {
			t.Fatalf("Startup(corrupt cache) = %v, want ErrCacheCorrupt", err)
		}
		if state := syncer.Active(); state.Source != SourceBuiltin || state.Serial != 0 {
			t.Errorf("corrupt-cache state = {%s %d}, want the built-ins", state.Source, state.Serial)
		}
	})
}

// TestRulesPayloadCarriesOptions pins the one optional extension of the frozen
// pack element: a rule may carry the typed per-detector options object, and it
// survives sign, strict decode and verify unchanged. The filter-side content
// projection is out of scope here: DecodeRulesPack already strict-decodes the
// options object, so a malformed nested key must still be rejected at this
// layer before any signature is consulted.
func TestRulesPayloadCarriesOptions(t *testing.T) {
	// The pre-change projection of the options-less fixture below, captured
	// from the frozen struct before the optional field existed. Byte-identical
	// output for an absent field is the golden-vector guarantee: omitempty
	// emits no key, so every existing signing_vectors.json entry still
	// recomputes.
	const wantOptionsLessSigningInput = "746f6b656e687573682d72756c65732d7061636b2d76310a63616364353231393764613963623431613263613431613230616465643432373865393563653061353263353466353237326131653530623535343333646363"

	optionsLessPack := func() RulesPackPayload {
		return RulesPackPayload{
			Channel: "stable", SchemaVersion: 1, MinBinaryVersion: "0.3.0", Serial: 9,
			KeyID: rulesTestKeyID, NotBefore: EpochSeconds(fixtureNotBefore), Expires: EpochSeconds(fixtureExpires),
			Rules: []RulesRule{{ID: "email.corp", Type: "email", Action: "redact"}},
		}
	}

	t.Run("options survive sign, decode and verify", func(t *testing.T) {
		public, priv := substrateKeyPair(t)
		pack := optionsLessPack()
		pack.Rules[0].Options = &filter.RuleOptions{
			Email: &filter.EmailOptions{Suffixes: []string{"corp.com"}},
		}
		doc, err := json.Marshal(pack)
		if err != nil {
			t.Fatalf("marshal pack fixture: %v", err)
		}
		decoded, err := DecodeRulesPack(rulesSignPackDoc(t, priv, string(doc)))
		if err != nil {
			t.Fatalf("DecodeRulesPack(signed fixture): %v", err)
		}
		if err := VerifyRulesPack(decoded, &rulesKeyVerifier{keyID: rulesTestKeyID, public: public}); err != nil {
			t.Fatalf("VerifyRulesPack = %v, want nil", err)
		}
		if len(decoded.Rules) != 1 || decoded.Rules[0].Options == nil || decoded.Rules[0].Options.Email == nil {
			t.Fatalf("decoded rules = %+v, want one rule carrying the email options object", decoded.Rules)
		}
		if got := decoded.Rules[0].Options.Email.Suffixes; !slices.Equal(got, []string{"corp.com"}) {
			t.Errorf("decoded suffixes = %v, want [corp.com]", got)
		}
	})

	t.Run("an options-less rule keeps the frozen signing bytes", func(t *testing.T) {
		pack := optionsLessPack()
		body, err := json.Marshal(pack)
		if err != nil {
			t.Fatalf("marshal pack fixture: %v", err)
		}
		if bytes.Contains(body, []byte(`"options"`)) {
			t.Fatalf("options-less rule marshaled an options key: %s", body)
		}
		if got := hex.EncodeToString(RulesPackSigningInput(pack)); got != wantOptionsLessSigningInput {
			t.Errorf("options-less signing input drifted:\n got: %s\nwant: %s", got, wantOptionsLessSigningInput)
		}
	})

	t.Run("an unknown key nested under options is still rejected", func(t *testing.T) {
		doc := rulesPackDoc(10, "", "",
			`{"id":"email.corp","type":"email","action":"redact","options":{"email":{"suffixes":["corp.com"],"bogus":true}}}`)
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(doc), &fields); err != nil {
			t.Fatalf("unmarshal fixture: %v", err)
		}
		fields["signature"] = json.RawMessage(`"AA"`)
		signed, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("marshal signed fixture: %v", err)
		}
		_, err = DecodeRulesPack(signed)
		if !errors.Is(err, ErrMalformedDoc) {
			t.Fatalf("DecodeRulesPack(unknown nested option) = %v, want ErrMalformedDoc", err)
		}
		if !strings.Contains(err.Error(), "bogus") {
			t.Errorf("decode error %q does not name the unknown field", err)
		}
	})
}
