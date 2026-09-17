package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/supply"
)

// rulesTestKeyID is the stub issuer's key id.
const rulesTestKeyID = "rules-test-key"

// rulesTestNow is the fixed clock every fixture window contains.
func rulesTestNow() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }

// stubSignature is a syntactically valid base64 raw-URL signature; the stub
// verifier never inspects its bytes.
func stubSignature() string { return base64.RawURLEncoding.EncodeToString([]byte("stub-signature")) }

// mustMarshal renders one fixture document and fails the test on an error.
func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

// stubVerifier accepts every signature and records the domains it verified, so
// a test can prove the check sequence reached verification.
type stubVerifier struct{ domains []string }

func (v *stubVerifier) Verify(domain, keyID string, signingInput, sig []byte) error {
	v.domains = append(v.domains, domain)
	return nil
}

// stubFetcher is the stub issuer's transport: a URL-keyed body map with a call
// log, so a test can prove the code under test never fetched.
type stubFetcher struct {
	bodies map[string][]byte
	calls  []string
}

func newStubFetcher() *stubFetcher { return &stubFetcher{bodies: map[string][]byte{}} }

func (f *stubFetcher) set(url string, body []byte) { f.bodies[url] = body }

func (f *stubFetcher) Get(_ context.Context, url string) ([]byte, error) {
	f.calls = append(f.calls, url)
	body, ok := f.bodies[url]
	if !ok {
		return nil, fmt.Errorf("stubFetcher: no body for %s", url)
	}
	return body, nil
}

func (f *stubFetcher) invoked() int { return len(f.calls) }

// rulesTestBundle renders one strict wire rules-pack document with a single
// evaluable rule.
func rulesTestBundle(serial uint64) []byte {
	window := rulesTestNow()
	return []byte(fmt.Sprintf(
		`{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":%d,"key_id":%q,"not_before":%q,"expires":%q,"rules":[{"id":"tok","type":"prefix","action":"redact"}]}`,
		serial, rulesTestKeyID, window.Add(-time.Hour).Format(time.RFC3339), window.Add(time.Hour).Format(time.RFC3339)))
}

// rulesTestManifest renders the signed pointer to one bundle. The signature is
// synthetic: the command is wired to the stub verifier.
func rulesTestManifest(t *testing.T, serial uint64, bundle []byte) []byte {
	t.Helper()
	window := rulesTestNow()
	return mustMarshal(t, supply.RulesManifestPayload{
		Channel: "stable", SchemaVersion: 1, MinBinaryVersion: "0.3.0",
		Serial: serial, KeyID: rulesTestKeyID,
		NotBefore:    supply.EpochSeconds(window.Add(-time.Hour).Unix()),
		Expires:      supply.EpochSeconds(window.Add(time.Hour).Unix()),
		BundleSHA256: fmt.Sprintf("%x", sha256.Sum256(bundle)),
		Bundle:       "rules/stable/bundle.json", Signature: stubSignature(),
	})
}

// rulesTestURLs are the two frozen rules URLs the sync fetches.
func rulesTestURLs() (manifest, bundle string) {
	return supply.BaseURL + supply.RulesManifestPath + supply.ChannelQuery,
		supply.BaseURL + supply.RulesBundlePath + supply.ChannelQuery
}

// rulesTestEnv is the close-to-end CLI harness for the rules command: a stub
// issuer, a stub verifier, a temp data dir and an injectable environment.
type rulesTestEnv struct {
	dataDir  string
	fetcher  *stubFetcher
	verifier *stubVerifier
	ruleEnv  map[string]string
}

func newRulesTestEnv(t *testing.T) *rulesTestEnv {
	t.Helper()
	return &rulesTestEnv{dataDir: t.TempDir(), fetcher: newStubFetcher(), verifier: &stubVerifier{}, ruleEnv: map[string]string{}}
}

// publish wires one serial's manifest and bundle into the stub issuer.
func (e *rulesTestEnv) publish(t *testing.T, serial uint64) {
	t.Helper()
	bundle := rulesTestBundle(serial)
	manifestURL, bundleURL := rulesTestURLs()
	e.fetcher.set(manifestURL, rulesTestManifest(t, serial, bundle))
	e.fetcher.set(bundleURL, bundle)
}

func (e *rulesTestEnv) seams() rulesSeams {
	return rulesSeams{
		lookupEnv: func(name string) (string, bool) { value, ok := e.ruleEnv[name]; return value, ok },
		dataDir:   func() (string, error) { return e.dataDir, nil },
		fetcher:   func() supply.Fetcher { return e.fetcher },
		verifier:  e.verifier,
		now:       rulesTestNow,
	}
}

// runRulesSync seeds the real sync path and fails the test on a non-zero exit.
func (e *rulesTestEnv) runRulesSync(t *testing.T, serial uint64) {
	t.Helper()
	e.publish(t, serial)
	var stdout, stderr bytes.Buffer
	if code := rulesSync(nil, &stdout, &stderr, e.seams()); code != exitOK {
		t.Fatalf("rules sync (serial %d) = %d, want 0 (stderr %q)", serial, code, stderr.String())
	}
}

// TestRulesSyncCheckReportsWithoutWriting is the QA happy path: every check
// runs (both documents verified) and no state is written.
func TestRulesSyncCheckReportsWithoutWriting(t *testing.T) {
	env := newRulesTestEnv(t)
	env.publish(t, 7)
	var stdout, stderr bytes.Buffer
	if code := rulesSync([]string{"--check"}, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("rules sync --check = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "serial 7") || !strings.Contains(stdout.String(), "no state was written") {
		t.Errorf("stdout = %q, want the verified-serial verdict and the no-write note", stdout.String())
	}
	if env.fetcher.invoked() != 2 {
		t.Errorf("fetcher calls = %d, want the manifest and the bundle", env.fetcher.invoked())
	}
	if len(env.verifier.domains) != 2 {
		t.Errorf("verified domains = %v, want the manifest and the pack", env.verifier.domains)
	}
	entries, err := os.ReadDir(env.dataDir)
	if err != nil {
		t.Fatalf("read data dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a --check run wrote %d entries into the data dir", len(entries))
	}
	if _, err := supply.NewRulesHighWater(env.dataDir); err != nil {
		t.Fatalf("open high-water: %v", err)
	}
	if _, err := os.Stat(filepath.Join(env.dataDir, "rules", "highwater.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a --check run created the high-water file (stat err = %v)", err)
	}
}

// TestRulesSyncCheckIsUpToDateWithoutWriting pins the replay verdict: a serial
// the persisted mark already covers is reported without a bundle fetch and
// without writing.
func TestRulesSyncCheckIsUpToDateWithoutWriting(t *testing.T) {
	env := newRulesTestEnv(t)
	env.publish(t, 7)
	mark, err := supply.NewRulesHighWater(env.dataDir)
	if err != nil {
		t.Fatalf("open high-water: %v", err)
	}
	if err := mark.Advance(7); err != nil {
		t.Fatalf("seed mark: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := rulesSync([]string{"--check"}, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("rules sync --check = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "already current") {
		t.Errorf("stdout = %q, want the up-to-date verdict", stdout.String())
	}
	if env.fetcher.invoked() != 1 {
		t.Errorf("fetcher calls = %d, want only the manifest (the replay never re-fetches the bundle)", env.fetcher.invoked())
	}
	if got := mark.Current(); got != 7 {
		t.Errorf("high-water mark = %d, want the untouched 7", got)
	}
}

// TestRulesSyncCheckRejectsAReplayAgainstTheRealMark proves every check uses
// the persisted anti-rollback mark, and that a rejection writes nothing.
func TestRulesSyncCheckRejectsAReplayAgainstTheRealMark(t *testing.T) {
	env := newRulesTestEnv(t)
	env.publish(t, 6)
	mark, err := supply.NewRulesHighWater(env.dataDir)
	if err != nil {
		t.Fatalf("open high-water: %v", err)
	}
	if err := mark.Advance(7); err != nil {
		t.Fatalf("seed mark: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := rulesSync([]string{"--check"}, &stdout, &stderr, env.seams())
	if code != exitFailure {
		t.Fatalf("rules sync --check (serial 6 against mark 7) = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "below high-water mark") {
		t.Errorf("stderr = %q, want the anti-rollback rejection", stderr.String())
	}
	if entries, err := os.ReadDir(env.dataDir); err != nil || len(entries) != 1 {
		t.Errorf("data dir entries = %v (err %v), want only the seeded high-water file", entries, err)
	}
}

// TestRulesSyncWritesTheCacheAndMark is the production sync: the verified pack
// is cached and the mark advances.
func TestRulesSyncWritesTheCacheAndMark(t *testing.T) {
	env := newRulesTestEnv(t)
	env.publish(t, 7)
	var stdout, stderr bytes.Buffer
	if code := rulesSync(nil, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("rules sync = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "serial 7 activated") {
		t.Errorf("stdout = %q, want the activation verdict", stdout.String())
	}
	active, err := supply.NewRulesCache(env.dataDir).ActiveSerial()
	if err != nil {
		t.Fatalf("active serial: %v", err)
	}
	if active != 7 {
		t.Errorf("cached active serial = %d, want 7", active)
	}
	mark, err := supply.NewRulesHighWater(env.dataDir)
	if err != nil {
		t.Fatalf("open high-water: %v", err)
	}
	if got := mark.Current(); got != 7 {
		t.Errorf("high-water mark = %d, want 7", got)
	}
}

// TestRulesSyncSwitchSendsNoRequest pins the disclosed switch: no fetcher call
// and the no-request message, for both sync modes.
func TestRulesSyncSwitchSendsNoRequest(t *testing.T) {
	env := newRulesTestEnv(t)
	env.publish(t, 7)
	env.ruleEnv[noRuleSyncEnv] = "1"
	for _, args := range [][]string{nil, {"--check"}} {
		var stdout, stderr bytes.Buffer
		if code := rulesSync(args, &stdout, &stderr, env.seams()); code != exitOK {
			t.Fatalf("rules sync %v with the switch = %d, want 0 (stderr %q)", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "no request was sent") {
			t.Errorf("stdout = %q, want the no-request message", stdout.String())
		}
	}
	if env.fetcher.invoked() != 0 {
		t.Errorf("fetcher calls = %d, want 0 with the switch set", env.fetcher.invoked())
	}
}

// TestRulesRollbackRestoresThePreviousVerifiedPack rolls an activated serial 8
// back to the cached serial 7 without a single fetch and without rewinding the
// anti-rollback mark.
func TestRulesRollbackRestoresThePreviousVerifiedPack(t *testing.T) {
	env := newRulesTestEnv(t)
	env.runRulesSync(t, 7)
	env.runRulesSync(t, 8)
	callsBefore := env.fetcher.invoked()
	var stdout, stderr bytes.Buffer
	if code := rulesRollback(nil, &stdout, &stderr, env.seams()); code != exitOK {
		t.Fatalf("rules rollback = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "serial 7") {
		t.Errorf("stdout = %q, want the restored serial", stdout.String())
	}
	active, err := supply.NewRulesCache(env.dataDir).ActiveSerial()
	if err != nil {
		t.Fatalf("active serial: %v", err)
	}
	if active != 7 {
		t.Errorf("active serial after rollback = %d, want 7", active)
	}
	if env.fetcher.invoked() != callsBefore {
		t.Errorf("rollback made %d fetch(es), want none", env.fetcher.invoked()-callsBefore)
	}
	mark, err := supply.NewRulesHighWater(env.dataDir)
	if err != nil {
		t.Fatalf("open high-water: %v", err)
	}
	if got := mark.Current(); got != 8 {
		t.Errorf("high-water mark after rollback = %d, want the unrewound 8", got)
	}
}

// TestRulesRollbackWithoutAPreviousPackIsTyped pins the typed failure when the
// cache holds nothing earlier to restore.
func TestRulesRollbackWithoutAPreviousPackIsTyped(t *testing.T) {
	env := newRulesTestEnv(t)
	if _, err := previousVerifiedPack(env.dataDir, 8, env.seams()); !errors.Is(err, errNoRollbackTarget) {
		t.Errorf("previousVerifiedPack on an empty cache = %v, want the typed %v", err, errNoRollbackTarget)
	}
	var stdout, stderr bytes.Buffer
	if code := rulesRollback(nil, &stdout, &stderr, env.seams()); code != exitFailure {
		t.Fatalf("rules rollback on an empty cache = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), errNoRollbackTarget.Error()) {
		t.Errorf("stderr = %q, want it to name the typed failure", stderr.String())
	}
}

// TestRulesRollbackRefusesACorruptCandidate proves the candidate is verified
// before the active pointer moves: a corrupt previous pack is not restored and
// the pack in force stays.
func TestRulesRollbackRefusesACorruptCandidate(t *testing.T) {
	env := newRulesTestEnv(t)
	env.runRulesSync(t, 7)
	env.runRulesSync(t, 8)
	corrupt := filepath.Join(env.dataDir, "rules", "7", "bundle.json")
	if err := os.WriteFile(corrupt, []byte(`{"channel":"stable"}`), 0o600); err != nil {
		t.Fatalf("corrupt the cached candidate: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := rulesRollback(nil, &stdout, &stderr, env.seams()); code != exitFailure {
		t.Fatalf("rules rollback with a corrupt candidate = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), errNoRollbackTarget.Error()) {
		t.Errorf("stderr = %q, want the typed failure", stderr.String())
	}
	active, err := supply.NewRulesCache(env.dataDir).ActiveSerial()
	if err != nil {
		t.Fatalf("active serial: %v", err)
	}
	if active != 8 {
		t.Errorf("active serial after a refused rollback = %d, want the retained 8", active)
	}
}

// TestRulesUsageErrors pins the usage exits, including the flags that must not
// exist: no base URL and no key is configurable from the CLI.
func TestRulesUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"nosuch"},
		{"sync", "extra"},
		{"sync", "--base-url", "https://evil.test"},
		{"sync", "--key", "deadbeef"},
		{"rollback", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		if code := rulesCommand(args, &stdout, &stderr); code != exitUsage {
			t.Errorf("rules %v = %d, want %d (stderr %q)", args, code, exitUsage, stderr.String())
		}
	}
}

// TestCommandSetIsExactlySeven pins the frozen CLI surface.
func TestCommandSetIsExactlySeven(t *testing.T) {
	want := []string{"env", "privacy", "rules", "run", "status", "update", "version"}
	got := slices.Sorted(maps.Keys(commands))
	if !slices.Equal(got, want) {
		t.Errorf("registered commands = %v, want exactly %v", got, want)
	}
}
