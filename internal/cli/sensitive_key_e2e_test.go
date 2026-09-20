package cli

// sensitive_key_e2e_test.go is the Feature-A end-to-end proof (work plan todo
// 14): it drives the REAL run gateway against a REAL signed rules pack that
// carries `sensitive_keys`. There is no shortcut — the pack's manifest and
// bundle are Ed25519-signed with an in-process issuer key over the frozen
// supply projections, written to the production rules cache, and loaded at
// startup through the production strict-decode, verify, floor and compile path
// (buildGatewayWithVerifier only swaps the trust root). Every assertion is on
// captured bytes: the exact request the upstream received and the bytes the
// client got back.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/supply"
)

// e2eSensitiveKeyID is the issuer key id both signed documents carry, and the
// serial is above zero so the cache pointer is meaningful (zero is the
// no-pack sentinel). The pack is a real remote pack: it carries serial and
// key_id, so pkg/filter classifies it RemotePack and the floor checks it.
const (
	e2eSensitiveKeyID      = "rules-2026-09"
	e2eSensitivePackSerial = 9
)

// e2eSensitiveVerifier verifies the two rules domains under one in-process
// key. It is the only difference from the embedded trust roots.
type e2eSensitiveVerifier struct{ public string }

func (v e2eSensitiveVerifier) Verify(domain, keyID string, signingInput, sig []byte) error {
	if keyID != e2eSensitiveKeyID || (domain != supply.DomainRulesManifest && domain != supply.DomainRulesPack) {
		return supply.ErrWrongKey
	}
	return supply.VerifyEd25519(v.public, signingInput, sig)
}

// e2eSensitivePack builds a real signed manifest and bundle carrying the given
// sensitive_keys, and the verifier bound to its issuer key. The bundle is a
// strict wire document with RFC 3339 timestamps (the filter decoder's form);
// its signature covers the frozen supply projection, and the manifest's digest
// covers the exact bundle bytes that are stored.
func e2eSensitivePack(t *testing.T, keys []string) (manifestRaw, bundleRaw []byte, verifier supply.Verifier) {
	t.Helper()
	public, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("marshal keys: %v", err)
	}
	window := time.Now().UTC()
	bundleDoc := fmt.Sprintf(
		`{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":%d,"key_id":%q,"not_before":%q,"expires":%q,"sensitive_keys":{"keys":%s}}`,
		e2eSensitivePackSerial, e2eSensitiveKeyID,
		window.Add(-time.Hour).Format(time.RFC3339), window.Add(24*time.Hour).Format(time.RFC3339), keysJSON)

	decoded, err := supply.DecodeRulesPack([]byte(bundleDoc))
	if err != nil {
		t.Fatalf("DecodeRulesPack(fixture): %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bundleDoc), &fields); err != nil {
		t.Fatalf("unmarshal bundle fixture: %v", err)
	}
	sigJSON, err := json.Marshal(base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, supply.RulesPackSigningInput(decoded))))
	if err != nil {
		t.Fatalf("marshal bundle signature: %v", err)
	}
	fields["signature"] = sigJSON
	bundleRaw, err = json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal signed bundle: %v", err)
	}

	manifest := supply.RulesManifestPayload{
		Channel: "stable", SchemaVersion: 1, MinBinaryVersion: "0.3.0",
		Serial: e2eSensitivePackSerial, KeyID: e2eSensitiveKeyID,
		NotBefore:    supply.EpochSeconds(window.Add(-time.Hour).Unix()),
		Expires:      supply.EpochSeconds(window.Add(24 * time.Hour).Unix()),
		BundleSHA256: fmt.Sprintf("%x", sha256.Sum256(bundleRaw)),
		Bundle:       "rules/stable/bundle.json",
	}
	manifest.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, supply.RulesManifestSigningInput(manifest)))
	manifestRaw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal signed manifest: %v", err)
	}
	return manifestRaw, bundleRaw, e2eSensitiveVerifier{public: base64.RawURLEncoding.EncodeToString(public)}
}

// e2eSensitiveGateway seeds the production rules cache with a signed pack that
// carries keys, then starts the real run gateway over the echo upstream with a
// verifier bound to the pack's key. It mirrors e2eGateway except for the pack
// and the injected verifier.
func e2eSensitiveGateway(t *testing.T, upstream *e2eUpstream, keys []string) string {
	t.Helper()
	manifestRaw, bundleRaw, verifier := e2eSensitivePack(t, keys)
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")
	if err := supply.NewRulesCache(dataDir).Store(e2eSensitivePackSerial, manifestRaw, bundleRaw); err != nil {
		t.Fatalf("store signed pack: %v", err)
	}

	stop := make(chan struct{})
	seams := defaultRunSeams()
	seams.recoverRun = func(string) (supply.RecoveryResult, error) { return supply.RecoveryNone, nil }
	seams.loadConfig = func(string) (config.Config, error) {
		cfg := config.Default()
		cfg.Listen.Port = 0
		cfg.Upstreams = []config.Upstream{{Match: e2ePath, Target: upstream.server.URL}}
		return cfg, nil
	}
	seams.build = func(cfg config.Config, dir string, stderr io.Writer, logRedactions bool) (*gateway, error) {
		return buildGatewayWithVerifier(cfg, dir, stderr, logRedactions, verifier)
	}
	seams.notify = func(signals chan<- os.Signal) {
		<-stop
		signals <- syscall.SIGTERM
	}
	done := make(chan int, 1)
	go func() { done <- runWith(nil, io.Discard, seams) }()
	t.Cleanup(func() {
		close(stop)
		if code := <-done; code != exitOK {
			t.Errorf("runWith = %d, want %d", code, exitOK)
		}
	})

	state := waitForSession(t, dataDir)
	base := fmt.Sprintf("http://127.0.0.1:%d", state.Port)
	e2eWaitReady(t, base)
	return base
}

// TestE2ESensitiveKeyRedactsAndRestores is the Feature-A happy path through a
// signed pack: a matching immediate member leaves as a custom placeholder and
// the original returns to the client restored.
func TestE2ESensitiveKeyRedactsAndRestores(t *testing.T) {
	upstream := newE2EUpstream(t)
	base := e2eSensitiveGateway(t, upstream, []string{"password"})

	status, got := e2ePost(t, base+e2ePath, []byte(`{"password":"hunter2"}`), nil)
	if status != http.StatusOK {
		t.Fatalf("POST = %d, want 200 (body %s)", status, got)
	}
	sent := upstream.recorded()
	if bytes.Contains(sent, []byte("hunter2")) {
		t.Errorf("the sensitive value left the process: %s", sent)
	}
	if !bytes.Contains(sent, []byte("__PII_custom_")) {
		t.Errorf("no custom placeholder reached the upstream: %s", sent)
	}
	if !bytes.Contains(got, []byte("hunter2")) {
		t.Errorf("the original value did not return to the client: %s", got)
	}
	if bytes.Contains(got, []byte("__PII_")) {
		t.Errorf("a placeholder reached the client: %s", got)
	}
}

// TestE2ESensitiveKeyNumericKeyNoArrayMatch pins the member/array discriminator
// end to end: a numeric object key "0" matches its member, while the same
// scalar as an array element has no key and is forwarded unchanged.
func TestE2ESensitiveKeyNumericKeyNoArrayMatch(t *testing.T) {
	upstream := newE2EUpstream(t)
	base := e2eSensitiveGateway(t, upstream, []string{"0"})

	status, got := e2ePost(t, base+e2ePath, []byte(`{"0":"x"}`), nil)
	if status != http.StatusOK {
		t.Fatalf("object POST = %d, want 200 (body %s)", status, got)
	}
	if sent := upstream.recorded(); !bytes.Contains(sent, []byte("__PII_custom_")) {
		t.Errorf("the numeric object key did not match: %s", sent)
	}

	status, got = e2ePost(t, base+e2ePath, []byte(`["x"]`), nil)
	if status != http.StatusOK {
		t.Fatalf("array POST = %d, want 200 (body %s)", status, got)
	}
	sent := upstream.recorded()
	if bytes.Contains(sent, []byte("__PII_")) {
		t.Errorf("an array element must not match a numeric key: %s", sent)
	}
	if !bytes.Contains(sent, []byte(`["x"]`)) {
		t.Errorf("the array was not forwarded unchanged: %s", sent)
	}
	if bytes.Contains(got, []byte("__PII_")) {
		t.Errorf("a placeholder reached the client for an array element: %s", got)
	}
}

// TestE2ESensitiveKeyNestedDirectMemberMatches pins that the match is on the
// leaf's IMMEDIATE member key at any object depth: a nested password matches.
func TestE2ESensitiveKeyNestedDirectMemberMatches(t *testing.T) {
	upstream := newE2EUpstream(t)
	base := e2eSensitiveGateway(t, upstream, []string{"password"})

	status, got := e2ePost(t, base+e2ePath, []byte(`{"credentials":{"password":"hunter2"}}`), nil)
	if status != http.StatusOK {
		t.Fatalf("POST = %d, want 200 (body %s)", status, got)
	}
	sent := upstream.recorded()
	if bytes.Contains(sent, []byte("hunter2")) {
		t.Errorf("the nested sensitive value left the process: %s", sent)
	}
	if !bytes.Contains(sent, []byte("__PII_custom_")) {
		t.Errorf("the nested member did not match: %s", sent)
	}
	if !bytes.Contains(got, []byte("hunter2")) {
		t.Errorf("the nested original did not return to the client: %s", got)
	}
}

// TestE2ESensitiveKeyContainerValueNoMatch pins the frozen residual: a
// sensitive key whose value is a container is not matched, because the
// container's inner leaf has a different immediate member key ("secret").
func TestE2ESensitiveKeyContainerValueNoMatch(t *testing.T) {
	upstream := newE2EUpstream(t)
	base := e2eSensitiveGateway(t, upstream, []string{"password"})

	status, got := e2ePost(t, base+e2ePath, []byte(`{"password":{"secret":"x"}}`), nil)
	if status != http.StatusOK {
		t.Fatalf("POST = %d, want 200 (body %s)", status, got)
	}
	sent := upstream.recorded()
	if bytes.Contains(sent, []byte("__PII_")) {
		t.Errorf("a container value must not match a sensitive key: %s", sent)
	}
	if !bytes.Contains(sent, []byte(`{"password":{"secret":"x"}}`)) {
		t.Errorf("the container body was not forwarded unchanged: %s", sent)
	}
	if bytes.Contains(got, []byte("__PII_")) {
		t.Errorf("a placeholder reached the client for a container value: %s", got)
	}
}
