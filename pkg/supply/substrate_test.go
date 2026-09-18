package supply

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// substrateKeyPair returns a fresh base64 raw-URL public key and its private
// half, so no test ever needs embedded key material.
func substrateKeyPair(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(pub), priv
}

// substrateSigned builds a domain-separated signing input and its signature.
func substrateSigned(domain string, payload []byte, priv ed25519.PrivateKey) ([]byte, []byte) {
	input := append([]byte(domain+"\n"), payload...)
	return input, ed25519.Sign(priv, input)
}

// countingFetcher proves the verify-only path never touches the network.
type countingFetcher struct{ calls atomic.Int64 }

func (c *countingFetcher) Get(context.Context, string) ([]byte, error) {
	c.calls.Add(1)
	return nil, errors.New("test fetcher must not be called")
}

// recordingVerifier is a stub Verifier bound to one test key.
type recordingVerifier struct {
	calls  atomic.Int64
	keyID  string
	public string
}

func (v *recordingVerifier) Verify(domain, keyID string, signingInput, sig []byte) error {
	v.calls.Add(1)
	if domain != DomainRulesPack || keyID != v.keyID {
		return ErrWrongKey
	}
	return VerifyEd25519(v.public, signingInput, sig)
}

// stubIssuer is the injectable seam: it holds a Fetcher, but this path only
// ever consults the Verifier.
type stubIssuer struct {
	fetcher  Fetcher
	verifier Verifier
}

func (s stubIssuer) verifyOnly(domain, keyID string, signingInput, sig []byte) error {
	return s.verifier.Verify(domain, keyID, signingInput, sig)
}

var (
	_ Fetcher  = (*countingFetcher)(nil)
	_ Verifier = (*recordingVerifier)(nil)
)

// TestSubstrate is the W5.1 happy QA: constants, embedded roots, signature
// accept/reject, caps, the bounded fetch and the injectable seams.
func TestSubstrate(t *testing.T) {
	t.Run("frozen wire constants", func(t *testing.T) {
		if BaseURL != "https://updates.tokenhush.com" {
			t.Fatalf("BaseURL = %q, want exactly https://updates.tokenhush.com", BaseURL)
		}
		if ChannelQuery != "?channel=stable" {
			t.Fatalf("ChannelQuery = %q", ChannelQuery)
		}
		paths := map[string]string{
			"/v1/update/manifest":    UpdateManifestPath,
			"/v1/update/revocations": UpdateRevocationsPath,
			"/v1/update/keylist":     updateKeylistPath,
			"/v1/rules/manifest":     RulesManifestPath,
			"/v1/rules/bundle":       RulesBundlePath,
			"/v1/rules/revocations":  rulesRevocationsPath,
		}
		for want, got := range paths {
			if got != want {
				t.Errorf("path = %q, want %q", got, want)
			}
		}
		composed := BaseURL + UpdateManifestPath + ChannelQuery
		if composed != "https://updates.tokenhush.com/v1/update/manifest?channel=stable" {
			t.Errorf("composed update manifest URL = %q", composed)
		}
		domains := []string{
			DomainUpdateManifest, DomainUpdateRevocations, DomainUpdateKeylist,
			DomainRulesManifest, DomainRulesPack, DomainRulesRevocations,
		}
		wantDomains := []string{
			"tokenhush-update-manifest-v1", "tokenhush-update-revocations-v1",
			"tokenhush-update-keylist-v1", "tokenhush-rules-manifest-v1",
			"tokenhush-rules-pack-v1", "tokenhush-rules-revocations-v1",
		}
		if !slices.Equal(domains, wantDomains) {
			t.Errorf("domain tags = %q, want %q", domains, wantDomains)
		}
		if KeyRootUpdate != "root-2026-09" || KeyRulesRoot != "rules-2026-09" {
			t.Errorf("root key ids = %q/%q", KeyRootUpdate, KeyRulesRoot)
		}
		if MaxUpdateDocBytes != 131072 || MaxRulesDocBytes != 262144 || MaxArtifactBytes != 268435456 {
			t.Errorf("caps = %d/%d/%d, want 131072/262144/268435456",
				MaxUpdateDocBytes, MaxRulesDocBytes, MaxArtifactBytes)
		}
		t.Logf("QA happy: base URL %s, 6 frozen domain tags, caps 128KiB/256KiB/256MiB", BaseURL)
	})

	t.Run("embeds only the two public roots", func(t *testing.T) {
		roots := DefaultRootKeys()
		want := map[string]string{
			"root-2026-09":  "6X3Sz-1c9u5iySAkHMSR4MvxPy812FV7kjrqd-HHZvQ",
			"rules-2026-09": "IBCvse8BQWafHk0HwLbaq9gycQm_9uDN8-6DHd-Ucvw",
		}
		if len(roots) != len(want) {
			t.Fatalf("DefaultRootKeys() has %d entries, want %d", len(roots), len(want))
		}
		for _, root := range roots {
			if want[root.ID] != root.Public {
				t.Errorf("root %q public = %q, want %q", root.ID, root.Public, want[root.ID])
			}
			pub, err := base64.RawURLEncoding.DecodeString(root.Public)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				t.Errorf("root %q public is not a %d-byte base64 raw-URL key (err=%v)",
					root.ID, ed25519.PublicKeySize, err)
			}
			if strings.HasPrefix(root.ID, "upd-") {
				t.Errorf("online update key %q must never be embedded", root.ID)
			}
		}
	})

	t.Run("accepts a valid signature", func(t *testing.T) {
		pub, priv := substrateKeyPair(t)
		input, sig := substrateSigned(DomainUpdateManifest, []byte(`{"serial":1}`), priv)
		if err := VerifyEd25519(pub, input, sig); err != nil {
			t.Fatalf("VerifyEd25519(valid) = %v, want nil", err)
		}
		sigB64 := base64.RawURLEncoding.EncodeToString(sig)
		if err := verifyEd25519B64(pub, input, sigB64); err != nil {
			t.Fatalf("verifyEd25519B64(valid) = %v, want nil", err)
		}
		if _, err := DecodeSignature(sigB64); err != nil {
			t.Fatalf("DecodeSignature(valid) = %v, want nil", err)
		}
	})

	t.Run("rejects wrong keys and malformed signatures typedly", func(t *testing.T) {
		pub, priv := substrateKeyPair(t)
		other, _ := substrateKeyPair(t)
		input, sig := substrateSigned(DomainUpdateManifest, []byte(`{"serial":1}`), priv)
		cases := []struct {
			name string
			err  error
			want error
		}{
			{"wrong key", VerifyEd25519(other, input, sig), ErrBadSignature},
			{"wrong-length key", VerifyEd25519("c2hvcnQ", input, sig), ErrWrongKey},
			{"non-base64 key", VerifyEd25519("!!!not-base64!!!", input, sig), ErrWrongKey},
			{"truncated signature", VerifyEd25519(pub, input, sig[:len(sig)-1]), ErrBadSignature},
			{"empty signature", VerifyEd25519(pub, input, nil), ErrBadSignature},
			{"non-base64 signature", verifyEd25519B64(pub, input, "!!!not-base64!!!"), ErrBadSignature},
			{"static verifier unknown key", NewStaticVerifier().Verify(DomainUpdateManifest, "upd-2026-09", input, sig), ErrWrongKey},
			{"static verifier empty domain", NewStaticVerifier().Verify("", KeyRootUpdate, input, sig), ErrBadSignature},
			{"static verifier unverifiable root", NewStaticVerifier().Verify(DomainUpdateManifest, KeyRootUpdate, input, sig), ErrBadSignature},
		}
		for _, tc := range cases {
			if !errors.Is(tc.err, tc.want) {
				t.Errorf("%s: err = %v, want %v", tc.name, tc.err, tc.want)
			}
		}
	})

	t.Run("rejects a flipped signature byte typedly", func(t *testing.T) {
		pub, priv := substrateKeyPair(t)
		input, sig := substrateSigned(DomainRulesPack, []byte(`{"serial":7}`), priv)
		flipped := bytes.Clone(sig)
		flipped[0] ^= 0x01
		err := VerifyEd25519(pub, input, flipped)
		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("flipped byte: err = %v, want ErrBadSignature", err)
		}
		t.Logf("QA failure: flipped signature byte -> %v (ErrBadSignature=true)", err)
	})

	t.Run("rejects oversized documents typedly", func(t *testing.T) {
		if DocLimit(DomainUpdateManifest) != 131072 || DocLimit(DomainRulesPack) != 262144 {
			t.Fatalf("DocLimit = %d/%d", DocLimit(DomainUpdateManifest), DocLimit(DomainRulesPack))
		}
		cases := []struct {
			name   string
			domain string
			size   int
			ok     bool
		}{
			{"update manifest at cap", DomainUpdateManifest, 131072, true},
			{"update manifest over cap", DomainUpdateManifest, 131073, false},
			{"update revocations over cap", DomainUpdateRevocations, 131073, false},
			{"update keylist over cap", DomainUpdateKeylist, 131073, false},
			{"rules pack at cap", DomainRulesPack, 262144, true},
			{"rules pack over cap", DomainRulesPack, 262145, false},
			{"rules manifest over cap", DomainRulesManifest, 262145, false},
			{"rules revocations over cap", DomainRulesRevocations, 262145, false},
			{"rules doc above the update cap", DomainRulesManifest, 131073, true},
			{"unknown domain fails closed", "tokenhush-unknown-v1", 131073, false},
		}
		for _, tc := range cases {
			err := CheckDocSize(tc.domain, make([]byte, tc.size))
			if tc.ok && err != nil {
				t.Errorf("%s: err = %v, want nil", tc.name, err)
			}
			if !tc.ok && !errors.Is(err, ErrDocTooLarge) {
				t.Errorf("%s: err = %v, want ErrDocTooLarge", tc.name, err)
			}
		}
	})

	t.Run("bounded fetch", func(t *testing.T) {
		t.Run("returns a small body", func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer srv.Close()
			body, err := NewBoundedHTTPFetcher(2*time.Second, MaxUpdateDocBytes).Get(context.Background(), srv.URL)
			if err != nil {
				t.Fatalf("Get = %v, want nil", err)
			}
			if string(body) != `{"ok":true}` {
				t.Fatalf("body = %q", body)
			}
		})
		t.Run("times out typedly", func(t *testing.T) {
			stall := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			}))
			defer stall.Close()
			start := time.Now()
			_, err := NewBoundedHTTPFetcher(150*time.Millisecond, MaxUpdateDocBytes).Get(context.Background(), stall.URL)
			if !errors.Is(err, ErrFetchTimeout) {
				t.Fatalf("stalled Get = %v, want ErrFetchTimeout", err)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("stalled Get took %v", elapsed)
			}
			t.Logf("QA happy: stalled server -> %v", err)
		})
		t.Run("caps the body typedly", func(t *testing.T) {
			var written atomic.Int64
			big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n, _ := w.Write(bytes.Repeat([]byte("a"), 4097))
				written.Store(int64(n))
			}))
			defer big.Close()
			_, err := NewBoundedHTTPFetcher(2*time.Second, 4096).Get(context.Background(), big.URL)
			if !errors.Is(err, ErrDocTooLarge) {
				t.Fatalf("oversized Get = %v, want ErrDocTooLarge", err)
			}
			if written.Load() < 4097 {
				t.Fatalf("server only sent %d bytes", written.Load())
			}
		})
	})

	t.Run("seams are injectable with zero network", func(t *testing.T) {
		pub, priv := substrateKeyPair(t)
		input, sig := substrateSigned(DomainRulesPack, []byte(`{"serial":1}`), priv)
		fetcher := &countingFetcher{}
		verifier := &recordingVerifier{keyID: KeyRulesRoot, public: pub}
		issuer := stubIssuer{fetcher: fetcher, verifier: verifier}
		if err := issuer.verifyOnly(DomainRulesPack, KeyRulesRoot, input, sig); err != nil {
			t.Fatalf("verifyOnly = %v, want nil", err)
		}
		if got := fetcher.calls.Load(); got != 0 {
			t.Fatalf("verify-only path invoked the fetcher %d times", got)
		}
		if got := verifier.calls.Load(); got != 1 {
			t.Fatalf("verifier calls = %d, want 1", got)
		}
	})

	t.Logf("QA happy: 6 domain tags pinned, 2 public roots, caps enforced, bounded GET bounded, seams injectable")
}
