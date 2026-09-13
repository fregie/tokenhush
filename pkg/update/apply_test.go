package update

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBinary(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readBinary(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func sha256Hex(b []byte) string { return hex.EncodeToString(sha256Sum(b)) }

// validApplyConfig is a complete, valid self-managed configuration reused by
// every configuration test.
func validApplyConfig() ApplyConfig {
	return ApplyConfig{
		Source:   Source{Kind: SourceSelfManaged, Exe: "/home/me/.local/bin/tokenhush"},
		Channel:  "stable",
		BaseURL:  "https://updates.tokenhush.com",
		Verifier: &Verifier{},
	}
}

// TestNewApplierRefusesNonSelfManagedSources asserts brew/scoop/unknown are
// rejected with ErrNotSelfManaged: self-update must never overwrite a
// package-managed or unrecognised install. This is the structural guarantee
// behind the "brew never self-replaces" acceptance.
func TestNewApplierRefusesNonSelfManagedSources(t *testing.T) {
	for _, kind := range []SourceKind{SourceBrew, SourceScoop, SourceUnknown} {
		cfg := validApplyConfig()
		cfg.Source = Source{Kind: kind, Exe: "/usr/bin/tokenhush"}
		_, err := NewApplier(cfg)
		if !errors.Is(err, ErrNotSelfManaged) {
			t.Fatalf("NewApplier(%s) error = %v, want ErrNotSelfManaged", kind, err)
		}
	}
}

// TestNewApplierValidatesConfiguration asserts every required field is
// enforced before the engine can fetch or write anything.
func TestNewApplierValidatesConfiguration(t *testing.T) {
	if _, err := NewApplier(validApplyConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	tests := []struct {
		name string
		bad  func(c *ApplyConfig)
		want error
	}{
		{"missing channel", func(c *ApplyConfig) { c.Channel = "" }, ErrMissingConfig},
		{"missing base url", func(c *ApplyConfig) { c.BaseURL = "" }, ErrMissingConfig},
		{"non-https base url", func(c *ApplyConfig) { c.BaseURL = "http://updates.tokenhush.com" }, nil},
		{"base url with query", func(c *ApplyConfig) { c.BaseURL = "https://updates.tokenhush.com?x=1" }, nil},
		{"missing verifier", func(c *ApplyConfig) { c.Verifier = nil }, ErrMissingConfig},
		{"missing target", func(c *ApplyConfig) { c.Target, c.Source.Exe = "", "" }, ErrMissingConfig},
		{"relative target", func(c *ApplyConfig) { c.Target = "tokenhush" }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validApplyConfig()
			tt.bad(&cfg)
			_, err := NewApplier(cfg)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestNewApplierDefaultsTargetToSourceExe asserts the running binary path from
// source detection is the default install target.
func TestNewApplierDefaultsTargetToSourceExe(t *testing.T) {
	cfg := validApplyConfig()
	a, err := NewApplier(cfg)
	if err != nil {
		t.Fatalf("NewApplier: %v", err)
	}
	if a.target != cfg.Source.Exe {
		t.Fatalf("target = %q, want %q", a.target, cfg.Source.Exe)
	}
}

// TestRefusalMessageNamesTheOwningManager asserts the refusal is actionable:
// each non-self-managed source is told how to upgrade instead.
func TestRefusalMessageNamesTheOwningManager(t *testing.T) {
	tests := []struct {
		kind SourceKind
		want string
	}{
		{SourceBrew, "brew upgrade"},
		{SourceScoop, "scoop update"},
		{SourceUnknown, "install script"},
	}
	for _, tt := range tests {
		msg := RefusalMessage(Source{Kind: tt.kind})
		if !strings.Contains(msg, tt.want) {
			t.Errorf("RefusalMessage(%s) = %q, want it to mention %q", tt.kind, msg, tt.want)
		}
		if !strings.Contains(msg, "package-managed") {
			t.Errorf("RefusalMessage(%s) must state it never overwrites a package manager", tt.kind)
		}
	}
}

// TestCandidateRevokedMergesIndependentAndManifestSources asserts the
// kill-switch honours the independent revocation document first and the
// manifest's advisory lists as defence in depth.
func TestCandidateRevokedMergesIndependentAndManifestSources(t *testing.T) {
	m := baseManifest() // version 0.4.0, serial 10

	if candidateRevoked(RevocationList{}, m) {
		t.Fatal("a clean candidate must not be reported revoked")
	}
	if !candidateRevoked(RevocationList{RevokedVersions: []string{"0.4.0"}}, m) {
		t.Fatal("an independently revoked version must be rejected")
	}
	if !candidateRevoked(RevocationList{RevokedSerials: []uint64{10}}, m) {
		t.Fatal("an independently revoked serial must be rejected")
	}
	self := m
	self.RevokedVersions = []string{"0.4.0"}
	if !candidateRevoked(RevocationList{}, self) {
		t.Fatal("a manifest-declared revocation must be rejected defensively")
	}
}

// TestUpdatePackageUsesNoLicenseTrust validates the hard constraint that the
// update channel never reuses the license trust chain or its revocation list:
// no file in pkg/update may import pkg/license or an entitlement package.
func TestUpdatePackageUsesNoLicenseTrust(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "pkg/license") || strings.Contains(path, "entitlement") {
				t.Errorf("%s imports %q: the update channel must use its own trust root", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Go files were inspected; the guard would be vacuous")
	}
}

// TestHashMatchesConstantTime asserts the artifact hash comparison accepts the
// exact digest and rejects a truncated, malformed or wrong one.
func TestHashMatchesConstantTime(t *testing.T) {
	content := []byte("artifact-bytes")
	got := sha256Sum(content)
	if !hashMatches(sha256Hex(content), got) {
		t.Fatal("the exact digest must match")
	}
	if hashMatches(strings.Repeat("00", 32), got) {
		t.Fatal("a wrong digest must not match")
	}
	if hashMatches("abcd", got) {
		t.Fatal("a malformed digest must not match")
	}
}

// TestApplyURLsEncodeTheChannel asserts the engine builds the B2 endpoint
// contract with the channel safely encoded.
func TestApplyURLsEncodeTheChannel(t *testing.T) {
	cfg := validApplyConfig()
	cfg.Channel = "beta/../evil"
	a, err := NewApplier(cfg)
	if err != nil {
		t.Fatalf("NewApplier: %v", err)
	}
	if got := a.manifestURL(); !strings.HasPrefix(got, "https://updates.tokenhush.com"+ManifestPath+"?channel=") {
		t.Fatalf("manifestURL = %q", got)
	}
	if strings.Contains(a.manifestURL(), "beta/../evil") || strings.Contains(a.revocationsURL(), "beta/../evil") {
		t.Fatalf("channel must be query-escaped: manifest=%q revocations=%q", a.manifestURL(), a.revocationsURL())
	}
}
