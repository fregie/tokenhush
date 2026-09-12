package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testKeyID = "test-key"

// refNow is the pinned clock the badge matrix runs against.
var refNow = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

// testVerifier returns a verifier bound to a freshly generated key pair and
// the pinned clock.
func testVerifier(t *testing.T) (Verifier, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return Verifier{Keys: []Key{{ID: testKeyID, Public: pub}}, Now: func() time.Time { return refNow }}, priv
}

// signedToken builds a valid Ed25519-signed license token. mutate runs before
// signing, so payload adjustments (key id, expiry) produce tokens that are
// correctly signed for the mutated payload.
func signedToken(tb testing.TB, priv ed25519.PrivateKey, mutate func(*License)) []byte {
	tb.Helper()
	lic := License{
		Version:   Version,
		KeyID:     testKeyID,
		LicenseID: "lic_test_0001",
		Subject:   "user@example.com",
		Features:  []string{"pro"},
		IssuedAt:  refNow.Add(-time.Hour),
		ExpiresAt: refNow.Add(365 * 24 * time.Hour),
	}
	if mutate != nil {
		mutate(&lic)
	}
	lic.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, SigningInput(lic)))
	raw, err := json.Marshal(lic)
	if err != nil {
		tb.Fatalf("marshal token: %v", err)
	}
	return raw
}

// reencodeToken decodes an already-signed token, applies mutate to the decoded
// license and re-marshals it. It exists for mutations that must not update the
// signature (e.g. corrupting the signature encoding).
func reencodeToken(tb testing.TB, raw []byte, mutate func(*License)) []byte {
	tb.Helper()
	var lic License
	if err := json.Unmarshal(raw, &lic); err != nil {
		tb.Fatalf("decode token: %v", err)
	}
	mutate(&lic)
	out, err := json.Marshal(lic)
	if err != nil {
		tb.Fatalf("marshal token: %v", err)
	}
	return out
}

// writeLicense writes raw to <dir>/license.json and returns the path.
func writeLicense(tb testing.TB, dir string, raw []byte) string {
	tb.Helper()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		tb.Fatalf("write license: %v", err)
	}
	return path
}

// TestLicenseBadge is the W6.7 acceptance matrix: a valid token renders the
// exact badge, and every hostile or absent variant renders nothing.
func TestLicenseBadge(t *testing.T) {
	v, priv := testVerifier(t)
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	valid := signedToken(t, priv, nil)

	t.Run("valid token renders the badge", func(t *testing.T) {
		path := writeLicense(t, t.TempDir(), valid)
		if got := v.Badge(path); got != Badge {
			t.Fatalf("Badge() = %q, want %q", got, Badge)
		}
	})

	t.Run("absent file renders no badge", func(t *testing.T) {
		if got := v.Badge(filepath.Join(t.TempDir(), "missing.json")); got != "" {
			t.Fatalf("Badge(absent) = %q, want empty", got)
		}
	})

	t.Run("malformed and hostile inputs render no badge", func(t *testing.T) {
		inputs := map[string][]byte{
			"empty":               {},
			"not json":            []byte("not json at all"),
			"json array":          []byte(`["license"]`),
			"null":                []byte("null"),
			"missing fields":      []byte(`{"version":1}`),
			"non utf8":            {0xff, 0xfe, 0xfd, 0x00},
			"truncated signature": append([]byte(nil), valid[:len(valid)-8]...),
			"oversized":           bytes.Repeat([]byte("A"), MaxTokenSize+1),
			"bad signature encoding": reencodeToken(t, valid, func(l *License) {
				l.Signature = "!!!not-base64!!!"
			}),
		}
		for name, raw := range inputs {
			path := writeLicense(t, t.TempDir(), raw)
			if got := v.Badge(path); got != "" {
				t.Errorf("%s: Badge() = %q, want empty", name, got)
			}
		}
	})

	t.Run("tampering leaves no badge", func(t *testing.T) {
		for name, mutate := range map[string]func([]byte) []byte{
			"payload byte": func(raw []byte) []byte {
				return bytes.Replace(raw, []byte("user@example.com"), []byte("evil@example.com"), 1)
			},
			"signature byte": func(raw []byte) []byte {
				tampered := append([]byte(nil), raw...)
				tampered[len(tampered)-3] ^= 0x01
				return tampered
			},
		} {
			raw := mutate(valid)
			if bytes.Equal(raw, valid) {
				t.Fatalf("%s: mutation was a no-op", name)
			}
			path := writeLicense(t, t.TempDir(), raw)
			if got := v.Badge(path); got != "" {
				t.Errorf("%s: Badge() = %q, want empty", name, got)
			}
		}
	})

	t.Run("wrong key renders no badge", func(t *testing.T) {
		path := writeLicense(t, t.TempDir(), signedToken(t, otherPriv, nil))
		if got := v.Badge(path); got != "" {
			t.Fatalf("Badge(wrong key) = %q, want empty", got)
		}
	})

	t.Run("unknown key id renders no badge", func(t *testing.T) {
		path := writeLicense(t, t.TempDir(), signedToken(t, priv, func(l *License) { l.KeyID = "rotated-away" }))
		if got := v.Badge(path); got != "" {
			t.Fatalf("Badge(unknown key) = %q, want empty", got)
		}
	})

	t.Run("expiry and grace", func(t *testing.T) {
		expires := refNow.Add(time.Hour)
		raw := signedToken(t, priv, func(l *License) { l.ExpiresAt = expires })

		inGrace := v
		inGrace.Now = func() time.Time { return expires.Add(GracePeriod - time.Minute) }
		if got := inGrace.Badge(writeLicense(t, t.TempDir(), raw)); got != Badge {
			t.Fatalf("Badge(within grace) = %q, want %q", got, Badge)
		}

		pastGrace := v
		pastGrace.Now = func() time.Time { return expires.Add(GracePeriod + time.Minute) }
		if got := pastGrace.Badge(writeLicense(t, t.TempDir(), raw)); got != "" {
			t.Fatalf("Badge(past grace) = %q, want empty", got)
		}
	})

	t.Run("clock rollback is tolerated", func(t *testing.T) {
		rolledBack := v
		rolledBack.Now = func() time.Time { return refNow.Add(-30 * 24 * time.Hour) }
		path := writeLicense(t, t.TempDir(), valid)
		if got := rolledBack.Badge(path); got != Badge {
			t.Fatalf("Badge(clock rollback) = %q, want %q", got, Badge)
		}
	})

	t.Run("expires before issue renders no badge", func(t *testing.T) {
		raw := signedToken(t, priv, func(l *License) {
			l.ExpiresAt = l.IssuedAt.Add(-time.Minute)
		})
		if got := v.Badge(writeLicense(t, t.TempDir(), raw)); got != "" {
			t.Fatalf("Badge(inverted expiry) = %q, want empty", got)
		}
	})

	t.Run("embedded key rejects foreign tokens", func(t *testing.T) {
		// The embedded verifier accepts only tokens signed by the key whose
		// public half is compiled in; a token signed by a test key must never
		// produce a badge, proving the default path cannot be spoofed by
		// generic tooling.
		path := writeLicense(t, t.TempDir(), valid)
		if got := BadgeForFile(path); got != "" {
			t.Fatalf("BadgeForFile(foreign token) = %q, want empty", got)
		}
		if len(embeddedPublicKey) != ed25519.PublicKeySize {
			t.Fatalf("embedded key length = %d, want %d", len(embeddedPublicKey), ed25519.PublicKeySize)
		}
	})
}

// TestParseErrorClassification pins the error taxonomy so callers can rely on
// errors.Is without matching strings.
func TestParseErrorClassification(t *testing.T) {
	v, priv := testVerifier(t)

	tooLarge := bytes.Repeat([]byte("A"), MaxTokenSize+1)
	if _, err := v.Parse(tooLarge); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized: err = %v, want ErrTooLarge", err)
	}
	if _, err := v.Parse([]byte("not json")); !errors.Is(err, ErrMalformed) {
		t.Errorf("malformed: err = %v, want ErrMalformed", err)
	}
	if _, err := v.Parse([]byte(`{"version":99}`)); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("version: err = %v, want ErrUnsupportedVersion", err)
	}
	if _, err := v.Parse(signedToken(t, priv, func(l *License) { l.KeyID = "nope" })); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown key: err = %v, want ErrUnknownKey", err)
	}
	tampered := signedToken(t, priv, nil)
	tampered[len(tampered)-3] ^= 0x01
	if _, err := v.Parse(tampered); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered: err = %v, want ErrBadSignature", err)
	}
	expired := v
	expired.Now = func() time.Time { return refNow.Add(10 * 365 * 24 * time.Hour) }
	if _, err := expired.Parse(signedToken(t, priv, nil)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: err = %v, want ErrExpired", err)
	}
}

// TestSigningInputCanonical pins the exact bytes an issuer must sign. A change
// here breaks the closed-source license service, so it is asserted verbatim.
func TestSigningInputCanonical(t *testing.T) {
	lic := License{
		Version:   Version,
		KeyID:     "prod-2026-09",
		LicenseID: "lic_example",
		Subject:   "user@example.com",
		Features:  []string{"team", "pro"},
		IssuedAt:  time.Unix(1789603200, 0).UTC(),
		ExpiresAt: time.Unix(1821139200, 0).UTC(),
	}
	want := "tokenhush-license-v1\n" +
		"key_id:prod-2026-09\n" +
		"license_id:lic_example\n" +
		"subject:user@example.com\n" +
		"features:pro,team\n" +
		"issued_at:1789603200\n" +
		"expires_at:1821139200\n"
	if got := string(SigningInput(lic)); got != want {
		t.Fatalf("SigningInput mismatch\n got: %q\nwant: %q", got, want)
	}

	lic.Features = []string{"pro", "team"}
	if got := string(SigningInput(lic)); got != want {
		t.Fatalf("feature order changed the signing input: %q", got)
	}
}

// TestNoCoreLicenseGate proves the licensing boundary structurally:
//
//  1. pkg/license imports only the standard library, and
//  2. no non-test Go file outside pkg/license and internal/cli imports it.
//
// Together these mean no core behavior can branch on license state: a valid
// token can only ever be rendered by the CLI badge.
func TestNoCoreLicenseGate(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	const importPath = "github.com/fregie/tokenhush/pkg/license"

	selfDir := filepath.Join("pkg", "license")
	allowedImporters := map[string]bool{
		filepath.Join("internal", "cli"): true,
	}

	importsOf := func(path string) ([]string, error) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		var imports []string
		for _, spec := range file.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, fmt.Errorf("unquote import in %s: %w", path, err)
			}
			imports = append(imports, p)
		}
		return imports, nil
	}

	var scanned int
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relDir := filepath.Dir(rel)
		scanned++

		imports, err := importsOf(path)
		if err != nil {
			return err
		}
		for _, imp := range imports {
			if relDir == selfDir {
				if first := strings.SplitN(imp, "/", 2)[0]; strings.Contains(first, ".") {
					t.Errorf("%s imports non-stdlib package %q: the parser must stay isolated", rel, imp)
				}
				continue
			}
			if imp == importPath && !allowedImporters[relDir] {
				t.Errorf("%s imports %q: licensing must not gate core behavior", rel, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if scanned == 0 {
		t.Fatal("no Go files scanned; the isolation check is vacuous")
	}

	// Guard against a vacuous import scan (typo in the path would silently
	// disable both checks above).
	var foundImporter bool
	err = filepath.WalkDir(filepath.Join(root, "internal", "cli"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		imports, err := importsOf(path)
		if err != nil {
			return err
		}
		for _, imp := range imports {
			if imp == importPath {
				foundImporter = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk cli: %v", err)
	}
	if !foundImporter {
		t.Fatalf("internal/cli does not import %q; the gate check is vacuous", importPath)
	}
}

// moduleRoot walks up from the test working directory until go.mod is found.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found in any parent directory")
		}
		dir = parent
	}
}

// TestEmbeddedKeyConstant locks the shared production key set: the embedded
// key_id and public bytes must equal this checked-in expectation. The literal
// is written independently of embeddedPublicKey so a placeholder regression or
// an accidental key swap fails here instead of shipping silently.
func TestEmbeddedKeyConstant(t *testing.T) {
	want := ed25519.PublicKey{
		0xc8, 0xc3, 0x60, 0x0c, 0x87, 0xe1, 0xb7, 0x29,
		0xe4, 0x6d, 0x0e, 0x33, 0x27, 0x34, 0x56, 0xfe,
		0x7e, 0x94, 0x8b, 0x64, 0x93, 0x02, 0x44, 0xa5,
		0xff, 0x5b, 0x95, 0x83, 0xbe, 0xd6, 0xca, 0x37,
	}
	keys := DefaultKeys()
	if len(keys) != 1 {
		t.Fatalf("DefaultKeys() has %d entries, want exactly 1", len(keys))
	}
	if got := keys[0].ID; got != "prod-2026-09" {
		t.Errorf("DefaultKeys()[0].ID = %q, want %q", got, "prod-2026-09")
	}
	if got := keys[0].Public; !got.Equal(want) {
		t.Errorf("DefaultKeys()[0].Public = %#v, want %#v", []byte(got), []byte(want))
	}
}
