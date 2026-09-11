package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/license"
)

const proBadgeTestKeyID = "cli-test-key"

// licenseBadgeToken builds a signed token for the CLI badge tests.
func licenseBadgeToken(t *testing.T, priv ed25519.PrivateKey, keyID string, issued, expires time.Time) []byte {
	t.Helper()
	lic := license.License{
		Version:   license.Version,
		KeyID:     keyID,
		LicenseID: "lic_cli_0001",
		Subject:   "user@example.com",
		Features:  []string{"pro"},
		IssuedAt:  issued,
		ExpiresAt: expires,
	}
	lic.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, license.SigningInput(lic)))
	raw, err := json.Marshal(lic)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	return raw
}

// TestStatusProBadge drives `tokenhush status` end to end through Run with an
// injected verifier and a temp TOKENHUSH_HOME. A valid token must render the
// read-only badge (and nothing else); every rejected token must render
// nothing and leak no rejection cause.
func TestStatusProBadge(t *testing.T) {
	issued := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	validUntil := issued.Add(24 * time.Hour)
	now := issued.Add(time.Hour)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	installVerifier := func(t *testing.T, when time.Time) {
		t.Helper()
		previous := licenseVerifier
		licenseVerifier = license.Verifier{
			Keys: []license.Key{{ID: proBadgeTestKeyID, Public: pub}},
			Now:  func() time.Time { return when },
		}
		t.Cleanup(func() { licenseVerifier = previous })
	}

	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	licensePath := filepath.Join(home, license.FileName)

	writeLicense := func(t *testing.T, raw []byte) {
		t.Helper()
		if err := os.WriteFile(licensePath, raw, 0o600); err != nil {
			t.Fatalf("write license: %v", err)
		}
	}
	status := func(t *testing.T) (stdout, stderr string, code int) {
		t.Helper()
		var out, errOut bytes.Buffer
		code = Run([]string{"status"}, &out, &errOut)
		return out.String(), errOut.String(), code
	}

	valid := licenseBadgeToken(t, priv, proBadgeTestKeyID, issued, validUntil)

	t.Run("valid license renders the badge and unlocks nothing", func(t *testing.T) {
		installVerifier(t, now)
		writeLicense(t, valid)
		stdout, stderr, code := status(t)
		if !strings.Contains(stdout, license.Badge) {
			t.Fatalf("stdout = %q, want it to contain %q", stdout, license.Badge)
		}
		if strings.Contains(stderr, license.Badge) {
			t.Fatalf("stderr = %q, want no badge there", stderr)
		}
		// The badge is display-only: status stays the pre-W6.3 stub, so a
		// valid license changes no command behavior beyond the badge line.
		if !strings.Contains(stderr, "not implemented") || code != ExitUsage {
			t.Fatalf("valid license changed the stub contract: code=%d stderr=%q", code, stderr)
		}
	})

	t.Run("tampered license renders no badge and leaks no cause", func(t *testing.T) {
		installVerifier(t, now)
		tampered := bytes.Replace(valid, []byte("user@example.com"), []byte("evil@example.com"), 1)
		if bytes.Equal(tampered, valid) {
			t.Fatal("tamper helper was a no-op")
		}
		writeLicense(t, tampered)
		stdout, stderr, _ := status(t)
		combined := stdout + stderr
		if strings.Contains(combined, license.Badge) {
			t.Fatalf("tampered license produced the badge: stdout=%q stderr=%q", stdout, stderr)
		}
		for _, leak := range []string{"signature", "malformed", "tamper", "expired", "reject"} {
			if strings.Contains(strings.ToLower(combined), leak) {
				t.Fatalf("stderr leaks rejection cause %q: %q", leak, stderr)
			}
		}
	})

	t.Run("absent license renders no badge", func(t *testing.T) {
		installVerifier(t, now)
		if err := os.Remove(licensePath); err != nil {
			t.Fatalf("remove license: %v", err)
		}
		stdout, _, _ := status(t)
		if strings.Contains(stdout, license.Badge) {
			t.Fatalf("absent license produced the badge: %q", stdout)
		}
	})

	t.Run("wrong key renders no badge", func(t *testing.T) {
		installVerifier(t, now)
		writeLicense(t, licenseBadgeToken(t, otherPriv, proBadgeTestKeyID, issued, validUntil))
		stdout, _, _ := status(t)
		if strings.Contains(stdout, license.Badge) {
			t.Fatalf("wrong key produced the badge: %q", stdout)
		}
	})

	t.Run("expired beyond grace renders no badge", func(t *testing.T) {
		installVerifier(t, validUntil.Add(license.GracePeriod+time.Hour))
		writeLicense(t, valid)
		stdout, _, _ := status(t)
		if strings.Contains(stdout, license.Badge) {
			t.Fatalf("expired license produced the badge: %q", stdout)
		}
	})
}
