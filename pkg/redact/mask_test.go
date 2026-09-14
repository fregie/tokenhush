package redact

import (
	"strings"
	"testing"
)

// TestMaskSecretNeverRevealsFull pins the security property the redaction log
// relies on: whatever the detector type or value shape, MaskSecret neither
// returns the value nor contains it as a substring.
func TestMaskSecretNeverRevealsFull(t *testing.T) {
	values := []string{
		"sk-proj-Te5tA1b2C3d4E5f6G7h8I9j0", // api_key (prefix detector shape)
		"AKIAIOSFODNN7EXAMPLE",
		"github_pat_11ABCDEFG0123456789abcdefghijklmnopqrstuvwxyz",
		"a3f9c1d2e4b5f60718293a4b5c6d7e8f",                         // high_entropy
		"user.name+tag@example.com",                                // email
		"4111111111111111",                                         // credit_card
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig", // jwt
		"-----BEGIN OPENSSH PRIVATE KEY-----",                      // private_key
		"****",                                                     // equals the no-reveal constant
		"[redacted]",                                               // equals the fallback constant
		"short",                                                    // below every reveal threshold
		"",                                                         // empty
	}
	types := []string{
		"api_key", "high_entropy", "email", "credit_card", "jwt", "private_key", "", "unknown",
	}

	for _, typ := range types {
		for _, value := range values {
			masked := MaskSecret(value, typ)
			if masked == value {
				t.Errorf("MaskSecret(%q, %q) returned the value itself", value, typ)
			}
			if value != "" && strings.Contains(masked, value) {
				t.Errorf("MaskSecret(%q, %q) = %q contains the value", value, typ, masked)
			}
		}
	}
}

// TestMaskSecretRevealClass pins the bounded edge reveal for opaque tokens.
func TestMaskSecretRevealClass(t *testing.T) {
	value := "sk-proj-Te5tA1b2C3d4E5f6G7h8I9j0" // 31 runes
	got := MaskSecret(value, "api_key")
	const want = "sk-p…j0"
	if got != want {
		t.Fatalf("MaskSecret(api_key) = %q, want %q", got, want)
	}
	if got := MaskSecret(value, "high_entropy"); got != want {
		t.Fatalf("MaskSecret(high_entropy) = %q, want %q", got, want)
	}
}

// TestMaskSecretNoRevealClass pins that structured and PII types reveal nothing.
func TestMaskSecretNoRevealClass(t *testing.T) {
	for _, typ := range []string{"email", "credit_card", "jwt", "private_key", "unknown", ""} {
		if got := MaskSecret("user.name@example.com", typ); got != maskFull {
			t.Errorf("MaskSecret(_, %q) = %q, want %q", typ, got, maskFull)
		}
	}
}

// TestMaskSecretLengthThreshold pins the reveal cutoff and the hidden-floor
// guard: a value must be long enough that the reveal cannot reconstruct it.
func TestMaskSecretLengthThreshold(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{n: 0, want: maskFull},
		{n: 15, want: maskFull}, // below maskMinLen
		{n: 16, want: "aaaa…aa"},
	}
	for _, tc := range cases {
		value := strings.Repeat("a", tc.n)
		if got := MaskSecret(value, "api_key"); got != tc.want {
			t.Errorf("MaskSecret(len=%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// TestMaskSecretRuneSafe checks a multi-byte value is masked on rune
// boundaries and still never leaks.
func TestMaskSecretRuneSafe(t *testing.T) {
	value := "密钥-秘密-abcdef-ABCDEF-123456" // multi-byte prefix, > 16 runes
	got := MaskSecret(value, "api_key")
	if strings.Contains(got, value) || got == value {
		t.Fatalf("multi-byte value leaked: %q", got)
	}
	for _, r := range got {
		if r == '\uFFFD' {
			t.Fatalf("masked form split a multi-byte rune: %q", got)
		}
	}
}
