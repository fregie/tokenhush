package redact

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// parsePlaceholder splits a placeholder into its type and digest segments, and
// fails the test when the frozen grammar is violated.
func parsePlaceholder(t *testing.T, p string) (typ, digest string) {
	t.Helper()
	if !strings.HasPrefix(p, placeholderPrefix) || !strings.HasSuffix(p, placeholderSuffix) {
		t.Fatalf("placeholder %q lacks the frozen affixes", p)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(p, placeholderPrefix), placeholderSuffix)
	i := strings.LastIndex(inner, placeholderSep)
	if i < 0 {
		t.Fatalf("placeholder %q has no type/digest separator", p)
	}
	return inner[:i], inner[i+1:]
}

// assertHexDigest fails the test unless digest is a hex string of a ladder
// length.
func assertHexDigest(t *testing.T, p, digest string) {
	t.Helper()
	onLadder := false
	for _, n := range digestLadder {
		if len(digest) == n {
			onLadder = true
		}
	}
	if !onLadder {
		t.Fatalf("placeholder %q has digest length %d, want one of %v", p, len(digest), digestLadder)
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("placeholder %q has non-hex digest character %q", p, c)
		}
	}
}

// mustPlaceholder mints a placeholder and fails on error.
func mustPlaceholder(t *testing.T, e *engine, secret, kind string) string {
	t.Helper()
	p, err := e.placeholder([]byte(secret), kind)
	if err != nil {
		t.Fatalf("placeholder(%q, %q): %v", secret, kind, err)
	}
	return p
}

// TestPlaceholderDeterministic: the same (type, secret) keeps yielding the same
// placeholder for the engine's lifetime, and the first one starts at the
// shortest digest.
func TestPlaceholderDeterministic(t *testing.T) {
	e := newEngine()
	first := mustPlaceholder(t, e, "alice@example.com", "email")
	typ, digest := parsePlaceholder(t, first)
	if typ != "email" {
		t.Errorf("type = %q, want %q", typ, "email")
	}
	if len(digest) != minDigestLen {
		t.Errorf("first digest length = %d, want %d", len(digest), minDigestLen)
	}
	assertHexDigest(t, first, digest)

	for i := 0; i < 16; i++ {
		if got := mustPlaceholder(t, e, "alice@example.com", "email"); got != first {
			t.Fatalf("call %d = %q, want the cached %q", i, got, first)
		}
	}
}

// TestPlaceholderDistinctSecretsUnique: every distinct secret within one engine
// gets its own placeholder.
func TestPlaceholderDistinctSecretsUnique(t *testing.T) {
	e := newEngine()
	seen := map[string]string{}
	for i := 0; i < 2000; i++ {
		secret := fmt.Sprintf("secret-value-%d", i)
		p := mustPlaceholder(t, e, secret, "token")
		typ, digest := parsePlaceholder(t, p)
		if typ != "token" {
			t.Fatalf("secret %q: type = %q, want token", secret, typ)
		}
		assertHexDigest(t, p, digest)
		if other, dup := seen[p]; dup {
			t.Fatalf("placeholder %q shared by %q and %q", p, other, secret)
		}
		seen[p] = secret
	}
}

// TestPlaceholderSaltIsolation: engines seed independent random salts that stay
// in memory, and uniqueness holds per engine.
func TestPlaceholderSaltIsolation(t *testing.T) {
	a, b := newEngine(), newEngine()
	if len(a.salt) != saltLen || len(b.salt) != saltLen {
		t.Fatalf("salt lengths = %d, %d, want %d", len(a.salt), len(b.salt), saltLen)
	}
	if bytes.Equal(a.salt, b.salt) {
		t.Fatal("two engines share a salt, want independent random salts")
	}
	if bytes.Equal(a.salt, make([]byte, saltLen)) {
		t.Fatal("salt is all zeroes: crypto/rand did not seed the engine")
	}

	for _, e := range []*engine{a, b} {
		seen := map[string]bool{}
		for i := 0; i < 256; i++ {
			p := mustPlaceholder(t, e, fmt.Sprintf("s-%d", i), "kind")
			if seen[p] {
				t.Fatalf("placeholder %q repeated within one engine", p)
			}
			seen[p] = true
		}
	}
}

// TestPlaceholderTypeSanitization: the <type> segment keeps only [a-z0-9],
// replaces everything else with '_', and is capped.
func TestPlaceholderTypeSanitization(t *testing.T) {
	e := newEngine()

	typ, _ := parsePlaceholder(t, mustPlaceholder(t, e, "x", "Email Address!"))
	if want := "_mail__ddress_"; typ != want {
		t.Errorf("sanitized type = %q, want %q", typ, want)
	}

	typ, _ = parsePlaceholder(t, mustPlaceholder(t, e, "y", strings.Repeat("a-b", 10)))
	if want := "a_ba_ba_ba_ba_ba"; typ != want {
		t.Errorf("capped type = %q, want %q", typ, want)
	}
	if len(typ) != maxTypeLen {
		t.Errorf("capped type length = %d, want %d", len(typ), maxTypeLen)
	}

	typ, _ = parsePlaceholder(t, mustPlaceholder(t, e, "z", ""))
	if want := "unknown"; typ != want {
		t.Errorf("empty-kind type = %q, want %q", typ, want)
	}

	for _, kind := range []string{"Email Address!", strings.Repeat("A-Z", 20), "", "..."} {
		typ, _ := parsePlaceholder(t, mustPlaceholder(t, e, "s", kind))
		if len(typ) == 0 || len(typ) > maxTypeLen {
			t.Errorf("kind %q: type length = %d, want 1..%d", kind, len(typ), maxTypeLen)
		}
		for i := 0; i < len(typ); i++ {
			c := typ[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
			if !ok {
				t.Errorf("kind %q: type %q contains forbidden byte %q", kind, typ, c)
			}
		}
	}
}

// TestPlaceholderCollisionGrowth injects a digest that always returns the same
// bytes: the engine must grow the digest instead of reusing a placeholder.
func TestPlaceholderCollisionGrowth(t *testing.T) {
	alwaysSame := func(salt, kind string, secret []byte) []byte {
		return bytes.Repeat([]byte{0xab}, 32)
	}
	e := newEngine(withDigest(alwaysSame))

	p1 := mustPlaceholder(t, e, "secret-1", "k")
	p2 := mustPlaceholder(t, e, "secret-2", "k")
	p3 := mustPlaceholder(t, e, "secret-3", "k")
	if p1 == p2 || p1 == p3 || p2 == p3 {
		t.Fatalf("colliding digest reused a placeholder: %q %q %q", p1, p2, p3)
	}

	var lengths []int
	for _, p := range []string{p1, p2, p3} {
		_, digest := parsePlaceholder(t, p)
		assertHexDigest(t, p, digest)
		lengths = append(lengths, len(digest))
	}
	want := []int{minDigestLen, 16, 24}
	for i := range want {
		if lengths[i] != want[i] {
			t.Errorf("digest lengths = %v, want %v (growth instead of reuse)", lengths, want)
			break
		}
	}

	if again := mustPlaceholder(t, e, "secret-1", "k"); again != p1 {
		t.Errorf("cached lookup = %q, want %q", again, p1)
	}

	exhausted := newEngine(withDigest(alwaysSame))
	var last string
	for i := 0; i < len(digestLadder); i++ {
		last = mustPlaceholder(t, exhausted, fmt.Sprintf("s-%d", i), "k")
	}
	if _, digest := parsePlaceholder(t, last); len(digest) != maxDigestLen {
		t.Errorf("last ladder digest = %d chars, want %d", len(digest), maxDigestLen)
	}
	if _, err := exhausted.placeholder([]byte("one-too-many"), "k"); !errors.Is(err, errDigestExhausted) {
		t.Fatalf("error after ladder exhaustion = %v, want errDigestExhausted", err)
	}
}

// TestMaxPlaceholderLenBound: the reported bound is exactly the maximum length
// the engine can produce, and no placeholder ever exceeds it.
func TestMaxPlaceholderLenBound(t *testing.T) {
	if want := len(placeholderPrefix) + maxTypeLen + 1 + maxDigestLen + len(placeholderSuffix); maxPlaceholderLen != want {
		t.Fatalf("maxPlaceholderLen = %d, want %d", maxPlaceholderLen, want)
	}
	if want := 89; maxPlaceholderLen != want {
		t.Fatalf("maxPlaceholderLen = %d, want the frozen grammar's %d", maxPlaceholderLen, want)
	}

	alwaysSame := func(salt, kind string, secret []byte) []byte {
		return bytes.Repeat([]byte{0xcd}, 32)
	}
	e := newEngine(withDigest(alwaysSame))
	longKind := strings.Repeat("z", 100)

	maxSeen := 0
	for i := 0; i < len(digestLadder); i++ {
		p := mustPlaceholder(t, e, fmt.Sprintf("s-%d", i), longKind)
		if len(p) > maxSeen {
			maxSeen = len(p)
		}
		if len(p) > maxPlaceholderLen {
			t.Fatalf("placeholder %q has length %d > maxPlaceholderLen %d", p, len(p), maxPlaceholderLen)
		}
	}
	if maxSeen != maxPlaceholderLen {
		t.Fatalf("maximum produced length = %d, but maxPlaceholderLen reports %d", maxSeen, maxPlaceholderLen)
	}
}
