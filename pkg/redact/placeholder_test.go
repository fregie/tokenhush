package redact

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// placeholderGrammar mirrors the token shape allowlisted in the repo's
// .gitleaks.toml; every token the engine emits must match it.
var placeholderGrammar = regexp.MustCompile(`^__PII_[a-z][a-z0-9_]*_[0-9a-f]{8,}__$`)

// mustEngine returns a fresh engine or fails the test.
func mustEngine(t *testing.T) *PlaceholderEngine {
	t.Helper()
	e, err := NewPlaceholderEngine()
	if err != nil {
		t.Fatalf("NewPlaceholderEngine() error = %v", err)
	}
	return e
}

// digestOfToken extracts the hex digest from a token, for length assertions.
func digestOfToken(t *testing.T, token string) string {
	t.Helper()
	s := strings.TrimPrefix(token, placeholderOpen)
	s = strings.TrimSuffix(s, placeholderClose)
	i := strings.LastIndexByte(s, '_')
	if i < 0 {
		t.Fatalf("token %q has no digest separator", token)
	}
	return s[i+1:]
}

// TestPlaceholderDeterminism locks the core mapping contract: within one
// session the same (secret,type) always yields the same placeholder, distinct
// secrets and distinct types differ, the digest clears the 48-bit floor, and
// arbitrary finding types are sanitised into the placeholder grammar.
func TestPlaceholderDeterminism(t *testing.T) {
	e := mustEngine(t)
	const secret = "canary-alpha"
	const typ = "api_key"

	first := e.Placeholder(secret, typ)
	second := e.Placeholder(secret, typ)
	if first != second {
		t.Fatalf("same (secret,type) gave %q then %q", first, second)
	}
	if !placeholderGrammar.MatchString(first) {
		t.Fatalf("placeholder %q does not match %q", first, placeholderGrammar)
	}
	if got := digestOfToken(t, first); len(got) < placeholderMinDigestHex {
		t.Fatalf("digest %q = %d hex, want >= %d", got, len(got), placeholderMinDigestHex)
	}
	if got, ok := e.Secret(first); !ok || got != secret {
		t.Fatalf("Secret(%q) = (%q,%v), want (%q,true)", first, got, ok, secret)
	}

	if other := e.Placeholder("canary-beta", typ); other == first {
		t.Fatalf("distinct secrets shared placeholder %q", first)
	}
	if other := e.Placeholder(secret, "email"); other == first {
		t.Fatalf("same secret under a distinct type shared placeholder %q", first)
	}

	// Type sanitisation: mixed case, spaces and punctuation fold into
	// [a-z][a-z0-9_]* while staying deterministic ("API Key!" -> "api_key_").
	sanitized := e.Placeholder(secret, "API Key!")
	if !strings.Contains(sanitized, "_api_key_") {
		t.Fatalf("sanitised type missing from %q", sanitized)
	}
	if !placeholderGrammar.MatchString(sanitized) {
		t.Fatalf("sanitised placeholder %q does not match grammar", sanitized)
	}
	if again := e.Placeholder(secret, "API Key!"); again != sanitized {
		t.Fatalf("same raw type diverged: %q vs %q", sanitized, again)
	}
}

// TestPlaceholderMalformedInput probes the adversarial classes: empty secret,
// empty/oversized/invalid type, and placeholder-shaped non-tokens must never
// panic, must stay inside the grammar, and must round-trip exactly.
func TestPlaceholderMalformedInput(t *testing.T) {
	e := mustEngine(t)
	cases := []struct {
		name         string
		secret, kind string
	}{
		{"empty_secret", "", "email"},
		{"empty_type", "value-one", ""},
		{"invalid_utf8_type", "value-two", string([]byte{0xff, 0xfe, 0x80})},
		{"oversized_type", "value-three", strings.Repeat("A", 5000)},
		{"leading_digit_type", "value-four", "123"},
		{"punctuation_type", "value-five", "api key!/v2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := e.Placeholder(tc.secret, tc.kind)
			if !placeholderGrammar.MatchString(p) {
				t.Fatalf("token %q does not match grammar", p)
			}
			if len(p) > e.MaxPlaceholderLen() {
				t.Fatalf("token len %d > MaxPlaceholderLen %d", len(p), e.MaxPlaceholderLen())
			}
			if got, ok := e.Secret(p); !ok || got != tc.secret {
				t.Fatalf("round trip Secret(%q) = (%q,%v), want (%q,true)", p, got, ok, tc.secret)
			}
		})
	}

	for _, s := range []string{
		"",
		"plain text",
		placeholderOpen,
		"__PII_email_",
		"__PII_email_zzzz__",
		"__PII__",
		"__PII_email_0123456789ab__",
		"__PII_email_0123456789ab__x",
	} {
		if got, ok := e.Secret(s); ok {
			t.Errorf("Secret(%q) = (%q,true), want unknown", s, got)
		}
	}
}

// TestPlaceholderCollisionLengthens proves a digest collision lengthens the
// token instead of silently overwriting the earlier secret. A real 48-bit
// HMAC collision is not brute-forceable inside a unit test, so the candidate
// the second secret would compute is planted against the first secret and the
// engine must grow past it.
func TestPlaceholderCollisionLengthens(t *testing.T) {
	e := mustEngine(t)
	const kind = "email"
	const secretA = "collide-alpha"
	const secretB = "collide-beta"

	pA := e.Placeholder(secretA, kind)

	e.mu.Lock()
	shortB := e.candidate(sanitizePlaceholderType(kind), secretB, placeholderMinDigestHex)
	e.byPlaceholder[shortB] = secretA
	e.mu.Unlock()

	pB := e.Placeholder(secretB, kind)
	if pB == shortB {
		t.Fatalf("collision reused %q instead of lengthening", shortB)
	}
	if got := digestOfToken(t, pB); len(got) <= placeholderMinDigestHex {
		t.Fatalf("digest %q = %d hex, want longer than %d", got, len(got), placeholderMinDigestHex)
	}
	if got, ok := e.Secret(pB); !ok || got != secretB {
		t.Fatalf("Secret(%q) = (%q,%v), want B", pB, got, ok)
	}
	if got, ok := e.Secret(shortB); !ok || got != secretA {
		t.Fatalf("planted token now maps to (%q,%v), want A", got, ok)
	}
	if got := digestOfToken(t, pA); len(got) != placeholderMinDigestHex {
		t.Fatalf("A digest %q = %d hex, want %d (unchanged)", got, len(got), placeholderMinDigestHex)
	}
}

// TestPlaceholderSessionIsolation locks the session-scoped lifetime: a fresh
// engine has an independent salt and cannot resolve the previous session's
// placeholders, so a restart degrades to the client seeing the token verbatim.
func TestPlaceholderSessionIsolation(t *testing.T) {
	e1 := mustEngine(t)
	e2 := mustEngine(t)
	const secret = "session-alpha"
	const kind = "api_key"

	p1 := e1.Placeholder(secret, kind)
	p2 := e2.Placeholder(secret, kind)
	if p1 == p2 {
		t.Fatalf("two sessions shared placeholder %q (salt is not per-session)", p1)
	}
	if got, ok := e2.Secret(p1); ok {
		t.Fatalf("engine 2 resolved engine 1's placeholder to %q", got)
	}
	if got, ok := e1.Secret(p1); !ok || got != secret {
		t.Fatalf("engine 1 lost its own mapping: (%q,%v)", got, ok)
	}
}

// TestPlaceholderConcurrent exercises the mutex; run with -race.
func TestPlaceholderConcurrent(t *testing.T) {
	e := mustEngine(t)
	secrets := make([]string, 64)
	for i := range secrets {
		secrets[i] = fmt.Sprintf("concurrent-%d", i)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for _, s := range secrets {
				p := e.Placeholder(s, "email")
				if got, ok := e.Secret(p); !ok || got != s {
					t.Errorf("Secret(%q) = (%q,%v), want (%q,true)", p, got, ok, s)
				}
			}
		})
	}
	wg.Wait()
}

// TestApplyPlaceholders locks the outbound forward substitution: spans become
// placeholders, overlapping spans merge into their union, invalid spans are
// ignored, and an empty redaction set is a byte-for-byte no-op.
func TestApplyPlaceholders(t *testing.T) {
	e := mustEngine(t)
	const kind = "api_key"
	content := []byte("key=AAA111 BBB222 end")

	t.Run("distinct_spans", func(t *testing.T) {
		out := e.ApplyPlaceholders(content, []Redaction{
			{Start: 4, End: 10, Type: kind},
			{Start: 11, End: 17, Type: kind},
		})
		want := []byte("key=" + e.Placeholder("AAA111", kind) + " " + e.Placeholder("BBB222", kind) + " end")
		if !bytes.Equal(out, want) {
			t.Fatalf("got %q, want %q", out, want)
		}
		if bytes.Contains(out, []byte("AAA111")) || bytes.Contains(out, []byte("BBB222")) {
			t.Fatalf("outbound left an original span in %q", out)
		}
	})

	t.Run("overlap_merges_to_union", func(t *testing.T) {
		out := e.ApplyPlaceholders([]byte("abcdefghij"), []Redaction{
			{Start: 0, End: 5, Type: "first"},
			{Start: 3, End: 8, Type: "second"},
		})
		want := []byte(e.Placeholder("abcdefgh", "first") + "ij")
		if !bytes.Equal(out, want) {
			t.Fatalf("got %q, want %q", out, want)
		}
	})

	t.Run("adjacent_spans_stay_separate", func(t *testing.T) {
		out := e.ApplyPlaceholders([]byte("abcdef"), []Redaction{
			{Start: 0, End: 3, Type: "a"},
			{Start: 3, End: 6, Type: "b"},
		})
		want := []byte(e.Placeholder("abc", "a") + e.Placeholder("def", "b"))
		if !bytes.Equal(out, want) {
			t.Fatalf("got %q, want %q", out, want)
		}
	})

	t.Run("invalid_spans_ignored", func(t *testing.T) {
		out := e.ApplyPlaceholders([]byte("abcdef"), []Redaction{
			{Start: -1, End: 3, Type: "x"},
			{Start: 4, End: 4, Type: "x"},
			{Start: 5, End: 2, Type: "x"},
			{Start: 3, End: 99, Type: "x"},
		})
		if !bytes.Equal(out, []byte("abcdef")) {
			t.Fatalf("invalid spans changed content: %q", out)
		}
	})

	t.Run("empty_redactions_noop", func(t *testing.T) {
		if out := e.ApplyPlaceholders(content, nil); !bytes.Equal(out, content) {
			t.Fatalf("nil redactions changed content: %q", out)
		}
	})
}
