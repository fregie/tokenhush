package filter

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// The six primitive rules are the bundled detector algorithms, reachable
// through their constructors and mapped onto the frozen detector ids, rule
// types and categories. Fixtures are hardcoded so no test file imports a
// decoder of its own.

const (
	jwtHeader  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"                                       // {"alg":"HS256","typ":"JWT"}
	jwtPayload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" // {"sub":...}, unpadded
	jwtSig     = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	jwtToken   = jwtHeader + "." + jwtPayload + "." + jwtSig

	jwtTypOnly   = "eyJ0eXAiOiJKV1QifQ"   // {"typ":"JWT"} - no alg member
	jwtPaddedAlg = "eyJhbGciOiJub25lIn0=" // {"alg":"none"} - padded, alg member
	jwtNotJSON   = "bm90anNvbg"           // "notjson"
	jwtHeaderSub = jwtPayload             // {"sub":...} is valid JSON without alg

	highEntropyRun = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0fI" // 32 distinct base64 chars
	hex16          = "0123456789abcdef"
	hex64          = hex16 + hex16 + hex16 + hex16 // uniform hex, entropy exactly 4.0
)

func pemBlock(kind string) string {
	return "-----BEGIN " + kind + "-----\nMIIEfake\n-----END " + kind + "-----"
}

type primitiveCase struct {
	name     string
	rule     Rule
	id       string
	typ      string
	category string
	bait     string
}

func primitiveCases() []primitiveCase {
	return []primitiveCase{
		{"prefix", NewPrefixRule(), DetectorPrefix, TypePrefix, CategoryAPIKey, "sk-" + strings.Repeat("A", 40)},
		{"email", NewEmailRule(), DetectorEmail, TypeEmail, CategoryEmail, "user@example.com"},
		{"luhn", NewLuhnRule(), DetectorLuhn, TypeLuhn, CategoryCreditCard, "4111111111111111"},
		{"jwt", NewJWTRule(), DetectorJWT, TypeJWT, CategoryJWT, jwtToken},
		{"pem", NewPEMRule(), DetectorPrivateKey, TypePEM, CategoryPrivateKey, pemBlock("RSA PRIVATE KEY")},
		{"entropy", NewEntropyRule(), DetectorHighEntropy, TypeEntropy, CategoryHighEntropy, highEntropyRun},
	}
}

// TestPrimitiveCategories pins every primitive rule's frozen detector id, rule
// type and category mapping.
func TestPrimitiveCategories(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range primitiveCases() {
		if tc.rule.ID() != tc.id {
			t.Errorf("%s: ID() = %q, want %q", tc.name, tc.rule.ID(), tc.id)
		}
		if tc.rule.Type() != tc.typ {
			t.Errorf("%s: Type() = %q, want %q", tc.name, tc.rule.Type(), tc.typ)
		}
		if tc.rule.Category() != tc.category {
			t.Errorf("%s: Category() = %q, want %q", tc.name, tc.rule.Category(), tc.category)
		}
		if tc.rule.Scope() != ScopeRequest || tc.rule.Action() != ActionRedact {
			t.Errorf("%s: built-ins must be request-phase redact rules, got scope %q action %q",
				tc.name, tc.rule.Scope(), tc.rule.Action())
		}
		seen[tc.id] = true
	}
	if len(seen) != 6 {
		t.Errorf("the six primitive detector ids must be distinct, got %v", seen)
	}
}

// TestPrimitivePrefix: provider key shapes match whole, and a prefix embedded
// in a longer token run never matches.
func TestPrimitivePrefix(t *testing.T) {
	rule := NewPrefixRule()
	keys := []string{
		"sk-" + strings.Repeat("A1b2", 8),
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_" + strings.Repeat("a", 36),
		"glpat-" + strings.Repeat("B", 24),
		"xoxb-" + strings.Repeat("C", 12),
		"xoxp-" + strings.Repeat("d", 12),
		"AIza" + strings.Repeat("E", 35),
		"npm_" + strings.Repeat("F", 40),
	}
	for _, key := range keys {
		input := "k=" + key + ";"
		got := rule.Inspect([]byte(input))
		want := Span{Start: 2, End: 2 + len(key)}
		if len(got) != 1 || got[0] != want {
			t.Errorf("key %.16q...: spans %v, want [%v]", key, got, want)
		}
	}
	negatives := map[string]string{
		"leading token byte":  "x" + "sk-" + strings.Repeat("A", 32),
		"trailing token byte": "AKIAIOSFODNN7EXAMPLE" + "z",
		"embedded run":        "abc" + "sk-" + strings.Repeat("A", 32) + "def",
		"too short":           "sk-" + strings.Repeat("A", 15),
		"not a provider":      "skey-" + strings.Repeat("A", 32),
	}
	for name, input := range negatives {
		if got := rule.Inspect([]byte(input)); len(got) != 0 {
			t.Errorf("%s: spans %v, want none", name, got)
		}
	}
}

// TestPrimitiveEmail: addresses match, dot-run and empty-part candidates are
// rejected.
func TestPrimitiveEmail(t *testing.T) {
	rule := NewEmailRule()
	addresses := []string{
		"user@example.com",
		"user.name+tag@example.co.uk",
		"a_b%c-d@sub.domain.example",
	}
	for _, addr := range addresses {
		input := "mail " + addr + " end"
		got := rule.Inspect([]byte(input))
		want := Span{Start: 5, End: 5 + len(addr)}
		if len(got) != 1 || got[0] != want {
			t.Errorf("address %q: spans %v, want [%v]", addr, got, want)
		}
	}
	negatives := []string{
		"a..b@example.com",
		"user@ex..ample.com",
		"a...b@example.com",
		"@example.com",
		"user@",
		"user@localhost",
		"user@example",
		"not an email",
	}
	for _, input := range negatives {
		if got := rule.Inspect([]byte(input)); len(got) != 0 {
			t.Errorf("%q: spans %v, want none", input, got)
		}
	}
}

// TestPrimitiveLuhn: 13..19 digit Luhn-valid runs match; bad checksums, all
// same-digit runs and out-of-bound lengths do not.
func TestPrimitiveLuhn(t *testing.T) {
	rule := NewLuhnRule()
	positives := []string{
		"4111111111111111",
		"5500005555555559",
		"4012888888881881",
		"378282246310005",
		"6011111111111117",
		"4111 1111 1111 1111",
	}
	for _, number := range positives {
		input := "card " + number + " end"
		got := rule.Inspect([]byte(input))
		want := Span{Start: 5, End: 5 + len(number)}
		if len(got) != 1 || got[0] != want {
			t.Errorf("number %q: spans %v, want [%v]", number, got, want)
		}
	}
	negatives := map[string]string{
		"luhn-invalid 16 digits": "1234567890123456",
		"all-same 16 digits":     "0000000000000000",
		"all-same 13 digits":     "1111111111111",
		"below the lower bound":  "411111111111",
		"above the upper bound":  "41111111111111111111",
		"too short":              "1234",
	}
	for name, number := range negatives {
		if got := rule.Inspect([]byte(number)); len(got) != 0 {
			t.Errorf("%s %q: spans %v, want none", name, number, got)
		}
	}
}

// TestPrimitiveJWT: exactly three base64url segments whose header decodes to
// JSON with an alg member.
func TestPrimitiveJWT(t *testing.T) {
	rule := NewJWTRule()
	positives := []string{
		jwtToken,
		jwtPaddedAlg + ".AAAA.c2ln",
	}
	for _, token := range positives {
		input := "Bearer " + token
		got := rule.Inspect([]byte(input))
		want := Span{Start: 7, End: 7 + len(token)}
		if len(got) != 1 || got[0] != want {
			t.Errorf("token %q: spans %v, want [%v]", token, got, want)
		}
	}
	negatives := map[string]string{
		"alg-less header":       jwtTypOnly + ".AAAA.c2ln",
		"two segments":          jwtHeader + "." + jwtSig,
		"four segments":         jwtToken + ".ZXh0cmE",
		"non-JSON header":       jwtNotJSON + ".AAAA.c2ln",
		"header without alg":    jwtHeaderSub + "." + jwtSig + "." + jwtSig,
		"header decodes to nil": "bnVsbA" + ".AAAA.c2ln",
	}
	for name, token := range negatives {
		if got := rule.Inspect([]byte(token)); len(got) != 0 {
			t.Errorf("%s %q: spans %v, want none", name, token, got)
		}
	}
}

// TestPrimitivePEM: a private-key header extends to its own END marker and
// never swallows an unrelated one; public-key headers never match.
func TestPrimitivePEM(t *testing.T) {
	rule := NewPEMRule()
	for _, kind := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
		block := pemBlock(kind)
		input := "before " + block + " after"
		got := rule.Inspect([]byte(input))
		want := Span{Start: 7, End: 7 + len(block)}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: spans %v, want [%v]", kind, got, want)
		}
	}
	header := "-----BEGIN RSA PRIVATE KEY-----"
	unrelated := header + "\nMIIEfake\n-----END OPENSSH PRIVATE KEY-----"
	got := rule.Inspect([]byte(unrelated))
	if len(got) != 1 {
		t.Fatalf("mismatched END: spans %v, want the header span only", got)
	}
	if got[0] != (Span{Start: 0, End: len(header)}) {
		t.Errorf("mismatched END: span %v must stop at the header (%d), not swallow the unrelated END", got[0], len(header))
	}
	public := "-----BEGIN PUBLIC KEY-----\nMIIEfake\n-----END PUBLIC KEY-----"
	if spans := rule.Inspect([]byte(public)); len(spans) != 0 {
		t.Errorf("PUBLIC KEY must never match: spans %v", spans)
	}
}

// TestPrimitiveEntropy: a long high-entropy base64-alphabet run matches; pure
// hex runs, short runs and runs split by non-alphabet bytes do not.
func TestPrimitiveEntropy(t *testing.T) {
	rule := NewEntropyRule()
	run := highEntropyRun
	input := "token " + run + " end"
	got := rule.Inspect([]byte(input))
	want := Span{Start: 6, End: 6 + len(run)}
	if len(got) != 1 || got[0] != want {
		t.Errorf("run: spans %v, want [%v]", got, want)
	}
	negatives := map[string]string{
		"16 hex chars":        "id " + hex16 + " end",
		"uniform 64 hex run":  "sha " + hex64 + " end",
		"27 chars, below min": "tok " + run[:27] + " end",
		"split by a comma":    "a " + run[:8] + "," + run[8:16] + "," + run[16:24] + " end",
		"low entropy run":     "x " + strings.Repeat("a", 40) + " end",
	}
	for name, candidate := range negatives {
		if spans := rule.Inspect([]byte(candidate)); len(spans) != 0 {
			t.Errorf("%s: spans %v, want none", name, spans)
		}
	}
	// The 28-char boundary is the documented default min_length.
	if spans := rule.Inspect([]byte("tok " + run[:28] + " end")); len(spans) != 1 {
		t.Errorf("28-char run: spans %v, want exactly one", spans)
	}
}

// TestPrimitiveBudget pins the documented per-call byte budget: a match ending
// exactly at the budget is still found, and everything at or past the budget is
// never inspected.
func TestPrimitiveBudget(t *testing.T) {
	const wantBudget = 1 << 20
	if PrimitiveByteBudgetBytes != wantBudget {
		t.Fatalf("PrimitiveByteBudgetBytes = %d, want the documented %d", PrimitiveByteBudgetBytes, wantBudget)
	}
	filler := bytes.Repeat([]byte{'\n'}, wantBudget)
	for _, tc := range primitiveCases() {
		t.Run(tc.name, func(t *testing.T) {
			inside := append(append([]byte{}, filler[:wantBudget-len(tc.bait)]...), tc.bait...)
			spans := tc.rule.Inspect(inside)
			if len(spans) != 1 {
				t.Fatalf("a bait ending exactly at the budget must match once, got %v", spans)
			}
			want := Span{Start: wantBudget - len(tc.bait), End: wantBudget}
			if spans[0] != want {
				t.Fatalf("span %v, want %v", spans[0], want)
			}
			beyond := append(append([]byte{}, filler...), tc.bait...)
			for _, span := range tc.rule.Inspect(beyond) {
				t.Fatalf("byte budget %d must truncate the scan, got span %v", wantBudget, span)
			}
		})
	}
}

// TestPrimitiveDeterminism: the same input yields identical spans on every call.
func TestPrimitiveDeterminism(t *testing.T) {
	for _, tc := range primitiveCases() {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("head " + tc.bait + " tail")
			first := tc.rule.Inspect(input)
			if len(first) == 0 {
				t.Fatalf("fixture %q must match", tc.bait)
			}
			for i := 0; i < 3; i++ {
				if got := tc.rule.Inspect(input); !reflect.DeepEqual(got, first) {
					t.Fatalf("call %d returned %v, want %v", i, got, first)
				}
			}
		})
	}
}

func benchmarkPrimitive(b *testing.B, rule Rule, input []byte) {
	b.Helper()
	b.SetBytes(int64(len(input)))
	for i := 0; i < b.N; i++ {
		if spans := rule.Inspect(input); len(spans) == 0 {
			b.Fatal("benchmark input must match")
		}
	}
}

func BenchmarkPrimitivePrefix(b *testing.B) {
	benchmarkPrimitive(b, NewPrefixRule(), []byte("key=sk-"+strings.Repeat("A1b2", 8)+";"))
}

func BenchmarkPrimitiveEmail(b *testing.B) {
	benchmarkPrimitive(b, NewEmailRule(), []byte("mail user.name+tag@example.co.uk end"))
}

func BenchmarkPrimitiveLuhn(b *testing.B) {
	benchmarkPrimitive(b, NewLuhnRule(), []byte("card 4111 1111 1111 1111 end"))
}

func BenchmarkPrimitiveJWT(b *testing.B) {
	benchmarkPrimitive(b, NewJWTRule(), []byte("Bearer "+jwtToken))
}

func BenchmarkPrimitivePEM(b *testing.B) {
	benchmarkPrimitive(b, NewPEMRule(), []byte("before "+pemBlock("RSA PRIVATE KEY")+" after"))
}

func BenchmarkPrimitiveEntropy(b *testing.B) {
	benchmarkPrimitive(b, NewEntropyRule(), []byte("token "+highEntropyRun+" end"))
}
