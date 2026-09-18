package filter

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestDomainHasSuffix pins the label-boundary contract of domainHasSuffix:
// the domain is lowercased, a canonical dot-prefixed suffix matches both the
// bare label sequence (domain == suffix[1:]) and every deeper subdomain
// (strings.HasSuffix at a label boundary), and a look-alike that only shares
// a byte tail is not a match. Every failure row fixes one adversarial shape:
// an unrelated domain, a reserved TLD, a deeper suffix, an empty suffix set,
// the empty domain, and dot-only or empty suffixes. The final happy row is
// deliberately an unnormalized input: a suffix without its canonical leading
// dot falls through to the raw byte-suffix arm, which is the frozen predicate
// and never occurs in production because effectiveEmailSuffixes normalizes
// every declared entry.
func TestDomainHasSuffix(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		suffixes []string
		want     bool
	}{
		{
			name:     "bare label sequence matches its canonical suffix",
			domain:   "co.uk",
			suffixes: []string{".co.uk"},
			want:     true,
		},
		{
			name:     "deep subdomain matches a compound suffix",
			domain:   "a.b.co.uk",
			suffixes: []string{".co.uk"},
			want:     true,
		},
		{
			name:     "bare corporate domain matches its declared suffix",
			domain:   "corp.com",
			suffixes: []string{".corp.com"},
			want:     true,
		},
		{
			name:     "subdomain matches the declared corporate suffix",
			domain:   "a.corp.com",
			suffixes: []string{".corp.com"},
			want:     true,
		},
		{
			name:     "one match among many suffixes wins",
			domain:   "a.co.uk",
			suffixes: []string{".com", ".co.uk", ".corp.com"},
			want:     true,
		},
		{
			name:     "a case-mixed domain is lowered before comparing",
			domain:   "A.B.Co.UK",
			suffixes: []string{".co.uk"},
			want:     true,
		},
		{
			name:     "a shared byte tail is not a label-boundary match",
			domain:   "evilcorp.com",
			suffixes: []string{".corp.com"},
			want:     false,
		},
		{
			name:     "a reserved TLD is not a built-in suffix",
			domain:   "example.invalid",
			suffixes: []string{".com"},
			want:     false,
		},
		{
			name:     "a bare domain does not match a deeper suffix",
			domain:   "corp.com",
			suffixes: []string{".a.corp.com"},
			want:     false,
		},
		{
			name:     "a nil suffix set matches nothing",
			domain:   "example.com",
			suffixes: nil,
			want:     false,
		},
		{
			name:     "an explicitly empty suffix set matches nothing",
			domain:   "example.com",
			suffixes: []string{},
			want:     false,
		},
		{
			name:     "the empty domain matches nothing",
			domain:   "",
			suffixes: []string{".com"},
			want:     false,
		},
		{
			name:     "a dot-only suffix is inert",
			domain:   "example.com",
			suffixes: []string{"."},
			want:     false,
		},
		{
			name:     "an empty suffix is inert rather than a panic",
			domain:   "example.com",
			suffixes: []string{""},
			want:     false,
		},
		{
			name:     "an unnormalized suffix without a leading dot is a raw byte-suffix match",
			domain:   "evilcorp.com",
			suffixes: []string{"corp.com"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domainHasSuffix(tt.domain, tt.suffixes); got != tt.want {
				t.Errorf("domainHasSuffix(%q, %v) = %v, want %v", tt.domain, tt.suffixes, got, tt.want)
			}
		})
	}
}

// TestEffectiveEmailSuffixes pins the single-owner union contract: the default
// mode returns a COPY of the built-in table unioned with the normalized
// declared suffixes, Replace returns the normalized declared suffixes only, a
// malformed declared entry is rejected with the normalizeEmailSuffix sentinel
// (never the other one), and neither mode ever mutates the package table. The
// copy check compares BuiltinEmailSuffixes() before and after both modes,
// because append(builtinEmailSuffixes, ...) would write into the package
// slice's spare capacity.
func TestEffectiveEmailSuffixes(t *testing.T) {
	t.Run("nil options yields a copy of the built-in set", func(t *testing.T) {
		got, err := effectiveEmailSuffixes(nil)
		if err != nil {
			t.Fatalf("effectiveEmailSuffixes(nil): %v", err)
		}
		if !slices.Equal(got, builtinEmailSuffixes) {
			t.Errorf("effectiveEmailSuffixes(nil) = %v, want the built-in set %v", got, builtinEmailSuffixes)
		}
		original := got[0]
		got[0] = ".mutated"
		if builtinEmailSuffixes[0] != original {
			t.Errorf("builtinEmailSuffixes[0] = %q after mutating the result, want %q", builtinEmailSuffixes[0], original)
		}
		got[0] = original // if the result aliased the table, restore it for later tests
	})

	t.Run("additive suffixes extend the whole built-in set", func(t *testing.T) {
		got, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{"Corp.COM"}})
		if err != nil {
			t.Fatalf("effectiveEmailSuffixes(additive): %v", err)
		}
		for _, builtin := range builtinEmailSuffixes {
			if !slices.Contains(got, builtin) {
				t.Errorf("additive result is missing built-in suffix %q", builtin)
			}
		}
		if !slices.Contains(got, ".corp.com") {
			t.Errorf("additive result %v is missing the normalized declared suffix .corp.com", got)
		}
		if slices.Contains(got, ".Corp.COM") {
			t.Errorf("additive result %v kept the unnormalized declared form .Corp.COM", got)
		}
		if want := len(builtinEmailSuffixes) + 1; len(got) != want {
			t.Errorf("len(additive) = %d, want %d", len(got), want)
		}
	})

	t.Run("an unknown suffix is an additive declaration", func(t *testing.T) {
		got, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{"corp.com", "co.uk"}})
		if err != nil {
			t.Fatalf("effectiveEmailSuffixes(unknown): %v", err)
		}
		if !slices.Contains(got, ".corp.com") || !slices.Contains(got, ".co.uk") {
			t.Errorf("additive result %v is missing a declared suffix", got)
		}
	})

	t.Run("replace returns only the normalized declared entries", func(t *testing.T) {
		got, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{"Corp.COM", "co.uk"}, Replace: true})
		if err != nil {
			t.Fatalf("effectiveEmailSuffixes(replace): %v", err)
		}
		want := []string{".corp.com", ".co.uk"}
		if !slices.Equal(got, want) {
			t.Errorf("replace result = %v, want exactly %v", got, want)
		}
	})

	t.Run("replace with an empty declared list matches nothing", func(t *testing.T) {
		got, err := effectiveEmailSuffixes(&EmailOptions{Replace: true})
		if err != nil {
			t.Fatalf("effectiveEmailSuffixes(replace-empty): %v", err)
		}
		if len(got) != 0 {
			t.Errorf("replace-empty result = %v, want no suffixes", got)
		}
	})

	t.Run("a declared duplicate of a built-in does not grow the set", func(t *testing.T) {
		got, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{"Corp.COM", ".corp.com", "com"}})
		if err != nil {
			t.Fatalf("effectiveEmailSuffixes(dedup): %v", err)
		}
		if n := countSuffix(got, ".corp.com"); n != 1 {
			t.Errorf("count of .corp.com = %d, want 1", n)
		}
		if n := countSuffix(got, ".com"); n != 1 {
			t.Errorf("count of .com = %d, want 1 (a declared repeat of a built-in)", n)
		}
		if want := len(builtinEmailSuffixes) + 1; len(got) != want {
			t.Errorf("len(additive-with-duplicates) = %d, want %d", len(got), want)
		}
	})

	t.Run("repeated additive calls are stable", func(t *testing.T) {
		first, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{"Corp.COM"}})
		if err != nil {
			t.Fatalf("first call: %v", err)
		}
		second, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{"Corp.COM"}})
		if err != nil {
			t.Fatalf("second call: %v", err)
		}
		if !slices.Equal(first, second) {
			t.Errorf("effectiveEmailSuffixes is not stable across calls:\nfirst  = %v\nsecond = %v", first, second)
		}
	})

	t.Run("a malformed declared entry is rejected in both modes", func(t *testing.T) {
		tests := []struct {
			name     string
			declared string
			want     error // the sentinel the error must satisfy
			other    error // the sentinel the error must NOT satisfy
		}{
			{"dot-dot run", "a..b", ErrInvalidValue, ErrBoundExceeded},
			{"internal whitespace", "a b.com", ErrInvalidValue, ErrBoundExceeded},
			{"non-ASCII label", "例え.com", ErrInvalidValue, ErrBoundExceeded},
			{"over-length canonical form", strings.Repeat("a", MaxLiteralBytes), ErrBoundExceeded, ErrInvalidValue},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for _, replace := range []bool{false, true} {
					got, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{tt.declared}, Replace: replace})
					if !errors.Is(err, tt.want) {
						t.Fatalf("replace=%v: error = %v, want %v", replace, err, tt.want)
					}
					if errors.Is(err, tt.other) {
						t.Errorf("replace=%v: error = %v, must not satisfy %v", replace, err, tt.other)
					}
					if got != nil {
						t.Errorf("replace=%v: result = %v on error, want nil", replace, got)
					}
				}
			})
		}
	})

	t.Run("effective suffixes never mutate the built-in table", func(t *testing.T) {
		before := BuiltinEmailSuffixes()
		if _, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{"Corp.COM"}}); err != nil {
			t.Fatalf("additive: %v", err)
		}
		if _, err := effectiveEmailSuffixes(&EmailOptions{Suffixes: []string{"co.uk"}, Replace: true}); err != nil {
			t.Fatalf("replace: %v", err)
		}
		if _, err := effectiveEmailSuffixes(nil); err != nil {
			t.Fatalf("nil: %v", err)
		}
		after := BuiltinEmailSuffixes()
		if !slices.Equal(before, after) {
			t.Errorf("BuiltinEmailSuffixes() changed across effectiveEmailSuffixes calls:\nbefore = %v\nafter  = %v", before, after)
		}
	})
}

// TestBuiltinEmailSuffixes pins the provisional table's shape: non-empty,
// every entry a dot-prefixed canonical suffix, the reserved and special-use
// names (localhost, test, example, invalid) absent in both their bare and
// dotted forms, the curated compound entries present, and the exported accessor
// a fresh clone per call so a caller can never mutate the package table.
func TestBuiltinEmailSuffixes(t *testing.T) {
	got := BuiltinEmailSuffixes()
	if len(got) == 0 {
		t.Fatal("BuiltinEmailSuffixes() is empty")
	}

	for i, suffix := range got {
		if !strings.HasPrefix(suffix, ".") || len(suffix) < 2 {
			t.Errorf("entry %d = %q, want a dot-prefixed canonical suffix", i, suffix)
		}
	}

	for _, reserved := range []string{".localhost", ".test", ".example", ".invalid"} {
		if slices.Contains(got, reserved) {
			t.Errorf("BuiltinEmailSuffixes() contains the reserved suffix %q", reserved)
		}
	}
	for _, bare := range []string{"localhost", "test", "example", "invalid"} {
		if slices.Contains(got, bare) {
			t.Errorf("BuiltinEmailSuffixes() contains the bare reserved name %q", bare)
		}
	}

	for _, want := range []string{".com", ".co.uk", ".com.au", ".co.jp", ".com.br"} {
		if !slices.Contains(got, want) {
			t.Errorf("BuiltinEmailSuffixes() is missing the curated entry %q", want)
		}
	}

	// Clone: a mutation through one result must not reach the next call or
	// the package table. The restore keeps later tests meaningful even when
	// the clone contract is the very thing that is broken.
	original := got[0]
	got[0] = ".mutated"
	next := BuiltinEmailSuffixes()
	if next[0] != original {
		t.Errorf("BuiltinEmailSuffixes()[0] = %q after mutating a previous result, want %q", next[0], original)
	}
	if builtinEmailSuffixes[0] != original {
		t.Errorf("builtinEmailSuffixes[0] = %q after mutating a returned clone, want %q", builtinEmailSuffixes[0], original)
	}
	got[0] = original
}

// countSuffix returns how many times suffix appears in suffixes.
func countSuffix(suffixes []string, suffix string) int {
	n := 0
	for _, s := range suffixes {
		if s == suffix {
			n++
		}
	}
	return n
}
