package redact

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// secretsAsStrings converts a KnownSecrets snapshot into strings so a test can
// compare it as data. It never asserts on the raw slices' identity.
func secretsAsStrings(secrets [][]byte) []string {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, string(s))
	}
	return out
}

// sameStrings reports whether two string slices are byte-for-byte equal.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestKnownSecretsSnapshot locks the read-only enumeration contract: one entry
// per distinct secret (however many types it was mapped under), a snapshot copy
// that cannot corrupt engine state in either direction, a deterministic order,
// and nil-engine tolerance.
func TestKnownSecretsSnapshot(t *testing.T) {
	t.Run("empty_engine_is_empty", func(t *testing.T) {
		e := mustEngine(t)
		if got := e.KnownSecrets(); len(got) != 0 {
			t.Fatalf("empty engine KnownSecrets() = %q, want none", got)
		}
	})

	t.Run("nil_engine_is_empty", func(t *testing.T) {
		var e *PlaceholderEngine
		// The membership scanner in W2.x treats a nil engine as "no known
		// secrets"; mirroring MaxPlaceholderLen's nil tolerance, this must not
		// panic on the mutex dereference.
		if got := e.KnownSecrets(); len(got) != 0 {
			t.Fatalf("nil engine KnownSecrets() = %q, want none", got)
		}
	})

	t.Run("one_entry_per_distinct_secret", func(t *testing.T) {
		e := mustEngine(t)
		e.Placeholder("dedup-alpha", "api_key")
		e.Placeholder("dedup-alpha", "email") // same secret under a second type
		e.Placeholder("dedup-beta", "jwt")

		got := secretsAsStrings(e.KnownSecrets())
		if len(got) != 2 {
			t.Fatalf("KnownSecrets() = %q, want 2 distinct secrets", got)
		}
		for _, want := range []string{"dedup-alpha", "dedup-beta"} {
			found := false
			for _, s := range got {
				if s == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("KnownSecrets() = %q, missing %q", got, want)
			}
		}
	})

	t.Run("deterministic_order", func(t *testing.T) {
		e := mustEngine(t)
		for _, s := range []string{"order-zzz", "order-aaa", "order-mmm"} {
			e.Placeholder(s, "api_key")
		}
		want := []string{"order-aaa", "order-mmm", "order-zzz"}
		for i := 0; i < 10; i++ {
			if got := secretsAsStrings(e.KnownSecrets()); !sameStrings(got, want) {
				t.Fatalf("KnownSecrets() call %d = %q, want %q", i, got, want)
			}
		}
	})

	t.Run("empty_secret_is_omitted", func(t *testing.T) {
		e := mustEngine(t)
		e.Placeholder("", "api_key")
		if got := e.KnownSecrets(); len(got) != 0 {
			t.Fatalf("KnownSecrets() = %q, want the empty mapping omitted", got)
		}
	})

	t.Run("returned_bytes_are_copies", func(t *testing.T) {
		e := mustEngine(t)
		const secret = "copied-alpha"
		placeholder := e.Placeholder(secret, "api_key")

		got := e.KnownSecrets()
		if len(got) != 1 || string(got[0]) != secret {
			t.Fatalf("KnownSecrets() = %q, want [%q]", got, secret)
		}
		got[0][0] ^= 0xff // mutate the returned copy only

		if restored, ok := e.Secret(placeholder); !ok || restored != secret {
			t.Fatalf("Secret(%q) = (%q,%v) after mutating the snapshot, want (%q,true)", placeholder, restored, ok, secret)
		}
		if again := secretsAsStrings(e.KnownSecrets()); !sameStrings(again, []string{secret}) {
			t.Fatalf("KnownSecrets() after mutating the snapshot = %q, want [%q]", again, secret)
		}
	})

	t.Run("snapshot_isolated_from_later_engine_mutation", func(t *testing.T) {
		e := mustEngine(t)
		e.Placeholder("isolated-alpha", "api_key")
		got := e.KnownSecrets()

		e.Placeholder("isolated-beta", "jwt")
		if want := []string{"isolated-alpha"}; !sameStrings(secretsAsStrings(got), want) {
			t.Fatalf("earlier snapshot changed to %q, want %q", secretsAsStrings(got), want)
		}
	})
}

// TestKnownSecretMembership locks the read-only membership check the outbound
// (post-redaction) re-check will call: substring semantics, empty-needle
// protection, deterministic placeholder identification and nil tolerance.
func TestKnownSecretMembership(t *testing.T) {
	const kind = "api_key"
	const secret = "membership-canary"

	t.Run("exact_secret_matches", func(t *testing.T) {
		e := mustEngine(t)
		want := e.Placeholder(secret, kind)

		ok, token := e.ContainsKnownSecret([]byte(secret))
		if !ok || token != want {
			t.Fatalf("ContainsKnownSecret(%q) = (%v,%q), want (true,%q)", secret, ok, token, want)
		}
		if strings.Contains(token, secret) {
			t.Fatalf("second return value carries the plaintext secret: %q", token)
		}
	})

	t.Run("embedded_secret_matches", func(t *testing.T) {
		e := mustEngine(t)
		want := e.Placeholder(secret, kind)
		body := []byte(`{"messages":[{"content":"please remember ` + secret + ` forever"}]}`)

		ok, token := e.ContainsKnownSecret(body)
		if !ok || token != want {
			t.Fatalf("ContainsKnownSecret(embedded) = (%v,%q), want (true,%q)", ok, token, want)
		}
		if strings.Contains(token, secret) {
			t.Fatalf("second return value carries the plaintext secret: %q", token)
		}
	})

	t.Run("unknown_secret_does_not_match", func(t *testing.T) {
		e := mustEngine(t)
		e.Placeholder(secret, kind)

		ok, token := e.ContainsKnownSecret([]byte("membership-cananry is one typo away"))
		if ok || token != "" {
			t.Fatalf("ContainsKnownSecret(near miss) = (%v,%q), want (false,\"\")", ok, token)
		}
	})

	t.Run("empty_engine_does_not_match", func(t *testing.T) {
		e := mustEngine(t)
		if ok, token := e.ContainsKnownSecret([]byte("anything at all")); ok || token != "" {
			t.Fatalf("empty engine ContainsKnownSecret = (%v,%q), want (false,\"\")", ok, token)
		}
	})

	t.Run("empty_input_does_not_match", func(t *testing.T) {
		e := mustEngine(t)
		e.Placeholder(secret, kind)
		for name, in := range map[string][]byte{"nil": nil, "zero_length": {}} {
			if ok, token := e.ContainsKnownSecret(in); ok || token != "" {
				t.Fatalf("%s input ContainsKnownSecret = (%v,%q), want (false,\"\")", name, ok, token)
			}
		}
	})

	t.Run("empty_secret_never_matches", func(t *testing.T) {
		e := mustEngine(t)
		e.Placeholder("", kind)

		// An empty needle is a substring of every buffer; it must be skipped
		// explicitly rather than reported as a hit.
		if ok, token := e.ContainsKnownSecret([]byte("any buffer")); ok || token != "" {
			t.Fatalf("empty-secret mapping matched = (%v,%q), want (false,\"\")", ok, token)
		}
	})

	t.Run("nil_engine_is_safe", func(t *testing.T) {
		var e *PlaceholderEngine
		if ok, token := e.ContainsKnownSecret([]byte("any buffer")); ok || token != "" {
			t.Fatalf("nil engine ContainsKnownSecret = (%v,%q), want (false,\"\")", ok, token)
		}
	})

	t.Run("secret_containing_nul_matches", func(t *testing.T) {
		e := mustEngine(t)
		const nulSecret = "nul\x00separated-secret"
		want := e.Placeholder(nulSecret, kind)

		// bySecret keys are typ + "\x00" + secret; the first NUL separates the
		// sanitised type (which cannot contain NUL) from the secret, so a NUL
		// inside the secret itself must survive the split intact.
		ok, token := e.ContainsKnownSecret([]byte("prefix " + nulSecret + " suffix"))
		if !ok || token != want {
			t.Fatalf("ContainsKnownSecret(NUL secret) = (%v,%q), want (true,%q)", ok, token, want)
		}
	})

	t.Run("longest_match_wins", func(t *testing.T) {
		e := mustEngine(t)
		short := e.Placeholder("longest-alpha", kind)
		long := e.Placeholder("longest-alphabet", kind)
		body := []byte("xx longest-alphabet yy")

		ok, token := e.ContainsKnownSecret(body)
		if !ok || token != long {
			t.Fatalf("ContainsKnownSecret(overlapping) = (%v,%q), want (true,%q) (short match=%q)", ok, token, long, short)
		}
	})

	t.Run("same_secret_mapped_twice_is_deterministic", func(t *testing.T) {
		e := mustEngine(t)
		first := e.Placeholder("dup-membership", kind)
		second := e.Placeholder("dup-membership", "email")
		want := first
		if second < first {
			want = second
		}

		// One secret, two placeholders: whichever token is reported must not
		// depend on Go's per-call random map iteration order.
		for i := 0; i < 50; i++ {
			ok, token := e.ContainsKnownSecret([]byte("say dup-membership now"))
			if !ok || token != want {
				t.Fatalf("ContainsKnownSecret call %d = (%v,%q), want (true,%q)", i, ok, token, want)
			}
		}
	})

	t.Run("equal_length_ties_are_deterministic", func(t *testing.T) {
		e := mustEngine(t)
		first := e.Placeholder("tie-aaaa", kind)
		e.Placeholder("tie-bbbb", kind)
		body := []byte("tie-bbbbtie-aaaa")

		// Both secrets match and both are the same length; whichever is chosen
		// must not depend on Go's per-call random map iteration order.
		for i := 0; i < 50; i++ {
			ok, token := e.ContainsKnownSecret(body)
			if !ok || token != first {
				t.Fatalf("ContainsKnownSecret call %d = (%v,%q), want (true,%q)", i, ok, token, first)
			}
		}
	})
}

// TestKnownSecretsConcurrentReads exercises the new read API against a
// concurrent writer (Placeholder), so a -race run of this package covers the
// read path. It does not require -race to pass.
func TestKnownSecretsConcurrentReads(t *testing.T) {
	e := mustEngine(t)
	const base = "concurrent-base"
	want := e.Placeholder(base, "api_key")
	body := []byte("xx " + base + " yy")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				e.Placeholder(fmt.Sprintf("concurrent-secret-%d", i), "jwt")
			}
		}
	}()

	for i := 0; i < 200; i++ {
		if ok, token := e.ContainsKnownSecret(body); !ok || token != want {
			close(stop)
			wg.Wait()
			t.Fatalf("iteration %d: ContainsKnownSecret = (%v,%q), want (true,%q)", i, ok, token, want)
		}
		_ = e.KnownSecrets()
	}
	close(stop)
	wg.Wait()
}

// TestKnownSecretReadOnly proves the new API is read-only: repeated membership
// checks and enumerations must not create, change or drop any mapping.
func TestKnownSecretReadOnly(t *testing.T) {
	e := mustEngine(t)
	const secret = "readonly-alpha"
	placeholder := e.Placeholder(secret, "api_key")

	before := secretsAsStrings(e.KnownSecrets())
	for i := 0; i < 20; i++ {
		if ok, token := e.ContainsKnownSecret([]byte("x " + secret + " y")); !ok || token != placeholder {
			t.Fatalf("iteration %d: ContainsKnownSecret = (%v,%q), want (true,%q)", i, ok, token, placeholder)
		}
		if ok, _ := e.ContainsKnownSecret([]byte("not-a-secret-at-all")); ok {
			t.Fatalf("iteration %d: probe buffer reported as a secret", i)
		}
		_ = e.KnownSecrets()
	}

	after := secretsAsStrings(e.KnownSecrets())
	if !sameStrings(after, before) {
		t.Fatalf("read-only calls changed the mapping set: before=%q after=%q", before, after)
	}
	if restored, ok := e.Secret(placeholder); !ok || restored != secret {
		t.Fatalf("Secret(%q) = (%q,%v), want (%q,true)", placeholder, restored, ok, secret)
	}
	if got := e.Placeholder(secret, "api_key"); got != placeholder {
		t.Fatalf("Placeholder(%q) = %q, want the pre-existing %q", secret, got, placeholder)
	}
	if ok, _ := e.ContainsKnownSecret([]byte("not-a-secret-at-all")); ok {
		// The probe buffer was never mapped by any call above.
		t.Fatal("a probe value became a known secret after repeated reads")
	}
}

// TestKnownSecretAPIAbsentFromExtensionSurface is a core-side structural guard
// that reads the sibling pkg/extension sources from disk and asserts this API
// cannot leak into that package's exported surface: no exported identifier may
// match (?i)(placeholder|backfill|secret) — which covers KnownSecrets and
// ContainsKnownSecret — and the package must not import pkg/redact. Keeping the
// check here (instead of relying on pkg/extension's own sentinel test being
// executed) makes the guarantee travel with the API itself.
func TestKnownSecretAPIAbsentFromExtensionSurface(t *testing.T) {
	const dir = "../extension"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", dir, err)
	}

	forbidden := regexp.MustCompile(`(?i)(placeholder|backfill|secret)`)
	explicit := []string{"KnownSecrets", "ContainsKnownSecret"}
	fset := token.NewFileSet()
	scanned := 0

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			// Test files legitimately export Test* names that contain
			// "Secret"; the invariant is about the package's public surface.
			continue
		}
		scanned++
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", path, err)
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(importPath, "/pkg/redact") {
				t.Errorf("%s imports %q; the known-secret API must stay out of pkg/extension", path, importPath)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			var ids []*ast.Ident
			switch decl := n.(type) {
			case *ast.FuncDecl:
				ids = append(ids, decl.Name)
			case *ast.TypeSpec:
				ids = append(ids, decl.Name)
			case *ast.ValueSpec:
				ids = append(ids, decl.Names...)
			case *ast.Field:
				ids = append(ids, decl.Names...)
			}
			for _, id := range ids {
				if !id.IsExported() {
					continue
				}
				matchedExplicit := false
				for _, want := range explicit {
					if id.Name == want {
						t.Errorf("%s exports %q; the known-secret API must not appear in pkg/extension", path, id.Name)
						matchedExplicit = true
					}
				}
				if !matchedExplicit && forbidden.MatchString(id.Name) {
					t.Errorf("%s exports %q; pkg/extension must not expose the placeholder/secret mapping", path, id.Name)
				}
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatalf("no non-test .go files scanned under %s; the surface guard would pass vacuously", dir)
	}
}
