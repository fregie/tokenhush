package redact

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// reversePathHints are names that would betray a placeholder -> secret path on
// a type that must never have one.
var reversePathHints = []string{"reverse", "backfill", "restore", "unredact", "reveal", "expand"}

// assertForwardOnlyShape fails when typ grows a reverse map: a map field that
// is not the forward map, a field named like a backfill path, or a forward map
// that holds secret payloads instead of placeholder strings.
func assertForwardOnlyShape(t *testing.T, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.ToLower(field.Name)
		for _, hint := range reversePathHints {
			if strings.Contains(name, hint) {
				t.Fatalf("%s.%s is named like a reverse/backfill path", typ, field.Name)
			}
		}
		if field.Type.Kind() != reflect.Map {
			continue
		}
		if !strings.Contains(name, "forward") {
			t.Fatalf("%s.%s is a map but not the forward map", typ, field.Name)
		}
		value := field.Type.Elem()
		if value.Kind() == reflect.Slice || value.Kind() == reflect.Pointer {
			t.Fatalf("%s.%s may hold secret payloads, not placeholders", typ, field.Name)
		}
	}
}

// assertNoRestoreMethod fails when typ exposes a method that consumes a string
// (a placeholder) and returns raw bytes (a secret), or is named like a restore
// path. It also pins the outbound writer's public surface to placeholder
// minting alone.
func assertNoRestoreMethod(t *testing.T, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumMethod(); i++ {
		method := typ.Method(i)
		name := strings.ToLower(method.Name)
		for _, hint := range reversePathHints {
			if strings.Contains(name, hint) {
				t.Fatalf("%s.%s looks like a restore path", typ, method.Name)
			}
		}
		signature := method.Type
		if signature.NumIn() == 0 || signature.NumOut() == 0 {
			continue
		}
		takesString := false
		for j := 0; j < signature.NumIn(); j++ {
			if signature.In(j).Kind() == reflect.String {
				takesString = true
			}
		}
		returnsBytes := false
		for j := 0; j < signature.NumOut(); j++ {
			out := signature.Out(j)
			if out.Kind() == reflect.Slice && out.Elem().Kind() == reflect.Uint8 {
				returnsBytes = true
			}
		}
		if takesString && returnsBytes {
			t.Fatalf("%s.%s takes a placeholder and returns a secret", typ, method.Name)
		}
	}
}

// assertPlaceholderOnlySurface pins the outbound writer to exactly one exported
// operation, Placeholder([]byte, string) (string, error).
func assertPlaceholderOnlySurface(t *testing.T, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumMethod(); i++ {
		method := typ.Method(i)
		if method.Name != "Placeholder" {
			t.Fatalf("%s exposes %s, want only Placeholder", typ, method.Name)
		}
	}
	placeholder, ok := typ.MethodByName("Placeholder")
	if !ok {
		t.Fatalf("%s has no Placeholder method", typ)
	}
	// reflect includes the receiver as the first input of a method signature.
	signature := placeholder.Type
	if signature.NumIn() != 3 || signature.NumOut() != 2 {
		t.Fatalf("%s.Placeholder arity = (%d in, %d out), want receiver + ([]byte, string) in and (string, error) out",
			typ, signature.NumIn(), signature.NumOut())
	}
	if signature.In(0).Kind() != reflect.Pointer {
		t.Fatalf("%s.Placeholder receiver = %s, want a pointer receiver", typ, signature.In(0))
	}
	if signature.In(1).Kind() != reflect.Slice || signature.In(2).Kind() != reflect.String {
		t.Fatalf("%s.Placeholder inputs = (_, %s, %s), want (_, []byte, string)", typ, signature.In(1), signature.In(2))
	}
	if signature.Out(0).Kind() != reflect.String || signature.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("%s.Placeholder outputs = (%s, %s), want (string, error)", typ, signature.Out(0), signature.Out(1))
	}
}

// TestInvariant1NeverBackfillOutbound proves invariant 1: the outbound writer
// substitutes forward only. It cannot restore a placeholder, re-application is
// idempotent, and a body that already carries a known placeholder is forwarded
// verbatim.
func TestInvariant1NeverBackfillOutbound(t *testing.T) {
	t.Run("shape: forward-only writer", func(t *testing.T) {
		assertForwardOnlyShape(t, reflect.TypeOf(ForwardWriter{}))
		assertForwardOnlyShape(t, reflect.TypeOf(engine{}))
		assertNoRestoreMethod(t, reflect.TypeOf(&ForwardWriter{}))
		assertNoRestoreMethod(t, reflect.TypeOf(&engine{}))
		assertPlaceholderOnlySurface(t, reflect.TypeOf(&ForwardWriter{}))
	})

	t.Run("applied redactions produce placeholders", func(t *testing.T) {
		w := NewForwardWriter(newEngine())
		secret := []byte("alice@example.com")
		body := []byte("to alice@example.com and cc alice@example.com please")

		out, err := redactBody(w, body, [][]byte{secret}, "email")
		if err != nil {
			t.Fatalf("redactBody: %v", err)
		}
		if bytes.Contains(out, secret) {
			t.Fatalf("secret survived redaction: %q", out)
		}
		p, err := w.Placeholder(secret, "email")
		if err != nil {
			t.Fatalf("placeholder: %v", err)
		}
		if got := bytes.Count(out, []byte(p)); got != 2 {
			t.Fatalf("placeholder %q occurs %d times, want 2 in %q", p, got, out)
		}
	})

	t.Run("re-application is idempotent", func(t *testing.T) {
		w := NewForwardWriter(newEngine())
		secrets := [][]byte{[]byte("alice@example.com"), []byte("bob@example.com")}
		body := []byte("alice@example.com wrote to bob@example.com about alice@example.com")

		first, err := redactBody(w, body, secrets, "email")
		if err != nil {
			t.Fatalf("first redactBody: %v", err)
		}
		second, err := redactBody(w, first, secrets, "email")
		if err != nil {
			t.Fatalf("second redactBody: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("re-application changed the body:\n first: %q\nsecond: %q", first, second)
		}
	})

	t.Run("body with a known placeholder is forwarded intact", func(t *testing.T) {
		w := NewForwardWriter(newEngine())
		secret := []byte("alice@example.com")
		known, err := w.Placeholder(secret, "email")
		if err != nil {
			t.Fatalf("placeholder: %v", err)
		}
		body := []byte("already redacted: " + known + " stays")

		// An unrelated redaction set never touches a placeholder it does not
		// mint, and never expands one it knows.
		out, err := redactBody(w, body, [][]byte{[]byte("carol@example.com")}, "email")
		if err != nil {
			t.Fatalf("redactBody unrelated: %v", err)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("unrelated redaction changed the body: %q", out)
		}

		// Even with the preimage in the redaction set, the placeholder is
		// forwarded verbatim: the outbound path has no backfill.
		out, err = redactBody(w, body, [][]byte{secret}, "email")
		if err != nil {
			t.Fatalf("redactBody with preimage: %v", err)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("known placeholder was not forwarded intact: %q", out)
		}
		if !bytes.Contains(out, []byte(known)) {
			t.Fatalf("placeholder %q vanished from %q", known, out)
		}
	})
}

// boundMatcher is the synthetic invariant-8 probe matcher: a token is any
// "<<...>>" run and every unterminated run is still a candidate prefix, so the
// writer must hold it until the bound forces a literal release.
type boundMatcher struct{}

// MaxTokenLen reports a longest token far beyond the holdback bound, so the
// bound (not the matcher) is what limits the held window.
func (boundMatcher) MaxTokenLen() int { return protocol.SSEBackfillHoldbackBytes * 2 }

// TokenLen never completes a token, so every fed byte must leave as literal
// text rather than as a replacement.
func (boundMatcher) TokenLen([]byte) int { return 0 }

// PrefixLen claims the whole tail while no ">>" has been seen.
func (boundMatcher) PrefixLen(p []byte) int {
	if bytes.Contains(p, []byte(">>")) {
		return 0
	}
	return len(p)
}

// TestInvariant8BoundDerived proves invariant 8 with the production bound: an
// unterminated token can never make the writer hold more than
// protocol.SSEBackfillHoldbackBytes, and past the bound the oldest held bytes
// leave literally and in order, so the writer always makes progress instead of
// buffering without limit. Every size here is derived from the bound itself.
func TestInvariant8BoundDerived(t *testing.T) {
	w := protocol.NewBackfillWriter(boundMatcher{}, func(tok []byte) []byte { return tok })

	limit := protocol.SSEBackfillHoldbackBytes
	chunk := limit / 16
	overflow := limit / 64
	if chunk <= 0 || overflow <= 0 {
		t.Fatalf("derived sizes must be positive: limit=%d chunk=%d overflow=%d", limit, chunk, overflow)
	}
	total := limit + overflow

	data := bytes.Repeat([]byte("<"), chunk)
	fed, released := 0, 0
	for fed < total {
		n := chunk
		if n > total-fed {
			n = total - fed
		}
		released += len(w.Feed(data[:n]))
		fed += n
		if held := w.Held(); held > limit {
			t.Fatalf("Held() = %d after %d bytes fed, want <= %d", held, fed, limit)
		}
	}
	if released == 0 {
		t.Fatal("no bytes were released before the bound was crossed: the writer buffered without limit")
	}

	// Nothing is replaced and nothing is dropped: every byte leaves exactly
	// once, either released during a Feed or flushed at the end.
	flushed := len(w.Flush())
	if got := released + flushed; got != fed {
		t.Fatalf("released %d + flushed %d = %d, want all %d fed bytes (literal passthrough)",
			released, flushed, got, fed)
	}
}
