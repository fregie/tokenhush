package redact

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// TestControlTokenNeverBackfilled locks the W6.1 narrow exclusion exception to
// the F1 general restore primitive: a value placed in the exclusion set is
// never restored inbound, while every other value keeps its byte-identical
// restore behaviour, and the detector allowlist cannot suppress the forced
// (non-Inspect) redaction path that produces the exclusion placeholder.
func TestControlTokenNeverBackfilled(t *testing.T) {
	// Assembled at runtime from fragments so no contiguous detector-shaped
	// literal is committed; the value still matches the `sk-` prefix detector,
	// which makes the allowlist subtest meaningful.
	token := "sk" + "-" + "canary" + "-" + "AbCdEf1234567890"
	kind := "api_key"

	t.Run("excluded_value_is_never_restored", func(t *testing.T) {
		e := mustEngine(t)
		e.ExcludeFromBackfill([]byte(token))
		placeholder := e.Placeholder(token, kind)

		if got, ok := e.Secret(placeholder); ok || got != "" {
			t.Fatalf("Secret(%q) = (%q,%v), want (\"\",false) for an excluded value", placeholder, got, ok)
		}
		if got := e.BackfillFunc()(placeholder); got != placeholder {
			t.Fatalf("BackfillFunc(%q) = %q, want the placeholder verbatim", placeholder, got)
		}

		var dst bytes.Buffer
		w := e.NewBackfillWriter(&dst)
		_, _ = w.Write([]byte("before " + placeholder + " after"))
		if err := w.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if strings.Contains(dst.String(), token) {
			t.Fatalf("excluded value was restored by the inbound writer: %q", dst.String())
		}
		if !strings.Contains(dst.String(), placeholder) {
			t.Fatalf("excluded placeholder disappeared from the client-bound stream: %q", dst.String())
		}
	})

	t.Run("boundary_non_excluded_values_restore_byte_identical", func(t *testing.T) {
		e := mustEngine(t)
		e.ExcludeFromBackfill([]byte(token))

		for _, secret := range []string{"other-canary-0002", "third-canary-0003", "fourth-canary-0004"} {
			placeholder := e.Placeholder(secret, kind)
			if got, ok := e.Secret(placeholder); !ok || got != secret {
				t.Fatalf("Secret(%q) = (%q,%v), want (%q,true) for a non-excluded value", placeholder, got, ok, secret)
			}
			if got := e.BackfillFunc()(placeholder); got != secret {
				t.Fatalf("BackfillFunc(%q) = %q, want %q", placeholder, got, secret)
			}
		}

		// Byte-identical round trip through the real writer, mirroring the
		// pre-W6.1 behaviour a regression would break.
		const secret = "boundary-canary-0005"
		placeholder := e.Placeholder(secret, kind)
		stream := "prefix " + placeholder + " suffix"
		want := "prefix " + secret + " suffix"
		var dst bytes.Buffer
		w := e.NewBackfillWriter(&dst)
		_, _ = w.Write([]byte(stream))
		if err := w.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got := dst.String(); got != want {
			t.Fatalf("non-excluded round trip = %q, want %q", got, want)
		}
	})

	t.Run("empty_exclusion_set_is_a_noop", func(t *testing.T) {
		e := mustEngine(t)
		// No ExcludeFromBackfill call at all: the pre-W6.1 engine restores
		// every mapped value.
		placeholder := e.Placeholder(token, kind)
		if got, ok := e.Secret(placeholder); !ok || got != token {
			t.Fatalf("Secret(%q) = (%q,%v), want (%q,true) when no exclusion is registered", placeholder, got, ok, token)
		}
	})

	t.Run("allowlist_cannot_suppress_forced_redaction", func(t *testing.T) {
		content := "here is " + token + " inside"

		// Non-vacuity: without the allowlist the detector finds the value, so
		// the suppressed case below proves the allowlist is doing the work.
		bare, err := NewPrefixDetector().Inspect(contentDocumentForTest(content))
		if err != nil {
			t.Fatalf("bare Inspect: %v", err)
		}
		if len(bare) == 0 {
			t.Fatalf("test setup: the prefix detector did not find %q", token)
		}

		det := NewPrefixDetector(WithAllowlist(token))
		suppressed, err := det.Inspect(contentDocumentForTest(content))
		if err != nil {
			t.Fatalf("allowlisted Inspect: %v", err)
		}
		if len(suppressed) != 0 {
			t.Fatalf("test setup: the allowlist did not suppress the detector finding: %+v", suppressed)
		}

		// The forced path never calls Inspect: it feeds the detected span
		// straight to ApplyPlaceholders, so the allowlist cannot exempt it.
		e := mustEngine(t)
		at := bytes.Index([]byte(content), []byte(token))
		if at < 0 {
			t.Fatal("test setup: token absent from content")
		}
		out := e.ApplyPlaceholders([]byte(content), []Redaction{
			{Start: at, End: at + len(token), Type: "self_protection"},
		})
		if bytes.Contains(out, []byte(token)) {
			t.Fatalf("allowlist suppressed the forced redaction: %q", out)
		}
		if !bytes.Contains(out, []byte(placeholderOpen)) {
			t.Fatalf("forced redaction produced no placeholder: %q", out)
		}
	})
}

// contentDocumentForTest builds a single-leaf extension.Document so a detector
// can be driven directly, matching what contentDocument feeds Inspect.
func contentDocumentForTest(content string) *extension.Document {
	return &extension.Document{
		Phase:  extension.RequestContent,
		Leaves: []extension.Leaf{{Content: []byte(content), Len: len(content)}},
	}
}
