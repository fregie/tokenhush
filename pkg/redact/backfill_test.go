package redact

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestBackfillRestoresMappedPlaceholder(t *testing.T) {
	w := NewForwardWriter(NewEngine())
	b := NewBackfiller()
	secret := []byte("alice@example.com")

	p, err := b.Mint(w, secret, "email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(p, placeholderPrefix) {
		t.Fatalf("Mint returned %q, want a placeholder", p)
	}

	body := []byte("hello " + p + " and " + p + " again")
	got := b.Backfill(body)
	if bytes.Contains(got, []byte(p)) {
		t.Fatalf("placeholder survived Backfill: %q", got)
	}
	if want := bytes.ReplaceAll(body, []byte(p), secret); !bytes.Equal(got, want) {
		t.Fatalf("Backfill = %q, want %q", got, want)
	}
}

func TestBackfillExcludedValueIsNeverRestored(t *testing.T) {
	w := NewForwardWriter(NewEngine())
	b := NewBackfiller()
	secret := []byte("control-token-42")

	p, err := b.Mint(w, secret, "token")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(p, placeholderPrefix) {
		t.Fatalf("Mint returned %q, want a placeholder", p)
	}

	b.ExcludeFromBackfill(secret)
	if !b.Excludes(secret) {
		t.Fatal("Excludes(secret) = false, want true")
	}

	// Outbound force-substitution: the secret leaves as the placeholder.
	body := []byte("auth " + string(secret) + " now")
	outbound := bytes.ReplaceAll(body, secret, []byte(p))
	if bytes.Contains(outbound, secret) {
		t.Fatalf("secret leaked outbound: %q", outbound)
	}

	// The client-bound pass must keep the excluded placeholder verbatim.
	got := b.Backfill(outbound)
	if !bytes.Equal(got, outbound) {
		t.Fatalf("excluded secret was restored: %q", got)
	}
	if !bytes.Contains(got, []byte(p)) {
		t.Fatalf("placeholder %q vanished from %q", p, got)
	}
	if bytes.Contains(got, secret) {
		t.Fatalf("excluded secret %q appeared in %q", secret, got)
	}
}

func TestExcludeFromBackfillIsAdditiveAndIdempotent(t *testing.T) {
	b := NewBackfiller()
	first := []byte("control-token-42")
	second := []byte("allowlist-bytes-7")

	b.ExcludeFromBackfill(first)
	b.ExcludeFromBackfill(first) // same value twice: no-op the second time
	if got := b.excludedCount(); got != 1 {
		t.Fatalf("excludedCount after duplicate = %d, want 1", got)
	}

	b.ExcludeFromBackfill(second) // additive
	if !b.Excludes(first) || !b.Excludes(second) {
		t.Fatalf("Excludes = (%v, %v), want both true", b.Excludes(first), b.Excludes(second))
	}
	if got := b.excludedCount(); got != 2 {
		t.Fatalf("excludedCount = %d, want 2", got)
	}
}

func TestBackfillForeignAndUnknownPlaceholdersUnchanged(t *testing.T) {
	b := NewBackfiller()
	body := []byte("foreign __PII_email_deadbeefcafe__ and unknown tok_12345 must stay")

	got := b.Backfill(body)
	if !bytes.Equal(got, body) {
		t.Fatalf("Backfill changed a foreign body: %q", got)
	}
}

func TestBackfillFreshSessionForgetsMapping(t *testing.T) {
	w := NewForwardWriter(NewEngine())
	old := NewBackfiller()
	secret := []byte("alice@example.com")

	p, err := old.Mint(w, secret, "email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	fresh := NewBackfiller()
	body := []byte("stale " + p + " from a previous session")
	got := fresh.Backfill(body)
	if !bytes.Equal(got, body) {
		t.Fatalf("fresh session restored a stale mapping: %q", got)
	}
}

func TestBackfillNoMatchIsByteIdentical(t *testing.T) {
	b := NewBackfiller()
	body := []byte("nothing redactable here")

	got := b.Backfill(body)
	if !bytes.Equal(got, body) {
		t.Fatalf("Backfill = %q, want the exact input %q", got, body)
	}
}

func TestForwardWriterCannotRestore(t *testing.T) {
	hints := []string{"restore", "backfill", "unbackfill", "unredact", "reveal", "expand", "decode"}

	for _, typ := range []reflect.Type{reflect.TypeOf(ForwardWriter{}), reflect.TypeOf(&ForwardWriter{})} {
		for i := 0; i < typ.NumMethod(); i++ {
			lower := strings.ToLower(typ.Method(i).Name)
			for _, hint := range hints {
				if strings.Contains(lower, hint) {
					t.Fatalf("%s exposes restore-like method %s", typ, typ.Method(i).Name)
				}
			}
		}
	}

	for _, typ := range []reflect.Type{reflect.TypeOf(ForwardWriter{}), reflect.TypeOf(Engine{})} {
		for i := 0; i < typ.NumField(); i++ {
			lower := strings.ToLower(typ.Field(i).Name)
			if strings.Contains(lower, "reverse") || strings.Contains(lower, "backfill") {
				t.Fatalf("%s has reverse-map field %s", typ, typ.Field(i).Name)
			}
		}
	}

	if _, ok := reflect.TypeOf(Backfiller{}).FieldByName("reverse"); !ok {
		t.Fatal("Backfiller must own the reverse map field")
	}
}
