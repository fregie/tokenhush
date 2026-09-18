package redact

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// TestSubstituteUnlocatableSpanIsNeverMinted is the honesty (G3) test: a leaf
// with no raw locator has no raw region to splice, so Substitute must return
// the body unchanged, report nothing, and mint nothing -- neither a forward
// placeholder nor a reverse mapping. Minting here would put a placeholder in
// the reverse map for a secret that was never sent.
func TestSubstituteUnlocatableSpanIsNeverMinted(t *testing.T) {
	backfiller := NewBackfiller()
	writer := NewForwardWriter(newEngine())
	secret := []byte("alice@example.com")
	body := []byte(`{"content":"my email is alice@example.com"}`)
	leaf := protocol.Leaf{Path: "/content", Value: secret, Length: len(secret)}

	out, applied, err := backfiller.Substitute(writer, body, []Substitution{
		{Leaf: leaf, Start: 0, End: len(secret), Category: "email"},
	})
	if err != nil {
		t.Fatalf("Substitute: %v", err)
	}
	if !bytes.Equal(out, body) {
		t.Errorf("body changed for an unlocatable span:\n got %q\nwant %q", out, body)
	}
	if len(applied) != 0 {
		t.Errorf("applied = %+v, want none for an unlocatable span", applied)
	}
	if got := len(backfiller.reverse); got != 0 {
		t.Errorf("reverse map has %d entries, want 0 (no placeholder for an unsent secret)", got)
	}
	if got := len(writer.engine.forward); got != 0 {
		t.Errorf("forward map has %d entries, want 0 (nothing was minted)", got)
	}
}

// TestSubstituteLocatesRawSpanThroughEscapes pins the fix: the decoded secret
// contains bytes JSON escapes, so it is a non-substring of the raw body; the
// substitution must still locate its raw spelling, splice the placeholder
// there, and report exactly one byte-changing application.
func TestSubstituteLocatesRawSpanThroughEscapes(t *testing.T) {
	backfiller := NewBackfiller()
	writer := NewForwardWriter(newEngine())
	secret := []byte("line1\nline2\"quoted\"-\\slash")
	body, err := json.Marshal(map[string]string{"content": "token " + string(secret) + " end"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if bytes.Contains(body, secret) {
		t.Fatalf("the raw body unexpectedly contains the secret verbatim: %s", body)
	}
	leaves, err := protocol.Walk(body)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	leaf, at := leafContaining(t, leaves, secret)

	out, applied, err := backfiller.Substitute(writer, body, []Substitution{
		{Leaf: leaf, Start: at, End: at + len(secret), Category: "keyword"},
	})
	if err != nil {
		t.Fatalf("Substitute: %v", err)
	}
	if len(applied) != 1 {
		t.Fatalf("applied = %+v, want exactly one", applied)
	}
	if applied[0].Index != 0 || applied[0].Category != "keyword" || applied[0].Length != len(secret) {
		t.Errorf("applied[0] = %+v, want {Index:0 Category:keyword Length:%d}", applied[0], len(secret))
	}
	if bytes.Contains(out, secret) {
		t.Errorf("the secret survived substitution: %s", out)
	}
	if n := bytes.Count(out, []byte("__PII_keyword_")); n != 1 {
		t.Errorf("the output carries %d placeholders, want 1: %s", n, out)
	}
	if !json.Valid(out) {
		t.Errorf("the spliced body is no longer valid JSON: %s", out)
	}
	if got := len(backfiller.reverse); got != 1 {
		t.Fatalf("reverse map has %d entries, want 1", got)
	}
	for placeholder, mapped := range backfiller.reverse {
		if !bytes.Equal(mapped, secret) {
			t.Errorf("reverse mapping %q = %q, want the decoded secret %q", placeholder, mapped, secret)
		}
	}
}

// TestSubstituteSkipsOutOfRangeSpanOnly pins the per-substitution skip: an
// out-of-range secret span is dropped without minting, while a valid span in
// the same call is still applied and reported.
func TestSubstituteSkipsOutOfRangeSpanOnly(t *testing.T) {
	backfiller := NewBackfiller()
	writer := NewForwardWriter(newEngine())
	secret := []byte("alice@example.com")
	body := []byte(`{"content":"my email is alice@example.com"}`)
	leaves, err := protocol.Walk(body)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	leaf, at := leafContaining(t, leaves, secret)

	out, applied, err := backfiller.Substitute(writer, body, []Substitution{
		{Leaf: leaf, Start: 0, End: len(leaf.Value) + 1, Category: "email"},
		{Leaf: leaf, Start: at, End: at + len(secret), Category: "email"},
	})
	if err != nil {
		t.Fatalf("Substitute: %v", err)
	}
	if len(applied) != 1 || applied[0].Index != 1 {
		t.Fatalf("applied = %+v, want exactly the valid span at index 1", applied)
	}
	if bytes.Contains(out, secret) {
		t.Errorf("the in-range secret survived: %s", out)
	}
	if got := len(backfiller.reverse); got != 1 {
		t.Errorf("reverse map has %d entries, want 1 (the skipped span minted)", got)
	}
}

// leafContaining returns the leaf whose decoded value contains want and the
// offset of want inside it.
func leafContaining(t *testing.T, leaves []protocol.Leaf, want []byte) (protocol.Leaf, int) {
	t.Helper()
	for _, leaf := range leaves {
		if at := bytes.Index(leaf.Value, want); at >= 0 {
			return leaf, at
		}
	}
	t.Fatalf("no leaf contains %q", want)
	return protocol.Leaf{}, 0
}
