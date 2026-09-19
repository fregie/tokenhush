package protocol

import (
	"strings"
	"testing"
)

// identityLeafByPath returns the single leaf at path, failing the test when it
// is absent or ambiguous.
func identityLeafByPath(t *testing.T, leaves []Leaf, path string) Leaf {
	t.Helper()
	var found []Leaf
	for _, l := range leaves {
		if l.Path == path {
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		t.Fatalf("leaves at %q = %d, want exactly 1: %+v", path, len(found), leaves)
	}
	return found[0]
}

// TestWalkIdentityIncludesPrecedingScalarMembers pins D1: a leaf's Identity
// starts with its Path and captures every enclosing frame's preceding
// non-string scalar members rendered name=rawValue from the raw document text.
// The OpenAI tool-call chunk is the incident channel: two distinct `index`
// scalars precede the arguments string.
func TestWalkIdentityIncludesPrecedingScalarMembers(t *testing.T) {
	doc := `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"type":"function","function":{"name":"bash","arguments":"alpha"}}]}}]}`
	leaf := identityLeafByPath(t, walkOK(t, doc), "/choices/0/delta/tool_calls/0/function/arguments")
	if !leaf.Identifiable {
		t.Fatalf("leaf %q is not Identifiable; Identity = %q", leaf.Path, leaf.Identity)
	}
	if !strings.HasPrefix(leaf.Identity, leaf.Path) {
		t.Fatalf("Identity = %q, want prefix %q", leaf.Identity, leaf.Path)
	}
	if !strings.Contains(leaf.Identity, "index=0") {
		t.Fatalf("Identity = %q, want the preceding scalar rendered as index=0", leaf.Identity)
	}
}

// TestWalkIdentityDistinguishesSameArrayPosition is the D1/F2 counterexample:
// two documents differ only in the non-string scalar `index` of the object that
// encloses the target leaf, and both leaves sit at the same array position
// tool_calls[0]. Path is therefore identical; only the captured scalar makes
// the Identity differ, which is what prevents cross-logical-call stitching.
func TestWalkIdentityDistinguishesSameArrayPosition(t *testing.T) {
	docA := `{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"frag-a"}}]}}]}`
	docB := `{"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"frag-a"}}]}}]}`
	const path = "/choices/0/delta/tool_calls/0/function/arguments"

	leafA := identityLeafByPath(t, walkOK(t, docA), path)
	leafB := identityLeafByPath(t, walkOK(t, docB), path)

	if leafA.Path != leafB.Path {
		t.Fatalf("paths differ: %q vs %q", leafA.Path, leafB.Path)
	}
	if !leafA.Identifiable || !leafB.Identifiable {
		t.Fatalf("Identifiable = (%v, %v), want both true", leafA.Identifiable, leafB.Identifiable)
	}
	if !strings.Contains(leafA.Identity, "index=0") || !strings.Contains(leafB.Identity, "index=1") {
		t.Fatalf("identities do not carry their own index: A=%q B=%q", leafA.Identity, leafB.Identity)
	}
	if leafA.Identity == leafB.Identity {
		t.Fatalf("Identity collision at the same array position: %q", leafA.Identity)
	}
}

// TestWalkLeafSetGolden pins the observable leaf set against the additive
// identity fields: only string-value leaves, in document order, with Encoded
// true for the nested-JSON inner leaf. Identity is deliberately ignored here so
// this test keeps passing once the identity API lands.
func TestWalkLeafSetGolden(t *testing.T) {
	doc := `{"msg":"plain","arr":["a","b"],"nested":{"k":"v"},"inner":"{\"deep\":\"payload\"}"}`
	want := []wantLeaf{
		{path: "/msg", value: "plain"},
		{path: "/arr/0", value: "a"},
		{path: "/arr/1", value: "b"},
		{path: "/nested/k", value: "v"},
		{path: "/inner/deep", value: "payload", encoded: true},
	}
	leaves := walkOK(t, doc)
	if len(leaves) != len(want) {
		t.Fatalf("Walk(%q) returned %d leaves, want %d: %+v", doc, len(leaves), len(want), leaves)
	}
	for i, w := range want {
		got := leaves[i]
		if got.Path != w.path || string(got.Value) != w.value || got.Encoded != w.encoded {
			t.Errorf("Walk(%q) leaf %d = {Path:%q Value:%q Encoded:%v}, want {Path:%q Value:%q Encoded:%v}",
				doc, i, got.Path, got.Value, got.Encoded, w.path, w.value, w.encoded)
		}
	}
}

// TestWalkIdentityOpaqueWhenOverCap pins D1's cap: when an enclosing frame's
// preceding non-string scalar raw text pushes Identity past maxIdentityBytes,
// the leaf is not Identifiable. Only non-string scalars are captured, so the
// long preceding token is a number literal (magnitude ~1 to stay in float64
// range), never a string.
func TestWalkIdentityOpaqueWhenOverCap(t *testing.T) {
	// A ~2 KiB number token: raw length is 2 + 2*maxIdentityBytes, comfortably
	// past the cap once combined with the path and separator bytes.
	longNumber := "1." + strings.Repeat("1", maxIdentityBytes*2)
	doc := `{"index":` + longNumber + `,"function":{"arguments":"alpha"}}`
	leaf := identityLeafByPath(t, walkOK(t, doc), "/function/arguments")
	if len(leaf.Identity) <= maxIdentityBytes {
		t.Fatalf("Identity = %d bytes, want > cap %d for this fixture", len(leaf.Identity), maxIdentityBytes)
	}
	if leaf.Identifiable {
		t.Fatalf("Identifiable = true for Identity of %d bytes (cap %d)", len(leaf.Identity), maxIdentityBytes)
	}
}
