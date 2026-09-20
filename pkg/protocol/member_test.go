package protocol

import "testing"

// TestWalkLeafDistinguishesObjectKeyFromArrayIndex pins the member
// discriminator: an object member and an array element can share a Path, so
// only Member/Key tell them apart.
func TestWalkLeafDistinguishesObjectKeyFromArrayIndex(t *testing.T) {
	object := walkOK(t, `{"0":"x"}`)
	array := walkOK(t, `["x"]`)
	if len(object) != 1 || len(array) != 1 {
		t.Fatalf("Walk leaf counts = (%d, %d), want (1, 1)", len(object), len(array))
	}
	objLeaf, arrLeaf := object[0], array[0]
	if objLeaf.Path != arrLeaf.Path {
		t.Fatalf("object leaf Path = %q, array leaf Path = %q, want identical paths", objLeaf.Path, arrLeaf.Path)
	}
	if !objLeaf.Member {
		t.Errorf("object leaf Member = false, want true")
	}
	if arrLeaf.Member {
		t.Errorf("array leaf Member = true, want false")
	}
	if objLeaf.Key != "0" || arrLeaf.Key != "" {
		t.Errorf("object leaf Key = %q, array leaf Key = %q, want (%q, %q)", objLeaf.Key, arrLeaf.Key, "0", "")
	}
}

// TestWalkLeafKeyForEncodedNestedDocument pins that a leaf reached by decoding
// a JSON-string wrapper still carries its immediate member key.
func TestWalkLeafKeyForEncodedNestedDocument(t *testing.T) {
	doc := `{"wrapper":"{\"inner\":\"x\"}"}`
	leaves := walkOK(t, doc)
	if len(leaves) != 1 {
		t.Fatalf("Walk(%q) returned %d leaves, want 1: %+v", doc, len(leaves), leaves)
	}
	leaf := leaves[0]
	if !leaf.Encoded {
		t.Errorf("Walk(%q) leaf Encoded = false, want true", doc)
	}
	if !leaf.Member {
		t.Errorf("Walk(%q) leaf Member = false, want true", doc)
	}
	if leaf.Key != "inner" {
		t.Errorf("Walk(%q) leaf Key = %q, want %q", doc, leaf.Key, "inner")
	}
}
