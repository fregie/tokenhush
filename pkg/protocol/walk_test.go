package protocol

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// wantLeaf is one expected leaf in document order.
type wantLeaf struct {
	path    string
	value   string
	encoded bool
}

// walkOK runs Walk and fails the test when it errors.
func walkOK(t *testing.T, doc string) []Leaf {
	t.Helper()
	leaves, err := Walk([]byte(doc))
	if err != nil {
		t.Fatalf("Walk(%q) error = %v, want nil", doc, err)
	}
	return leaves
}

// checkLeaves compares the walked leaves with want, in document order, and
// checks that every Length matches its Value.
func checkLeaves(t *testing.T, doc string, want []wantLeaf) {
	t.Helper()
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
		if got.Length != len(got.Value) {
			t.Errorf("Walk(%q) leaf %d Length = %d, want len(Value) = %d", doc, i, got.Length, len(got.Value))
		}
	}
}

func TestWalkNestedPathsInDocumentOrder(t *testing.T) {
	doc := `{"messages":[{"content":"first"},{"content":{"text":"second"}}],"top":"third"}`
	checkLeaves(t, doc, []wantLeaf{
		{path: "/messages/0/content", value: "first"},
		{path: "/messages/1/content/text", value: "second"},
		{path: "/top", value: "third"},
	})
}

func TestWalkRootString(t *testing.T) {
	checkLeaves(t, `"hello"`, []wantLeaf{{path: "", value: "hello"}})
}

func TestWalkIgnoresNonStringsAndNeverEmitsKeys(t *testing.T) {
	doc := `{"num":1,"flag":true,"nil":null,"kept":"value","arr":[2,false,null],"obj":{}}`
	checkLeaves(t, doc, []wantLeaf{{path: "/kept", value: "value"}})
}

func TestWalkPointerEscaping(t *testing.T) {
	doc := `{"a/b":"slash","c~d":"tilde","e~/f":"both"}`
	checkLeaves(t, doc, []wantLeaf{
		{path: "/a~1b", value: "slash"},
		{path: "/c~0d", value: "tilde"},
		{path: "/e~0~1f", value: "both"},
	})
}

func TestWalkRejectsTrailingData(t *testing.T) {
	docs := []string{
		`{"a":"b"} {"c":"d"}`,
		`{"a":"b"} garbage`,
		`"one" "two"`,
		`[1] 2`,
		`{"a":"first"} trailing`,
	}
	for _, doc := range docs {
		leaves, err := Walk([]byte(doc))
		if !errors.Is(err, ErrTrailingData) {
			t.Errorf("Walk(%q) error = %v, want ErrTrailingData", doc, err)
		}
		if leaves != nil {
			t.Errorf("Walk(%q) leaves = %+v, want nil", doc, leaves)
		}
	}
}

func TestWalkRejectsMalformedJSON(t *testing.T) {
	docs := []string{
		``,
		`   `,
		`{`,
		`{"a":`,
		`{"a" 1}`,
		`{"a":1 "b":2}`,
		`{"a":1,}`,
		`[1,`,
		`{]`,
		`nul`,
		`{"a":"first","b":`,
	}
	for _, doc := range docs {
		leaves, err := Walk([]byte(doc))
		if !errors.Is(err, ErrMalformedJSON) {
			t.Errorf("Walk(%q) error = %v, want ErrMalformedJSON", doc, err)
		}
		if leaves != nil {
			t.Errorf("Walk(%q) leaves = %+v, want nil (no partial results)", doc, leaves)
		}
	}
}

func TestWalkRejectsInvalidUTF8(t *testing.T) {
	docs := [][]byte{
		{'"', 0xff, '"'},
		[]byte("{\"a\":\"b\xc3\"}"),
		append([]byte(`{"a":"`), 0x80, '"', '}'),
	}
	for _, doc := range docs {
		leaves, err := Walk(doc)
		if !errors.Is(err, ErrNonUTF8) {
			t.Errorf("Walk(%q) error = %v, want ErrNonUTF8", doc, err)
		}
		if leaves != nil {
			t.Errorf("Walk(%q) leaves = %+v, want nil", doc, leaves)
		}
	}
}

func TestWalkNestingDepthBoundary(t *testing.T) {
	atLimit := strings.Repeat("[", MaxNestingDepth) + `"deep"` + strings.Repeat("]", MaxNestingDepth)
	leaves := walkOK(t, atLimit)
	if len(leaves) != 1 {
		t.Fatalf("Walk(depth %d) returned %d leaves, want 1", MaxNestingDepth, len(leaves))
	}
	if leaves[0].Value == nil || string(leaves[0].Value) != "deep" {
		t.Errorf("Walk(depth %d) value = %q, want %q", MaxNestingDepth, leaves[0].Value, "deep")
	}
	if wantPath := strings.Repeat("/0", MaxNestingDepth); leaves[0].Path != wantPath {
		t.Errorf("Walk(depth %d) path = %q, want %q", MaxNestingDepth, leaves[0].Path, wantPath)
	}

	overLimit := strings.Repeat("[", MaxNestingDepth+1) + `"deep"` + strings.Repeat("]", MaxNestingDepth+1)
	leaves, err := Walk([]byte(overLimit))
	if !errors.Is(err, ErrMaxDepth) {
		t.Errorf("Walk(depth %d) error = %v, want ErrMaxDepth", MaxNestingDepth+1, err)
	}
	if leaves != nil {
		t.Errorf("Walk(depth %d) leaves = %+v, want nil", MaxNestingDepth+1, leaves)
	}

	openOnly := strings.Repeat("[", MaxNestingDepth+1)
	if leaves, err := Walk([]byte(openOnly)); !errors.Is(err, ErrMaxDepth) || leaves != nil {
		t.Errorf("Walk(%d unclosed arrays) = (%+v, %v), want (nil, ErrMaxDepth)", MaxNestingDepth+1, leaves, err)
	}
}

// nestedString wraps s in levels successive JSON string encodings.
func nestedString(levels int, s string) string {
	for i := 0; i < levels; i++ {
		s = strconv.Quote(s)
	}
	return s
}

func TestWalkDecodesNestedJSONStrings(t *testing.T) {
	inner := `{"deep":"payload"}`
	mid := `{"mid":` + strconv.Quote(inner) + `}`
	doc := `{"outer":` + strconv.Quote(mid) + `}`
	checkLeaves(t, doc, []wantLeaf{
		{path: "/outer/mid/deep", value: "payload", encoded: true},
	})

	t.Run("ten physical levels", func(t *testing.T) {
		checkLeaves(t, nestedString(10, inner), []wantLeaf{
			{path: "/deep", value: "payload", encoded: true},
		})
	})
}

func TestWalkKeepsStringsWithoutStringLeaves(t *testing.T) {
	doc := `{"num":"123","arr":"[1,2]","empty":"{}","nonjson":"plain"}`
	checkLeaves(t, doc, []wantLeaf{
		{path: "/num", value: "123"},
		{path: "/arr", value: "[1,2]"},
		{path: "/empty", value: "{}"},
		{path: "/nonjson", value: "plain"},
	})
}

func TestWalkEncodedDepthLimit(t *testing.T) {
	payload := `{"k":"v"}`

	// A physical MaxEncodedDepth+1 chain cannot exist: every JSON string layer
	// escapes all quotes and backslashes of the layer below, so the encoded
	// bytes double per level (a 33-level chain is gigabytes). The boundary is
	// exercised at the exact helper call the walk makes for a string reached
	// with the given number of encoded boundaries already decoded.
	t.Run("budget remains decodes the wrapper", func(t *testing.T) {
		got := appendLeaf(nil, payload, "/p", false, MaxEncodedDepth-1, nil)
		if len(got) != 1 || got[0].Path != "/p/k" || string(got[0].Value) != "v" {
			t.Errorf("appendLeaf at depth %d = %+v, want one leaf /p/k = %q", MaxEncodedDepth-1, got, "v")
		}
	})

	t.Run("one past the limit stops literally", func(t *testing.T) {
		got := appendLeaf(nil, payload, "/p", false, MaxEncodedDepth, nil)
		if len(got) != 1 {
			t.Fatalf("appendLeaf at depth %d returned %d leaves, want 1: %+v", MaxEncodedDepth, len(got), got)
		}
		leaf := got[0]
		if leaf.Path != "/p" || string(leaf.Value) != payload || leaf.Encoded || leaf.Length != len(payload) {
			t.Errorf("appendLeaf at depth %d = %+v, want literal /p = %q with Encoded false",
				MaxEncodedDepth, leaf, payload)
		}
	})
}

func TestWalkKeepsBase64LookingLeaves(t *testing.T) {
	doc := `{"token":"c2VjcmV0","nested":{"b64":"eyJhIjoxfQ=="}}`
	checkLeaves(t, doc, []wantLeaf{
		{path: "/token", value: "c2VjcmV0"},
		{path: "/nested/b64", value: "eyJhIjoxfQ=="},
	})
}
