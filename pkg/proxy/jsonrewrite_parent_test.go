package proxy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// TestLeafRewriterEncodedParentSwallowsOnlyItsOwnLeaves pins the W6.3/W6.1
// encoded-parent replacement rule: replacing an Encoded parent must consume
// exactly its own nested leaves and advance the terminal ordinal by the number
// of non-Encoded leaves in that run.
//
// The body deliberately carries a sibling key literally named "x#y". Because
// escapePointer does not escape '#', its leaf path "/x#y" shares the "/x#"
// prefix of the encoded parent "/x", so a prefix-scan implementation would
// swallow the sibling (or desync and error). The ordinal in the edited sibling
// value proves terminalIdx advanced by exactly one.
func TestLeafRewriterEncodedParentSwallowsOnlyItsOwnLeaves(t *testing.T) {
	src := []byte(`{"x":"{\"a\":\"b\"}","x#y":"SIBLING"}`)
	walked, err := protocol.Walk(src)
	if err != nil {
		t.Fatalf("protocol.Walk: %v", err)
	}
	if len(walked) != 3 || !walked[0].Encoded || walked[0].Path != "/x" ||
		walked[1].Path != "/x#/a" || walked[2].Path != "/x#y" {
		t.Fatalf("test setup: unexpected walk %+v", walked)
	}

	rw := &leafRewriter{
		walked: walked,
		edit: func(terminalIdx int, path string, content []byte) ([]byte, bool) {
			if path == "/x#y" {
				return []byte(fmt.Sprintf("EDITED_%d", terminalIdx)), true
			}
			return content, false
		},
		parentEdit: func(encodedIdx int, path string, content []byte) ([]byte, bool) {
			if encodedIdx == 0 && path == "/x" {
				return []byte("REPLACED"), true
			}
			return content, false
		},
	}

	out, changed, err := rw.rewrite(src, "")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !changed {
		t.Fatal("rewrite reported changed = false")
	}

	var got struct {
		X   string `json:"x"`
		Sib string `json:"x#y"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("rewritten body is not the expected JSON: %s", out)
	}
	if got.X != "REPLACED" {
		t.Errorf("x = %q, want REPLACED", got.X)
	}
	if got.Sib != "EDITED_1" {
		t.Errorf("x#y = %q, want EDITED_1 (a prefix scan would swallow the sibling or desync)", got.Sib)
	}
}
