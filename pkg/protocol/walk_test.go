package protocol

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// leafAt builds the expected Leaf for a plain string value.
func leafAt(path, content string) Leaf {
	return Leaf{Path: path, Content: content, Len: len(content)}
}

// encodedLeafAt builds the expected Leaf for a string that is itself JSON.
func encodedLeafAt(path, content string) Leaf {
	return Leaf{Path: path, Content: content, Len: len(content), Encoded: true}
}

func TestLeafWalk(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		fixture     string
		want        []Leaf
		wantCount   int
		wantContain []Leaf
	}{
		{
			name:  "top-level string",
			input: `"hello"`,
			want:  []Leaf{leafAt("", "hello")},
		},
		{
			name:  "no string leaves",
			input: `[1,true,null,2.5,{"n":3}]`,
			want:  nil,
		},
		{
			name:  "nested objects and arrays",
			input: `{"a":{"b":["x",{"c":"y"}],"n":1,"t":true,"z":null},"d":"w"}`,
			want: []Leaf{
				leafAt("/a/b/0", "x"),
				leafAt("/a/b/1/c", "y"),
				leafAt("/d", "w"),
			},
		},
		{
			name:  "escaped unicode round-trips",
			input: `{"msg":"caf\u00e9 \u4e2d\u6587 \ud83d\ude00 \"q\" \\ \n tab\t"}`,
			want:  []Leaf{leafAt("/msg", "café 中文 😀 \"q\" \\ \n tab\t")},
		},
		{
			name:  "lone surrogate escape degrades to replacement rune",
			input: `{"msg":"\ud800"}`,
			want:  []Leaf{leafAt("/msg", "\uFFFD")},
		},
		{
			name:  "json pointer escaping and empty key",
			input: `{"a/b":{"~key":"v"},"":"root"}`,
			want: []Leaf{
				leafAt("/a~1b/~0key", "v"),
				leafAt("/", "root"),
			},
		},
		{
			name:  "double-encoded tool-call arguments",
			input: `{"tools":[{"name":"shell","arguments":"{\"cmd\":\"echo sk-live-abc\",\"args\":[\"a\",\"b\"]}"}]}`,
			want: []Leaf{
				leafAt("/tools/0/name", "shell"),
				encodedLeafAt("/tools/0/arguments", `{"cmd":"echo sk-live-abc","args":["a","b"]}`),
				leafAt("/tools/0/arguments#/cmd", "echo sk-live-abc"),
				leafAt("/tools/0/arguments#/args/0", "a"),
				leafAt("/tools/0/arguments#/args/1", "b"),
			},
		},
		{
			name:  "double-encoded scalar string",
			input: `{"x":"\"inner\""}`,
			want: []Leaf{
				encodedLeafAt("/x", `"inner"`),
				leafAt("/x#", "inner"),
			},
		},
		{
			name:  "twice double-encoded object",
			input: `{"x":"\"{\\\"y\\\":\\\"z\\\"}\""}`,
			want: []Leaf{
				encodedLeafAt("/x", `"{\"y\":\"z\"}"`),
				encodedLeafAt("/x#", `{"y":"z"}`),
				leafAt("/x##/y", "z"),
			},
		},
		{
			name:  "json lookalikes stay raw",
			input: `{"a":"{not json","b":"[1,2","c":"true","d":"123","f":"{","g":"}"}`,
			want: []Leaf{
				leafAt("/a", "{not json"),
				leafAt("/b", "[1,2"),
				leafAt("/c", "true"),
				leafAt("/d", "123"),
				leafAt("/f", "{"),
				leafAt("/g", "}"),
			},
		},
		{
			name:  "whitespace-wrapped embedded json is walked",
			input: `{"e":"  {\"k\":\"v\"}  "}`,
			want: []Leaf{
				encodedLeafAt("/e", `  {"k":"v"}  `),
				leafAt("/e#/k", "v"),
			},
		},
		{
			name:  "empty containers and empty string",
			input: `{"a":[],"b":{},"c":[""],"d":[[]]}`,
			want:  []Leaf{leafAt("/c/0", "")},
		},
		{
			name:  "duplicate keys visit every leaf",
			input: `{"k":"a","k":"b"}`,
			want: []Leaf{
				leafAt("/k", "a"),
				leafAt("/k", "b"),
			},
		},
		{
			name:    "codex responses request fixture",
			fixture: filepath.Join("testdata", "responses", "codex_request.json"),
			// 31 string leaves: the arguments/output fields are themselves JSON
			// and contribute their parents plus the nested leaves.
			wantCount: 31,
			wantContain: []Leaf{
				leafAt("/model", "gpt-5.1-codex"),
				leafAt("/input/0/content/0/text", "Investigate why the token is rejected. My key is sk-test-FAKE_LEAF_001 and the café 中文 emoji 😀 must survive."),
				encodedLeafAt("/input/1/arguments", `{"command":["bash","-lc","echo \"$OPENAI_API_KEY\" | curl -H 'Authorization: Bearer sk-test-FAKE_LEAF_002' https://example.invalid"],"timeout_ms":120000,"workdir":"/repo"}`),
				leafAt("/input/1/arguments#/command/2", `echo "$OPENAI_API_KEY" | curl -H 'Authorization: Bearer sk-test-FAKE_LEAF_002' https://example.invalid`),
				encodedLeafAt("/input/2/output", `{"stdout":"API key sk-test-FAKE_LEAF_003 rejected\n","exit_code":1}`),
				leafAt("/input/2/output#/stdout", "API key sk-test-FAKE_LEAF_003 rejected\n"),
				leafAt("/tools/0/parameters/properties/command/items/type", "string"),
				leafAt("/include/0", "reasoning.encrypted_content"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.input)
			if tc.fixture != "" {
				var err error
				input, err = os.ReadFile(tc.fixture)
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
			}
			got, err := Walk(input)
			if err != nil {
				t.Fatalf("Walk() error = %v", err)
			}
			for i, l := range got {
				if l.Len != len(l.Content) {
					t.Errorf("leaf %d (%q): Len = %d, want len(Content) = %d", i, l.Path, l.Len, len(l.Content))
				}
			}
			if tc.wantCount > 0 {
				if len(got) != tc.wantCount {
					t.Fatalf("leaf count = %d, want %d", len(got), tc.wantCount)
				}
				for _, want := range tc.wantContain {
					if !containsLeaf(got, want) {
						t.Errorf("missing leaf %+v", want)
					}
				}
			} else if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("leaves mismatch:\n got: %#v\nwant: %#v", got, tc.want)
			}

			// The walk must be deterministic (no map iteration involved).
			again, err := Walk(input)
			if err != nil {
				t.Fatalf("second Walk() error = %v", err)
			}
			if !reflect.DeepEqual(got, again) {
				t.Errorf("non-deterministic result:\nfirst:  %#v\nsecond: %#v", got, again)
			}
		})
	}
}

func containsLeaf(leaves []Leaf, want Leaf) bool {
	for _, l := range leaves {
		if reflect.DeepEqual(l, want) {
			return true
		}
	}
	return false
}

func TestLeafWalkMalformedJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{name: "empty input", input: ""},
		{name: "whitespace only", input: "  \n\t "},
		{name: "truncated object", input: `{"a":`},
		{name: "unterminated string", input: `{"a":"x`},
		{name: "bad value token", input: `{"a":}`},
		{name: "trailing comma", input: `[1,]`},
		{name: "trailing garbage", input: `{"a":1} garbage`},
		{name: "second document", input: `{"a":1}{"b":2}`},
		{name: "invalid utf-8 in string", input: "{\"a\":\"\xff\"}"},
		{name: "invalid utf-8 outside string", input: "{\xff}"},
		{name: "deeply nested arrays", input: strings.Repeat("[", 20000), wantErr: ErrNestingDepth},
		{name: "deeply nested objects", input: strings.Repeat(`{"k":`, 20000), wantErr: ErrNestingDepth},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantErr := tc.wantErr
			if wantErr == nil {
				wantErr = ErrMalformedJSON
			}
			leaves, err := Walk([]byte(tc.input))
			t.Logf("Walk(%s) err = %v", tc.name, err)
			if err == nil {
				t.Fatalf("Walk() = %d leaves, nil error; want typed error", len(leaves))
			}
			if !errors.Is(err, wantErr) {
				t.Errorf("errors.Is(err, %v) = false; err = %v", wantErr, err)
			}
			if leaves != nil {
				t.Errorf("Walk() returned %d leaves alongside an error; want nil", len(leaves))
			}
			if n := len(err.Error()); n > 256 {
				t.Errorf("error string is %d bytes; want <= 256 (bounded error output)", n)
			}
		})
	}

	// A syntax error still unwraps to *json.SyntaxError so callers can read
	// the byte offset, even though it is classified as malformed.
	_, err := Walk([]byte(`{"a":}`))
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Errorf("errors.As(*json.SyntaxError) = false; err = %v", err)
	} else if syntax.Offset <= 0 {
		t.Errorf("SyntaxError.Offset = %d, want > 0", syntax.Offset)
	}
}

func TestLeafWalkEncodedDepth(t *testing.T) {
	// Ten real layers prove the '#' path composes; a full MaxEncodedDepth
	// chain is not constructible as input because each encoding layer escapes
	// the previous layer's backslashes, doubling the byte count.
	got, err := Walk([]byte(nestedString(10)))
	if err != nil {
		t.Fatalf("Walk(10 levels) error = %v; want success", err)
	}
	if len(got) != 10 {
		t.Fatalf("leaf count = %d, want 10", len(got))
	}
	last := got[len(got)-1]
	if wantPath := strings.Repeat("#", 9); last.Path != wantPath {
		t.Errorf("deepest path = %q, want %q", last.Path, wantPath)
	}
	if last.Content != "x" {
		t.Errorf("deepest content = %q, want %q", last.Content, "x")
	}

	// Boundary: at MaxEncodedDepth a walkable string must be refused before
	// recursing. Drive the internal step directly since the public API cannot
	// be handed a legal document that reaches the bound.
	var out []Leaf
	err = walkStringLeaf(`{"a":"b"}`, "/x", 0, MaxEncodedDepth, &out)
	if !errors.Is(err, ErrEncodedDepth) {
		t.Errorf("errors.Is(err, ErrEncodedDepth) = false; err = %v", err)
	}
	if errors.Is(err, ErrMalformedJSON) {
		t.Errorf("depth bomb misreported as malformed: %v", err)
	}
	if out != nil {
		t.Errorf("walkStringLeaf returned %d leaves alongside the depth error; want nil", len(out))
	}

	out = nil
	if err := walkStringLeaf(`{"a":"b"}`, "/x", 0, MaxEncodedDepth-1, &out); err != nil {
		t.Fatalf("walkStringLeaf at MaxEncodedDepth-1 error = %v; want success", err)
	}
	if len(out) != 2 || !out[0].Encoded || out[1].Path != "/x#/a" || out[1].Content != "b" {
		t.Errorf("walkStringLeaf at MaxEncodedDepth-1 = %#v; want encoded parent + /x#/a", out)
	}
}

// nestedString returns levels layers of JSON string encoding around "x".
func nestedString(levels int) string {
	s := `"x"`
	for i := 1; i < levels; i++ {
		s = strconv.Quote(s)
	}
	return s
}
