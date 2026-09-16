package protocol

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// wantKey 描述一个期望的 KeySpan。
//
// raw 是键在原文中的转义形式（不含引号），doc 是 raw 所在的原文——顶层用例留空
// 表示用用例 input，双层编码叶内的键则显式填内层字符串内容。这样断言的是
// “data[RawStart:RawEnd] 逐字节等于期望的转义键文本”，而不是间接套用实现的算法。
type wantKey struct {
	path    string
	key     string
	raw     string
	doc     string
	encoded bool
}

func TestWalkKeys(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []wantKey
	}{
		{
			name:  "no_keys_in_array",
			input: `[1,true,null,2.5]`,
		},
		{
			name:  "empty_object",
			input: `{}`,
		},
		{
			name:  "top_level_string",
			input: `"hello"`,
		},
		{
			name:  "empty_object_value_yields_only_parent_key",
			input: `{"a":[],"b":{}}`,
			want: []wantKey{
				{path: "/a", key: "a", raw: "a"},
				{path: "/b", key: "b", raw: "b"},
			},
		},
		{
			name:  "top_level_keys",
			input: `{"a":1,"bb":2}`,
			want: []wantKey{
				{path: "/a", key: "a", raw: "a"},
				{path: "/bb", key: "bb", raw: "bb"},
			},
		},
		{
			name:  "nested_object_keys",
			input: `{"a":{"b":{"c":1}}}`,
			want: []wantKey{
				{path: "/a", key: "a", raw: "a"},
				{path: "/a/b", key: "b", raw: "b"},
				{path: "/a/b/c", key: "c", raw: "c"},
			},
		},
		{
			name:  "object_keys_inside_array",
			input: `{"arr":[{"k":1},{"m":2}]}`,
			want: []wantKey{
				{path: "/arr", key: "arr", raw: "arr"},
				{path: "/arr/0/k", key: "k", raw: "k"},
				{path: "/arr/1/m", key: "m", raw: "m"},
			},
		},
		{
			// 重复键不去重，按文档顺序全部返回。
			name:  "duplicate_keys_returned_in_document_order",
			input: `{"k":"a","k":"b"}`,
			want: []wantKey{
				{path: "/k", key: "k", raw: "k"},
				{path: "/k", key: "k", raw: "k"},
			},
		},
		{
			// Path 按 RFC 6901 转义 ~ 与 /；Key 保留解码后的原字符。
			name:  "escaped_keys_use_rfc6901_pointer_escaping",
			input: `{"a/b":1,"a~b":2,"q\"k":3}`,
			want: []wantKey{
				{path: "/a~1b", key: "a/b", raw: "a/b"},
				{path: "/a~0b", key: "a~b", raw: "a~b"},
				{path: `/q"k`, key: `q"k`, raw: `q\"k`},
			},
		},
		{
			// Key 是解码后的字符串，raw 是原始转义形式（含 \uXXXX 字面量）。
			name:  "unicode_keys_decode_but_raw_stays_escaped",
			input: `{"中文":"v","caf\u00e9":1}`,
			want: []wantKey{
				{path: "/中文", key: "中文", raw: "中文"},
				{path: "/café", key: "café", raw: `caf\u00e9`},
			},
		},
		{
			// 顶层就是一个编码字符串：全部键落在 "#" 之后的内部文档里。
			name:  "top_level_encoded_string",
			input: `"{\"a\":1}"`,
			want: []wantKey{
				{path: "#/a", key: "a", raw: "a", doc: `{"a":1}`, encoded: true},
			},
		},
		{
			// 键在双层编码字符串内：Path 用 "#" 组合；RawStart/RawEnd 相对
			// 内层内容（最近一层被解码的字符串），不是相对 data。
			name:  "keys_inside_double_encoded_string_leaf",
			input: `{"tools":[{"name":"shell","arguments":"{\"cmd\":\"echo\",\"nested\":{\"deep\":1}}"}]}`,
			want: []wantKey{
				{path: "/tools", key: "tools", raw: "tools"},
				{path: "/tools/0/name", key: "name", raw: "name"},
				{path: "/tools/0/arguments", key: "arguments", raw: "arguments"},
				{path: "/tools/0/arguments#/cmd", key: "cmd", raw: "cmd", doc: `{"cmd":"echo","nested":{"deep":1}}`, encoded: true},
				{path: "/tools/0/arguments#/nested", key: "nested", raw: "nested", doc: `{"cmd":"echo","nested":{"deep":1}}`, encoded: true},
				{path: "/tools/0/arguments#/nested/deep", key: "deep", raw: "deep", doc: `{"cmd":"echo","nested":{"deep":1}}`, encoded: true},
			},
		},
		{
			// 两层编码（外层字符串 -> 内层字符串 -> 对象）：'#' 应当叠加成 "##"。
			name:  "twice_double_encoded_key",
			input: `{"x":"\"{\\\"y\\\":\\\"z\\\"}\""}`,
			want: []wantKey{
				{path: "/x", key: "x", raw: "x"},
				{path: "/x##/y", key: "y", raw: "y", doc: `{"y":"z"}`, encoded: true},
			},
		},
		{
			// 值看着像 JSON 但不可 walk（true/123/{not json）时不下沉；只有
			// 真正可 walk 的字符串值才贡献内部键。
			name:  "json_lookalike_values_are_not_descended",
			input: `{"a":"{not json","b":"true","c":"123","d":"{\"real\":1}"}`,
			want: []wantKey{
				{path: "/a", key: "a", raw: "a"},
				{path: "/b", key: "b", raw: "b"},
				{path: "/c", key: "c", raw: "c"},
				{path: "/d", key: "d", raw: "d"},
				{path: "/d#/real", key: "real", raw: "real", doc: `{"real":1}`, encoded: true},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.input)
			got, err := WalkKeys(data)
			if err != nil {
				t.Fatalf("WalkKeys() error = %v", err)
			}
			if len(tc.want) == 0 {
				if got != nil {
					t.Fatalf("WalkKeys() = %#v; want nil for a document with no object keys", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("key count = %d, want %d\ngot: %#v", len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				doc := tc.input
				if w.doc != "" {
					doc = w.doc
				}
				ks := got[i]
				if ks.Path != w.path {
					t.Errorf("key %d Path = %q, want %q", i, ks.Path, w.path)
				}
				if ks.Key != w.key {
					t.Errorf("key %d (%s) Key = %q, want %q", i, w.path, ks.Key, w.key)
				}
				if ks.Encoded != w.encoded {
					t.Errorf("key %d (%s) Encoded = %v, want %v", i, w.path, ks.Encoded, w.encoded)
				}
				if ks.RawStart < 0 || ks.RawEnd < ks.RawStart || ks.RawEnd > len(doc) {
					t.Errorf("key %d (%s) raw span [%d,%d) out of range for a %d-byte document",
						i, w.path, ks.RawStart, ks.RawEnd, len(doc))
					continue
				}
				if raw := doc[ks.RawStart:ks.RawEnd]; raw != w.raw {
					t.Errorf("key %d (%s) raw = %q, want %q", i, w.path, raw, w.raw)
				}
			}

			// 遍历必须确定性（无 map 迭代）。
			again, err := WalkKeys(data)
			if err != nil {
				t.Fatalf("second WalkKeys() error = %v", err)
			}
			if !reflect.DeepEqual(got, again) {
				t.Errorf("non-deterministic result:\nfirst:  %#v\nsecond: %#v", got, again)
			}
		})
	}
}

// TestWalkKeysRawSpanExcludesQuotes 用真实换行/缩进钉死 raw span 的数值边界：
// 覆盖范围是键的转义形式本体，不含两侧引号。
func TestWalkKeysRawSpanExcludesQuotes(t *testing.T) {
	input := []byte("{\n  \"a\\u0041\" : 1,\n  \"b/c\" : 2\n}")
	got, err := WalkKeys(input)
	if err != nil {
		t.Fatalf("WalkKeys() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("key count = %d, want 2", len(got))
	}

	if got[0].RawStart != 5 || got[0].RawEnd != 12 {
		t.Errorf("first key raw span = [%d,%d), want [5,12)", got[0].RawStart, got[0].RawEnd)
	}
	if raw := string(input[got[0].RawStart:got[0].RawEnd]); raw != `a\u0041` {
		t.Errorf("first key raw = %q, want %q", raw, `a\u0041`)
	}
	if got[0].Key != "aA" {
		t.Errorf("first key Key = %q, want %q", got[0].Key, "aA")
	}
	if got[0].Path != "/aA" {
		t.Errorf("first key Path = %q, want %q", got[0].Path, "/aA")
	}

	if got[1].RawStart != 22 || got[1].RawEnd != 25 {
		t.Errorf("second key raw span = [%d,%d), want [22,25)", got[1].RawStart, got[1].RawEnd)
	}
	if raw := string(input[got[1].RawStart:got[1].RawEnd]); raw != "b/c" {
		t.Errorf("second key raw = %q, want %q", raw, "b/c")
	}
	if got[1].Path != "/b~1c" {
		t.Errorf("second key Path = %q, want %q", got[1].Path, "/b~1c")
	}
}

// TestWalkKeysEncodedOffsetsAreRelativeToInnerContent 显式钉死坐标空间：
// Encoded=true 时 RawStart/RawEnd 相对最近一层被解码的字符串内容，而不是 data。
func TestWalkKeysEncodedOffsetsAreRelativeToInnerContent(t *testing.T) {
	input := []byte(`{"pad":"aaaaaaaaaaaaaaaaaaaa","o":"{\"key1\":1}"}`)
	const inner = `{"key1":1}`

	got, err := WalkKeys(input)
	if err != nil {
		t.Fatalf("WalkKeys() error = %v", err)
	}
	var innerKey *KeySpan
	for i := range got {
		if got[i].Path == "/o#/key1" {
			innerKey = &got[i]
		}
	}
	if innerKey == nil {
		t.Fatalf("missing /o#/key1 in %#v", got)
	}
	if !innerKey.Encoded {
		t.Errorf("Encoded = false; want true for a key inside an encoded leaf")
	}
	if raw := inner[innerKey.RawStart:innerKey.RawEnd]; raw != "key1" {
		t.Errorf("inner[RawStart:RawEnd] = %q, want %q", raw, "key1")
	}
	// 若误把内层偏移当外层偏移，data 上同一区间不会是 "key1"。
	if raw := string(input[innerKey.RawStart:innerKey.RawEnd]); raw == "key1" {
		t.Errorf("data[RawStart:RawEnd] = %q (inner-relative offsets would be ambiguous)", raw)
	}
	if innerKey.RawEnd > len(inner) {
		t.Errorf("RawEnd = %d exceeds inner content length %d", innerKey.RawEnd, len(inner))
	}
}

func TestWalkKeysErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{name: "empty_input", input: ""},
		{name: "whitespace_only", input: "  \n\t "},
		// 尾随损坏：前面已有若干合法键，仍必须整体失败且不返回部分结果。
		{name: "truncated_after_valid_keys", input: `{"a":1,"b":2,"c":`},
		{name: "trailing_data_after_valid_keys", input: `{"a":1,"b":2} garbage`},
		{name: "second_document_after_valid_keys", input: `{"a":1,"b":2}{"c":3}`},
		{name: "invalid_utf8_after_valid_keys", input: "{\"a\":1,\"b\":\"\xff\"}"},
		{name: "deeply_nested_arrays", input: strings.Repeat("[", 20000), wantErr: ErrNestingDepth},
		// 嵌套炸弹：深度超限前已产出大量键，仍须返回 nil。
		{name: "deeply_nested_objects", input: strings.Repeat(`{"k":`, 20000), wantErr: ErrNestingDepth},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantErr := tc.wantErr
			if wantErr == nil {
				wantErr = ErrMalformedJSON
			}
			keys, err := WalkKeys([]byte(tc.input))
			t.Logf("WalkKeys(%s) err = %v", tc.name, err)
			if err == nil {
				t.Fatalf("WalkKeys() = %d keys, nil error; want typed error", len(keys))
			}
			if !errors.Is(err, wantErr) {
				t.Errorf("errors.Is(err, %v) = false; err = %v", wantErr, err)
			}
			if keys != nil {
				t.Errorf("WalkKeys() returned %d keys alongside an error; want nil (no partial results)", len(keys))
			}
			if n := len(err.Error()); n > 256 {
				t.Errorf("error string is %d bytes; want <= 256 (bounded error output)", n)
			}
		})
	}

	// 语法错误仍可 unwrap 出 *json.SyntaxError，与 Walk 的错误形状一致。
	_, err := WalkKeys([]byte(`{"a":}`))
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Errorf("errors.As(*json.SyntaxError) = false; err = %v", err)
	} else if syntax.Offset <= 0 {
		t.Errorf("SyntaxError.Offset = %d, want > 0", syntax.Offset)
	}
}

// TestWalkKeysNoPartialResultsOnMalformedTail 显式钉死“无部分结果”：
// 尾部损坏的文档在前面已含多个合法键时，仍必须返回 nil 切片并报错。
func TestWalkKeysNoPartialResultsOnMalformedTail(t *testing.T) {
	input := []byte(`{"a":1,"b":{"c":2},"d":[{"e":3}],"f":`)
	keys, err := WalkKeys(input)
	t.Logf("WalkKeys(%q) -> len(keys)=%d err=%v", input, len(keys), err)
	if err == nil {
		t.Fatalf("WalkKeys() = %d keys, nil error; want ErrMalformedJSON", len(keys))
	}
	if !errors.Is(err, ErrMalformedJSON) {
		t.Errorf("errors.Is(err, ErrMalformedJSON) = false; err = %v", err)
	}
	if keys != nil {
		t.Errorf("keys = %#v; want nil (a valid prefix must not leak partial results)", keys)
	}
}

func TestWalkKeysEncodedDepth(t *testing.T) {
	// 与 Walk 相同：在 MaxEncodedDepth 处必须拒绝继续下沉，且不产出部分键。
	var out []KeySpan
	err := walkKeysString(`{"a":"b"}`, "/x", 0, MaxEncodedDepth, &out)
	if !errors.Is(err, ErrEncodedDepth) {
		t.Errorf("errors.Is(err, ErrEncodedDepth) = false; err = %v", err)
	}
	if errors.Is(err, ErrMalformedJSON) {
		t.Errorf("encoded depth bomb misreported as malformed: %v", err)
	}
	if out != nil {
		t.Errorf("walkKeysString returned %d keys alongside the depth error; want nil", len(out))
	}

	out = nil
	if err := walkKeysString(`{"a":"b"}`, "/x", 0, MaxEncodedDepth-1, &out); err != nil {
		t.Fatalf("walkKeysString at MaxEncodedDepth-1 error = %v; want success", err)
	}
	if len(out) != 1 {
		t.Fatalf("key count = %d, want 1 (%#v)", len(out), out)
	}
	if out[0].Path != "/x#/a" || out[0].Key != "a" || !out[0].Encoded {
		t.Errorf("walkKeysString at MaxEncodedDepth-1 = %#v; want encoded /x#/a", out[0])
	}
	if raw := `{"a":"b"}`[out[0].RawStart:out[0].RawEnd]; raw != "a" {
		t.Errorf("inner raw = %q, want %q", raw, "a")
	}
}
