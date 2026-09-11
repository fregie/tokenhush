package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxEncodedDepth bounds how many nested double-encoded JSON strings a single
// Walk call follows. Real tool-call arguments need one or two levels; the
// bound stops adversarial strings such as "\"\\\"…\"" from recursing forever.
const MaxEncodedDepth = 32

// MaxNestingDepth bounds how deeply Walk descends into objects and arrays.
// json.Decoder.Token, unlike json.Unmarshal, has no built-in nesting cap, so
// the walker enforces its own before the goroutine stack is at risk. The value
// matches encoding/json's internal limit, keeping accepted documents aligned
// with the standard library.
const MaxNestingDepth = 10000

var (
	// ErrMalformedJSON reports that the input is not a single well-formed JSON
	// document (syntax error, trailing data, or invalid UTF-8). Errors wrapping
	// it also wrap the underlying *json.SyntaxError where one exists, so
	// callers can recover byte offsets with errors.As.
	ErrMalformedJSON = errors.New("protocol: malformed JSON")
	// ErrEncodedDepth reports that a string leaf was itself valid JSON nested
	// more than MaxEncodedDepth double-encoded boundaries deep.
	ErrEncodedDepth = errors.New("protocol: double-encoded JSON exceeds MaxEncodedDepth")
	// ErrNestingDepth reports that the document nests objects/arrays more than
	// MaxNestingDepth deep. Walk refuses rather than risk unbounded recursion.
	ErrNestingDepth = errors.New("protocol: JSON nesting exceeds MaxNestingDepth")
)

// Leaf is one JSON string value located by Walk.
//
// Path is an RFC 6901 JSON Pointer from the root of the outer document.
// Inside a double-encoded string the boundary is written as '#' followed by a
// JSON Pointer into the embedded document, e.g. /input/1/arguments#/command/2.
// The root of a document is the empty path.
//
// Content is the decoded Go string: JSON escapes (\" \\ \n \uXXXX) are
// resolved, so Content round-trips exactly to the original string value.
// Len is len(Content) in bytes.
//
// Encoded reports that Content is itself a JSON object, array, or string that
// was walked; that leaf's nested leaves follow it immediately in Walk's
// result. Consumers that scan raw text for secrets should skip Encoded parents
// when the nested leaves are present to avoid double-counting the same bytes.
type Leaf struct {
	Path    string
	Content string
	Len     int
	Encoded bool
}

// Walk parses data as one JSON document and returns every string leaf in
// document order. Objects and arrays are traversed recursively; a string whose
// content is itself a JSON object, array, or string is traversed as an inner
// document up to MaxEncodedDepth levels, and its leaves carry the composite
// '#' path described on Leaf.
//
// Non-string scalars (numbers, booleans, null) are not leaves. On any error
// Walk returns a nil slice: ErrMalformedJSON for invalid UTF-8, syntax errors,
// or trailing data; ErrNestingDepth beyond MaxNestingDepth; and ErrEncodedDepth
// when the double-encoded nesting bound is exceeded. Walk never panics on
// malformed input.
func Walk(data []byte) ([]Leaf, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: input is not valid UTF-8", ErrMalformedJSON)
	}
	var leaves []Leaf
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkValue(dec, "", 0, 0, &leaves); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after top-level JSON value", ErrMalformedJSON)
	}
	return leaves, nil
}

// walkValue consumes one JSON value from dec, appending its string leaves.
// depth counts object/array nesting, encDepth the double-encoded boundaries.
func walkValue(dec *json.Decoder, path string, depth, encDepth int, out *[]Leaf) error {
	if depth > MaxNestingDepth {
		return fmt.Errorf("%w: depth %d", ErrNestingDepth, depth)
	}
	tok, err := dec.Token()
	if err != nil {
		return malformed("read token", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		return walkContainer(dec, t, path, depth, encDepth, out)
	case string:
		return walkStringLeaf(t, path, depth, encDepth, out)
	default:
		// Numbers, booleans, and null are not string leaves.
		return nil
	}
}

// walkContainer consumes the remaining values of an object or array started by
// delim, recursing into every element.
func walkContainer(dec *json.Decoder, delim json.Delim, path string, depth, encDepth int, out *[]Leaf) error {
	switch delim {
	case '{':
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return malformed("read object key", err)
			}
			key, ok := keyTok.(string)
			if !ok {
				return malformed("object key is not a string", nil)
			}
			if err := walkValue(dec, path+"/"+escapePointer(key), depth+1, encDepth, out); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return malformed("read object end", err)
		}
		return nil
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkValue(dec, path+"/"+strconv.Itoa(i), depth+1, encDepth, out); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return malformed("read array end", err)
		}
		return nil
	default:
		return malformed("unexpected delimiter", nil)
	}
}

// walkStringLeaf records one string value and, when that value is itself a JSON
// document worth descending into, walks the embedded document.
func walkStringLeaf(content, path string, depth, encDepth int, out *[]Leaf) error {
	encoded := walkableJSON(content)
	if !encoded {
		*out = append(*out, Leaf{Path: path, Content: content, Len: len(content)})
		return nil
	}
	if encDepth >= MaxEncodedDepth {
		return fmt.Errorf("%w: depth %d", ErrEncodedDepth, encDepth)
	}
	*out = append(*out, Leaf{Path: path, Content: content, Len: len(content), Encoded: true})
	inner := json.NewDecoder(strings.NewReader(content))
	inner.UseNumber()
	return walkValue(inner, path+"#", depth+1, encDepth+1, out)
}

// walkableJSON reports whether s is a JSON object, array, or string that a
// string leaf may descend into. Numbers, booleans, and null are deliberately
// excluded: descending into them can never expose further string leaves.
func walkableJSON(s string) bool {
	i := 0
	for i < len(s) && isJSONSpace(s[i]) {
		i++
	}
	if i == len(s) {
		return false
	}
	switch s[i] {
	case '{', '[', '"':
	default:
		return false
	}
	return json.Valid([]byte(s))
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// escapePointer encodes one JSON Pointer reference token per RFC 6901 §3.
func escapePointer(token string) string {
	if !strings.ContainsAny(token, "~/") {
		return token
	}
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}

// malformed wraps a low-level decoder failure in ErrMalformedJSON.
func malformed(context string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrMalformedJSON, context)
	}
	return fmt.Errorf("%w: %s: %w", ErrMalformedJSON, context, err)
}
