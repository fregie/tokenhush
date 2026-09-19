// Package protocol is the wire-format substrate shared by the detection and
// redaction layers: it turns JSON documents into a flat leaf model and never
// normalises or decodes encodings on its own.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxNestingDepth bounds the object/array nesting Walk accepts: exactly this
// depth is fine, one level more fails with ErrMaxDepth.
const MaxNestingDepth = 10000

// MaxEncodedDepth bounds how many JSON-encoded string wrappers Walk decodes
// before it stops and emits the remaining value literally instead of failing.
const MaxEncodedDepth = 32

// Walk sentinels, all errors.Is-comparable. On any of them Walk returns no
// leaves: errors never come with partial results.
var (
	ErrMalformedJSON = errors.New("protocol: malformed JSON")
	ErrTrailingData  = errors.New("protocol: trailing data after JSON value")
	ErrNonUTF8       = errors.New("protocol: input is not valid UTF-8")
	ErrMaxDepth      = errors.New("protocol: JSON nesting exceeds MaxNestingDepth")
)

// Leaf is one JSON string value found by Walk.
type Leaf struct {
	Path    string // RFC 6901 JSON Pointer, e.g. /messages/0/content
	Value   []byte // decoded string bytes (JSON escapes resolved), not the raw spelling
	Length  int    // len(Value)
	Encoded bool   // true when reached by decoding a JSON-encoded string

	// Identity is the channel discriminator: Path, then each enclosing frame's
	// preceding non-string scalar members rendered name=rawValue, then the
	// leaf's occurrence among same-Path leaves. Identifiable is false when the
	// canonical identity exceeds maxIdentityBytes; it is never truncated.
	Identity     string
	Identifiable bool

	tok *rawToken // raw location; nil for hand-built or plugin leaves
}

// frame is one open object or array in the non-recursive walk.
type frame struct {
	object  bool
	key     string
	hasKey  bool
	index   int
	seg     string
	scalars []frameScalar // preceding non-string scalar members of this frame
}

// Walk collects every JSON string value in data as a Leaf.
//
// Semantics, pinned by the tests:
//   - Leaves are string values only; numbers, booleans and null are ignored
//     and object keys are never emitted, so key-position blocking is dropped
//     by design.
//   - Paths are RFC 6901 pointers ("~" renders "~0", "/" renders "~1", array
//     elements contribute their index).
//   - A string whose content parses as JSON and yields at least one string
//     leaf is not emitted itself: its inner leaves are emitted instead, with
//     Encoded true and paths prefixed by the wrapper's pointer.
//   - Recursion stops once MaxEncodedDepth wrappers are decoded; the value at
//     the limit is emitted literally with Encoded false.
//   - Nothing is decoded here: a base64-looking leaf is returned
//     byte-identical.
func Walk(data []byte) ([]Leaf, error) {
	if !utf8.Valid(data) {
		return nil, ErrNonUTF8
	}
	return walkDocument(data, "", false, 0, nil, &walkContext{})
}

// walkDocument walks one whole JSON document at data, honouring a base
// pointer, an encoded flag, the encoded-string recursion depth, the wrapper
// token enclosing is set to (nil at the root) and the identity context wc.
func walkDocument(data []byte, base string, encoded bool, depth int, enclosing *rawToken, wc *walkContext) ([]Leaf, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	leaves, err := walkValue(dec, data, base, encoded, depth, enclosing, wc)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrTrailingData
	}
	return leaves, nil
}

// walkValue consumes exactly one JSON value from dec. Open containers live in
// an explicit stack, so nesting is bounded by MaxNestingDepth rather than by
// the goroutine stack and Walk cannot panic on deep input. data is the
// document the decoder reads; every string token is located in it so its raw
// spelling can be recovered later. enclosing is the wrapper token whose
// decoded value is this document.
func walkValue(dec *json.Decoder, data []byte, base string, encoded bool, depth int, enclosing *rawToken, wc *walkContext) ([]Leaf, error) {
	var (
		stack []frame
		out   []Leaf
	)
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return nil, tokenError(err)
		}
		end := dec.InputOffset()
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if len(stack) >= MaxNestingDepth {
					return nil, ErrMaxDepth
				}
				seg := childSegment(stack)
				advance(stack)
				stack = append(stack, frame{object: delim == '{', seg: seg})
				continue
			case '}', ']':
				if len(stack) == 0 {
					return nil, ErrMalformedJSON
				}
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					return out, nil
				}
				continue
			}
		}
		if len(stack) == 0 {
			if raw, ok := tok.(string); ok {
				out = appendLeaf(out, raw, base, encoded, depth, tokenNode(data, int(start), int(end), enclosing), wc.child(nil))
			}
			return out, nil
		}
		top := &stack[len(stack)-1]
		if top.object && !top.hasKey {
			raw, ok := tok.(string)
			if !ok {
				return nil, ErrMalformedJSON
			}
			top.key, top.hasKey = raw, true
			continue
		}
		seg := childSegment(stack)
		name := memberName(stack)
		advance(stack)
		if raw, ok := tok.(string); ok {
			out = appendLeaf(out, raw, base+joinSegs(stack)+seg, encoded, depth, tokenNode(data, int(start), int(end), enclosing), wc.child(stack))
			continue
		}
		captureScalar(stack, name, scalarRaw(data, int(start), int(end)))
	}
}

// appendLeaf emits the string raw at path. While recursion budget remains it
// first tries to read raw as a JSON document: a document with at least one
// string leaf replaces its wrapper, whose inner leaves carry Encoded true.
// Anything else is emitted itself, without decoding. tok locates raw's token;
// inner leaves get tok as their enclosing wrapper. The identity context is
// variadic so the pre-existing six-argument call sites keep compiling.
func appendLeaf(out []Leaf, raw, path string, encoded bool, depth int, tok *rawToken, opt ...*walkContext) []Leaf {
	wc := leafContext(opt)
	if depth < MaxEncodedDepth {
		if inner, err := walkDocument([]byte(raw), path, true, depth+1, tok, wc); err == nil && len(inner) > 0 {
			return append(out, inner...)
		}
	}
	if depth >= MaxEncodedDepth {
		encoded = false
	}
	identity := joinIdentity(path, wc.inherited, wc.next(path))
	return append(out, Leaf{
		Path: path, Value: []byte(raw), Length: len(raw), Encoded: encoded, tok: tok,
		Identity: identity, Identifiable: len(identity) <= maxIdentityBytes,
	})
}

// tokenNode locates the raw interior of the string token occupying
// data[start:end]: start is the decoder offset before the token, so the first
// quote in that slice opens the token and the byte before end closes it.
func tokenNode(data []byte, start, end int, enclosing *rawToken) *rawToken {
	open := start + bytes.IndexByte(data[start:end], '"')
	return &rawToken{raw: data[open+1 : end-1], start: open, parent: enclosing}
}

// childSegment renders the pointer segment of the next value of the innermost
// open container; the root value contributes the empty pointer.
func childSegment(stack []frame) string {
	if len(stack) == 0 {
		return ""
	}
	top := stack[len(stack)-1]
	if top.object {
		return "/" + escapePointer(top.key)
	}
	return "/" + strconv.Itoa(top.index)
}

// advance moves the innermost open container past the value just consumed.
func advance(stack []frame) {
	if len(stack) == 0 {
		return
	}
	top := &stack[len(stack)-1]
	if top.object {
		top.hasKey = false
		return
	}
	top.index++
}

// escapePointer applies RFC 6901 escaping to one pointer segment.
func escapePointer(token string) string {
	if !strings.ContainsAny(token, "~/") {
		return token
	}
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// joinSegs concatenates the segments of every open container.
func joinSegs(stack []frame) string {
	n := 0
	for i := range stack {
		n += len(stack[i].seg)
	}
	var b strings.Builder
	b.Grow(n)
	for i := range stack {
		b.WriteString(stack[i].seg)
	}
	return b.String()
}

// tokenError maps a decoder failure onto a Walk sentinel. The standard
// library scanner reports its own nesting ceiling instead of returning the
// opening delimiter, so that message maps onto ErrMaxDepth.
func tokenError(err error) error {
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) && strings.Contains(syntax.Error(), "exceeded max depth") {
		return ErrMaxDepth
	}
	return ErrMalformedJSON
}
