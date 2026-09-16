package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// KeySpan locates one JSON object member name (a key) in a document.
//
// Path is the RFC 6901 JSON Pointer of the object member that holds this key:
// the container pointer plus "/" plus escapePointer(Key), matching the Path
// conventions of Leaf. A key that lives inside a double-encoded string leaf
// carries the same '#' composite boundary, e.g. /input/1/arguments#/command.
//
// Key is the decoded key string: JSON escapes (\" \\ \n \uXXXX) are resolved
// and the surrounding quotes are removed.
//
// RawStart and RawEnd delimit the raw byte span of the key excluding the
// surrounding quotes, i.e. the escaped form as it appears in the source. The
// coordinate space depends on Encoded:
//
//   - Encoded == false: the offsets index data, the document passed to WalkKeys.
//   - Encoded == true: the key was found inside a double-encoded string leaf,
//     so the offsets index that leaf's decoded content — the document opened by
//     the final '#' boundary of Path — not data. encoding/json's
//     Decoder.InputOffset only tracks the outer document, so inner offsets are
//     deliberately reported in inner coordinates rather than silently mixed
//     with outer ones. Subtract nothing: slice the enclosing content, which is
//     the string value whose Path is this Path with its final '#'-suffix
//     removed.
//
// Encoded also reports whether the nearest enclosing document is an embedded
// one, so callers can tell the two coordinate spaces apart. Duplicate keys are
// reported once each, in document order; WalkKeys never deduplicates them.
// KeySpan carries no value content and is not a Leaf — object keys are not
// string values and must not enter the Leaf contract.
type KeySpan struct {
	Path     string
	Key      string
	RawStart int
	RawEnd   int
	Encoded  bool
}

// WalkKeys parses data as one JSON document and returns the span of every
// object key in document order, descending into double-encoded string leaves
// exactly like Walk. Objects and arrays are traversed recursively; a string
// whose content is itself a JSON object, array, or string is traversed up to
// MaxEncodedDepth levels and its inner keys carry the composite '#' path
// described on KeySpan.
//
// Validation is identical to Walk: the same UTF-8 precheck, the same
// UseNumber decoder, the same trailing-data check, and the same sentinel
// errors (ErrMalformedJSON, ErrNestingDepth, ErrEncodedDepth) with the same
// wrapping. On any error it returns a nil slice, never partial results.
//
// WalkKeys is policy-free: it only locates keys and classifies nothing about
// them. It never mutates Walk's behaviour.
func WalkKeys(data []byte) ([]KeySpan, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: input is not valid UTF-8", ErrMalformedJSON)
	}
	var keys []KeySpan
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkKeysValue(data, dec, "", 0, 0, &keys); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after top-level JSON value", ErrMalformedJSON)
	}
	return keys, nil
}

// walkKeysValue consumes one JSON value from dec, appending the keys of any
// objects it contains. doc is the raw text the decoder reads from, needed to
// recover each key's source span. depth counts object/array nesting, encDepth
// the double-encoded boundaries.
func walkKeysValue(doc []byte, dec *json.Decoder, path string, depth, encDepth int, out *[]KeySpan) error {
	if depth > MaxNestingDepth {
		return fmt.Errorf("%w: depth %d", ErrNestingDepth, depth)
	}
	tok, err := dec.Token()
	if err != nil {
		return malformed("read token", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		return walkKeysContainer(doc, dec, t, path, depth, encDepth, out)
	case string:
		return walkKeysString(t, path, depth, encDepth, out)
	default:
		// Numbers, booleans, and null contain no keys.
		return nil
	}
}

// walkKeysContainer consumes the remaining values of an object or array started
// by delim, recursing into every element.
func walkKeysContainer(doc []byte, dec *json.Decoder, delim json.Delim, path string, depth, encDepth int, out *[]KeySpan) error {
	switch delim {
	case '{':
		for dec.More() {
			// InputOffset before the key token is the end of the previous
			// token; whitespace and possibly a comma follow, so the raw span
			// is recovered from the token end instead of that boundary.
			start := dec.InputOffset()
			keyTok, err := dec.Token()
			if err != nil {
				return malformed("read object key", err)
			}
			key, ok := keyTok.(string)
			if !ok {
				return malformed("object key is not a string", nil)
			}
			end := dec.InputOffset()
			rawStart, rawEnd, ok := rawKeySpan(doc, int(start), int(end))
			if !ok {
				return malformed("locate object key raw span", nil)
			}
			*out = append(*out, KeySpan{
				Path:     path + "/" + escapePointer(key),
				Key:      key,
				RawStart: rawStart,
				RawEnd:   rawEnd,
				Encoded:  encDepth > 0,
			})
			if err := walkKeysValue(doc, dec, path+"/"+escapePointer(key), depth+1, encDepth, out); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return malformed("read object end", err)
		}
		return nil
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkKeysValue(doc, dec, path+"/"+strconv.Itoa(i), depth+1, encDepth, out); err != nil {
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

// walkKeysString descends into a string value that is itself a JSON document,
// exactly like walkStringLeaf does for Walk. Non-walkable strings contribute
// no keys.
func walkKeysString(content, path string, depth, encDepth int, out *[]KeySpan) error {
	if !walkableJSON(content) {
		return nil
	}
	if encDepth >= MaxEncodedDepth {
		return fmt.Errorf("%w: depth %d", ErrEncodedDepth, encDepth)
	}
	innerDoc := []byte(content)
	inner := json.NewDecoder(bytes.NewReader(innerDoc))
	inner.UseNumber()
	return walkKeysValue(innerDoc, inner, path+"#", depth+1, encDepth+1, out)
}

// rawKeySpan recovers the source span of an object key token, excluding its
// surrounding quotes.
//
// The decoder was positioned at start before reading the key and at end right
// after its closing quote, so doc[end-1] is that closing quote. The opening
// quote is found by scanning backwards for a '"' preceded by an even number of
// backslashes; scanning forward from start cannot be used because a preceding
// comma is included in [start, end). It reports false if the token does not
// have the expected shape, which cannot happen for input that decoded as JSON.
func rawKeySpan(doc []byte, start, end int) (int, int, bool) {
	if end <= start || end > len(doc) || doc[end-1] != '"' {
		return 0, 0, false
	}
	close := end - 1
	for i := close - 1; i >= start; i-- {
		if doc[i] != '"' {
			continue
		}
		backslashes := 0
		for j := i - 1; j >= start && doc[j] == '\\'; j-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			return i + 1, close, true
		}
	}
	return 0, 0, false
}
