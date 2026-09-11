package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// errRewriterDesync means the rewriter's token stream no longer aligns with the
// protocol.Walk leaf list it was handed. That can only happen if the two
// traversals disagree, which would be a bug, so the caller fails closed (the
// request transform returns an error and the forwarder answers locally rather
// than forwarding a partially rewritten body).
var errRewriterDesync = errors.New("proxy: JSON rewriter leaf desync")

// leafEdit rewrites one terminal (non-encoded) JSON string leaf. It receives:
//
//   - terminalIdx: the leaf's ordinal among the terminal leaves, matching the
//     LeafIndex protocol.Walk reports when encoded parents are filtered out;
//   - path: the leaf's protocol JSON Pointer (with '#' inside a double-encoded
//     string);
//   - content: the decoded string value (JSON escapes resolved).
//
// It returns the replacement decoded content and whether it differs from
// content. A false "changed" means the raw token is copied byte-for-byte.
type leafEdit func(terminalIdx int, path string, content []byte) ([]byte, bool)

// leafRewriter rewrites JSON string leaves in place while preserving every byte
// it does not change: key order, whitespace, separators and number spelling all
// survive. Only a string value whose edit reports a change is re-quoted and
// spliced; everything else is copied verbatim.
//
// leafRewriter relies on protocol.Walk, called by the pipeline before this
// rewriter, to have produced the leaf list in exactly the order encoding/json
// visits string values. The rewriter walks the same token stream and consumes
// one walked leaf per string value, so a divergence is detected (errRewriterDesync)
// instead of silently editing the wrong span. Encoded parents are consumed but
// never edited: their nested leaves are edited and the enclosing string is
// re-encoded from them.
//
// leafRewriter is single-use and not safe for concurrent use.
type leafRewriter struct {
	walked      []protocol.Leaf
	edit        leafEdit
	walkIdx     int
	terminalIdx int
}

// rewrite re-walks src and returns the rewritten document. path is the JSON
// Pointer the document root carries ("" at the top level, "<outer>#" at the
// root of a double-encoded string). changed reports whether any byte inside a
// string value was rewritten; when false, out is byte-identical to src.
func (rw *leafRewriter) rewrite(src []byte, path string) (out []byte, changed bool, err error) {
	state := &rewriteState{src: src}
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	if err := rw.rewriteValue(dec, path, state); err != nil {
		return nil, false, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("%w: data after top-level JSON value", errRewriterDesync)
	}
	state.out.Write(src[state.copied:])
	return state.out.Bytes(), state.changed, nil
}

// rewriteState accumulates the output while copying unmodified spans from src.
type rewriteState struct {
	src     []byte
	out     bytes.Buffer
	copied  int // next src byte not yet copied to out
	changed bool
}

// splice emits the span before the edited token, the replacement token and
// advances the copy cursor past the original token.
func (st *rewriteState) splice(start, end int, replacement []byte) {
	st.out.Write(st.src[st.copied:start])
	st.out.Write(replacement)
	st.copied = end
	st.changed = true
}

// rewriteValue consumes one JSON value from dec and rewrites its string leaves
// in place. Containers are traversed; the object keys themselves are never
// edited (protocol.Walk does not treat keys as leaves).
func (rw *leafRewriter) rewriteValue(dec *json.Decoder, path string, state *rewriteState) error {
	before := int(dec.InputOffset())
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("proxy: rewrite JSON token: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		return rw.rewriteContainer(dec, t, path, state)
	case string:
		// The decoder is positioned just past the closing quote; the first '"'
		// in src[before:after) opens this token, because everything between the
		// previous token and this one is a separator (':', ',', whitespace).
		after := int(dec.InputOffset())
		start := before + bytes.IndexByte(state.src[before:after], '"')
		if start < before || start >= after {
			return fmt.Errorf("%w: string token boundary", errRewriterDesync)
		}
		return rw.rewriteString(t, path, start, after, state)
	default:
		// Numbers, booleans and null are not string leaves.
		return nil
	}
}

// rewriteContainer consumes the members of an object or array started by delim.
func (rw *leafRewriter) rewriteContainer(dec *json.Decoder, delim json.Delim, path string, state *rewriteState) error {
	switch delim {
	case '{':
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return fmt.Errorf("proxy: rewrite object key: %w", err)
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("%w: object key is not a string", errRewriterDesync)
			}
			if err := rw.rewriteValue(dec, path+"/"+escapeJSONPointer(key), state); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // closing '}'
			return fmt.Errorf("proxy: rewrite object end: %w", err)
		}
		return nil
	case '[':
		for i := 0; dec.More(); i++ {
			if err := rw.rewriteValue(dec, path+"/"+strconv.Itoa(i), state); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // closing ']'
			return fmt.Errorf("proxy: rewrite array end: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("%w: unexpected delimiter %q", errRewriterDesync, delim)
	}
}

// rewriteString consumes one walked leaf for the string token at
// src[start:end) and, when the edit changes it, splices the re-quoted value.
func (rw *leafRewriter) rewriteString(content, path string, start, end int, state *rewriteState) error {
	if rw.walkIdx >= len(rw.walked) {
		return fmt.Errorf("%w: more string values than walked leaves", errRewriterDesync)
	}
	leaf := rw.walked[rw.walkIdx]
	if leaf.Path != path {
		return fmt.Errorf("%w: walked path %q, stream path %q", errRewriterDesync, leaf.Path, path)
	}
	rw.walkIdx++

	if leaf.Encoded {
		inner, innerChanged, err := rw.rewrite([]byte(content), path+"#")
		if err != nil {
			return err
		}
		if innerChanged {
			state.splice(start, end, jsonQuote(string(inner)))
		}
		return nil
	}

	if rw.edit != nil {
		replacement, changed := rw.edit(rw.terminalIdx, path, []byte(content))
		if changed {
			state.splice(start, end, jsonQuote(string(replacement)))
		}
	}
	rw.terminalIdx++
	return nil
}

// jsonQuote returns the JSON string literal for s, including the surrounding
// quotes, using the standard Go escape set but without html escaping: '<', '>'
// and '&' stay literal so untouched content is not silently rewritten as
// \u003c etc. Encoding a string cannot fail.
func jsonQuote(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// escapeJSONPointer encodes one JSON Pointer reference token per RFC 6901 §3.
// It mirrors pkg/protocol's unexported encoder so the rewriter's paths align
// with the leaves protocol.Walk produces.
func escapeJSONPointer(token string) string {
	if !strings.ContainsAny(token, "~/") {
		return token
	}
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}
