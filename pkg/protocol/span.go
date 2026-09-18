package protocol

// Caller contract for raw span plumbing:
//
//  1. Call RawSpan BEFORE minting any placeholder. Never mint a placeholder for
//     a span RawSpan cannot locate (ok == false): there is no raw region to
//     splice, so minting would desynchronize the emitted buffer.
//  2. Only the indices returned by Apply denote edits that actually changed
//     body bytes. Log and count exactly those indices (G3), not the input edit
//     slice: Apply drops unlocatable, no-op, and overlapped edits.
//
// This file implements only the span primitive; its callers live elsewhere.

import (
	"bytes"
	"sort"
	"strconv"
	"unicode/utf8"
)

// rawToken locates one decoded JSON string token inside the document that
// carried it. raw is the token's interior (escapes intact, quotes excluded),
// start is the byte offset of the token's opening quote in that document, and
// parent links outward to the wrapper token whose decoded value IS this
// document (nil for a token in the Walk input).
type rawToken struct {
	raw    []byte
	start  int
	parent *rawToken
}

// nextUnit decodes one unit of a JSON string interior starting at raw[i]:
// a literal UTF-8 rune, or one escape (\" \\ \/ \b \f \n \r \t \uXXXX,
// including a surrogate pair). It returns the raw end index j, the number of
// decoded bytes k, and the decoded rune. The input is valid UTF-8 JSON.
func nextUnit(raw []byte, i int) (j, k int, r rune) {
	if i+1 >= len(raw) || raw[i] != '\\' {
		r, size := utf8.DecodeRune(raw[i:])
		return i + size, size, r
	}
	switch raw[i+1] {
	case '"', '\\', '/':
		return i + 2, 1, rune(raw[i+1])
	case 'b':
		return i + 2, 1, '\b'
	case 'f':
		return i + 2, 1, '\f'
	case 'n':
		return i + 2, 1, '\n'
	case 'r':
		return i + 2, 1, '\r'
	case 't':
		return i + 2, 1, '\t'
	case 'u':
		if i+6 > len(raw) {
			return len(raw), 3, utf8.RuneError
		}
		u, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 32)
		if err != nil {
			return i + 6, 3, utf8.RuneError
		}
		r = rune(u)
		if r >= 0xDC00 && r <= 0xDFFF {
			return i + 6, 3, utf8.RuneError
		}
		if r >= 0xD800 && r <= 0xDBFF {
			if i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
				lo, lerr := strconv.ParseUint(string(raw[i+8:i+12]), 16, 32)
				if lerr == nil && lo >= 0xDC00 && lo <= 0xDFFF {
					r = 0x10000 + (r-0xD800)<<10 + (rune(lo) - 0xDC00)
					return i + 12, 4, r
				}
			}
			return i + 6, 3, utf8.RuneError
		}
		return i + 6, utf8.RuneLen(r), r
	}
	r, size := utf8.DecodeRune(raw[i:])
	return i + size, size, r
}

// mapSpan maps the decoded half-open byte range [start,end) of the string whose
// raw interior is raw to the raw byte range that spells it. A decoded offset
// falling inside a multi-byte rune snaps to the start of that rune's raw
// spelling; for end it snaps to just past the raw spelling of the rune that
// produced decoded byte end-1. ok is false only for an out-of-range span.
func mapSpan(raw []byte, start, end int) (rawStart, rawEnd int, ok bool) {
	decodedLen := 0
	for i := 0; i < len(raw); {
		j, k, _ := nextUnit(raw, i)
		decodedLen += k
		i = j
	}
	if start < 0 || end < start || end > decodedLen {
		return 0, 0, false
	}
	if start == 0 && end == 0 {
		return 0, 0, true
	}
	d := 0
	for i := 0; i < len(raw); {
		j, k, _ := nextUnit(raw, i)
		if d <= start && start < d+k {
			rawStart = i
		}
		if d <= end-1 && end-1 < d+k {
			rawEnd = j
		}
		d += k
		i = j
	}
	if start == decodedLen {
		rawStart = len(raw)
	}
	return rawStart, rawEnd, true
}

// RawSpan maps the decoded byte span [start,end) of Value back to the raw bytes
// of the Walk input. ok is false when the leaf has no raw location (hand-built
// or plugin leaves) or the span is out of range.
func (l Leaf) RawSpan(start, end int) (rawStart, rawEnd int, ok bool) {
	if l.tok == nil || start < 0 || end < start || end > len(l.Value) {
		return 0, 0, false
	}
	rs, re, ok := mapSpan(l.tok.raw, start, end)
	if !ok {
		return 0, 0, false
	}
	rs += l.tok.start + 1
	re += l.tok.start + 1
	for t := l.tok.parent; t != nil; t = t.parent {
		var mapped bool
		rs, re, mapped = mapSpan(t.raw, rs, re)
		if !mapped {
			return 0, 0, false
		}
		rs += t.start + 1
		re += t.start + 1
	}
	return rs, re, true
}

// Edit is one replacement of the raw bytes spelling the decoded span
// [Start,End) of Leaf.Value.
type Edit struct {
	Leaf        Leaf
	Start, End  int
	Replacement []byte
}

// Apply splices every locatable, byte-changing edit into body and returns the
// new body plus the indices (into edits) that were actually applied, in
// ascending raw-start order. Overlapping edits keep the FIRST in ascending
// raw-start order; an edit whose raw bytes already equal its replacement is not
// applied. This index form is deliberate: it lets the caller log and count ONLY
// real changes (G3) without duplicating the overlap rule.
func Apply(body []byte, edits []Edit) ([]byte, []int) {
	type cand struct {
		idx    int
		rs, re int
		repl   []byte
	}
	var cands []cand
	for i := range edits {
		rs, re, ok := edits[i].Leaf.RawSpan(edits[i].Start, edits[i].End)
		if !ok || rs < 0 || re <= rs || re > len(body) {
			continue
		}
		repl := edits[i].Replacement
		if bytes.Equal(body[rs:re], repl) {
			continue
		}
		cands = append(cands, cand{i, rs, re, repl})
	}
	sort.SliceStable(cands, func(a, b int) bool { return cands[a].rs < cands[b].rs })
	var kept []cand
	lastEnd := 0
	for _, c := range cands {
		if c.rs < lastEnd {
			continue
		}
		kept = append(kept, c)
		lastEnd = c.re
	}
	idx := make([]int, len(kept))
	for i, c := range kept {
		idx[i] = c.idx
	}
	out := body
	for i := len(kept) - 1; i >= 0; i-- {
		c := kept[i]
		next := make([]byte, 0, len(out)-(c.re-c.rs)+len(c.repl))
		next = append(next, out[:c.rs]...)
		next = append(next, c.repl...)
		next = append(next, out[c.re:]...)
		out = next
	}
	return out, idx
}
