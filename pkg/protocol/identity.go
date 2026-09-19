package protocol

import (
	"strconv"
	"strings"
)

// maxIdentityBytes caps the channel identity a leaf may carry. A leaf whose
// canonical identity is longer is reported Identifiable false and is never
// truncated: the identity is a discriminator, so a clipped one could collide.
const maxIdentityBytes = 1024

// identitySep is the ASCII unit separator, byte 0x1f. It joins every component
// of a leaf identity and cannot appear in JSON syntax, so it never collides
// with a pointer or a rendered scalar.
const identitySep = "\x1f"

// frameScalar is one non-string scalar member captured from a frame that
// encloses a leaf. For an object frame name is the member key; for an array
// frame name is the scalar element's 0-based decimal index. raw is the member's
// literal document text, never a reformatted decoded value.
type frameScalar struct {
	name string
	raw  string
}

// walkContext threads channel-identity state through one Walk call: the scalar
// context already inherited from decoded JSON-string wrappers, and the per-path
// leaf occurrence counter shared by the whole call.
type walkContext struct {
	inherited []frameScalar
	occurred  map[string]int
}

// child returns the context for a leaf inside the open stack: the inherited
// scalar context followed by the open frames' captured scalars, outermost to
// innermost, sharing this call's occurrence counter.
func (c *walkContext) child(stack []frame) *walkContext {
	if c.occurred == nil {
		c.occurred = map[string]int{}
	}
	inherited := c.inherited
	if len(stack) > 0 {
		inherited = append(append([]frameScalar(nil), inherited...), flattenScalars(stack)...)
	}
	return &walkContext{inherited: inherited, occurred: c.occurred}
}

// next returns the 0-based occurrence of path and advances the counter.
func (c *walkContext) next(path string) int {
	if c.occurred == nil {
		c.occurred = map[string]int{}
	}
	n := c.occurred[path]
	c.occurred[path] = n + 1
	return n
}

// leafContext returns the caller-provided context or a fresh one. appendLeaf
// takes its context variadically so the pre-existing six-argument call sites
// keep compiling; Walk always supplies one.
func leafContext(opt []*walkContext) *walkContext {
	if len(opt) > 0 && opt[0] != nil {
		return opt[0]
	}
	return &walkContext{}
}

// joinIdentity renders the canonical channel identity: the path, then each
// captured scalar as name=rawValue, then the leaf's occurrence index, with
// every component separated by identitySep.
func joinIdentity(path string, scalars []frameScalar, occurrence int) string {
	var b strings.Builder
	b.WriteString(path)
	for i := range scalars {
		b.WriteString(identitySep)
		b.WriteString(scalars[i].name)
		b.WriteByte('=')
		b.WriteString(scalars[i].raw)
	}
	b.WriteString(identitySep)
	b.WriteString(strconv.Itoa(occurrence))
	return b.String()
}

// memberName renders the identity name of the value about to be consumed by the
// innermost open frame: the object key, or the array element's decimal index.
func memberName(stack []frame) string {
	if len(stack) == 0 {
		return ""
	}
	top := stack[len(stack)-1]
	if top.object {
		return top.key
	}
	return strconv.Itoa(top.index)
}

// captureScalar records one preceding non-string scalar member on the innermost
// open frame. Object keys never reach here: only member values and array
// elements do.
func captureScalar(stack []frame, name, raw string) {
	if len(stack) == 0 {
		return
	}
	top := &stack[len(stack)-1]
	top.scalars = append(top.scalars, frameScalar{name: name, raw: raw})
}

// flattenScalars concatenates the captured scalars of every open frame,
// outermost to innermost.
func flattenScalars(stack []frame) []frameScalar {
	n := 0
	for i := range stack {
		n += len(stack[i].scalars)
	}
	if n == 0 {
		return nil
	}
	out := make([]frameScalar, 0, n)
	for i := range stack {
		out = append(out, stack[i].scalars...)
	}
	return out
}

// scalarRaw slices the literal text of the scalar token occupying
// data[start:end]. start is the decoder offset before the token, so the slice
// can begin with the member/element separator and whitespace the decoder
// skipped; those bytes are stripped, leaving the literal itself.
func scalarRaw(data []byte, start, end int) string {
	raw := data[start:end]
	for len(raw) > 0 {
		switch raw[0] {
		case ' ', '\t', '\r', '\n', ',', ':':
			raw = raw[1:]
			continue
		}
		break
	}
	return string(raw)
}
