package proxy

import "github.com/fregie/tokenhush/pkg/protocol"

// emit writes one held event, applying its accumulated edits. A JSON event's
// single data payload is rewritten as a whole through the existing
// leafRewriter driven by the path->final-content map; any error or a no-op
// rewrite falls back to the original bytes verbatim, so a desync can never
// produce a half-spliced record. A raw (non-JSON) event's payload is replaced
// directly, without JSON quoting.
func (b *sseBackfiller) emit(he *heldEvent) error {
	if he.kind == kindRaw {
		if he.rawEdit == nil {
			return b.write(he.raw)
		}
		return b.write(splice(he.raw, he.dataOff, he.dataLen, []byte(*he.rawEdit)))
	}
	if len(he.jsonEdits) == 0 {
		return b.write(he.raw)
	}
	src := he.raw[he.dataOff : he.dataOff+he.dataLen]
	leaves, _ := protocol.Walk(src)
	rw := &leafRewriter{walked: leaves, edit: mapEdit(he.jsonEdits)}
	out, changed, err := rw.rewrite(src, "")
	if err == nil && changed {
		return b.write(splice(he.raw, he.dataOff, he.dataLen, out))
	}
	return b.write(he.raw)
}

// write forwards p to the destination. An empty p is a no-op so a record that
// was fully rewritten to nothing does not issue a zero-length Write.
func (b *sseBackfiller) write(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	_, err := b.dst.Write(p)
	return err
}

// mapEdit adapts a path->decoded-content map to the leafRewriter's edit hook.
// The terminal index is ignored: paths are unique within one payload, and a
// changed flag here would only duplicate the rewriter's own equality check.
func mapEdit(edits map[string]string) leafEdit {
	return func(_ int, path string, content []byte) ([]byte, bool) {
		replacement, ok := edits[path]
		if !ok {
			return content, false
		}
		return []byte(replacement), replacement != string(content)
	}
}

// splice returns raw with raw[off:off+n] replaced by replacement, copying the
// surrounding framing bytes unchanged.
func splice(raw []byte, off, n int, replacement []byte) []byte {
	out := make([]byte, 0, len(raw)-n+len(replacement))
	out = append(out, raw[:off]...)
	out = append(out, replacement...)
	out = append(out, raw[off+n:]...)
	return out
}
