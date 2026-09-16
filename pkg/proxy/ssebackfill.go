package proxy

import (
	"bytes"
	"io"

	"github.com/fregie/tokenhush/pkg/protocol"
)

const (
	// sseBackfillMaxHoldbackBytes bounds how many raw bytes may be retained for
	// ordering before the oldest held event is force-flushed. T6#12 reads it.
	sseBackfillMaxHoldbackBytes = 256 << 10
	// sseRawPathKey is the synthetic path for a non-JSON data payload. JSON
	// Pointers never contain NUL, so it cannot collide with a real leaf path.
	sseRawPathKey = "\x00raw"
)

// pathKind distinguishes a JSON string-leaf path from the synthetic raw path.
type pathKind uint8

const (
	kindJSON pathKind = iota
	kindRaw
)

// pathState accumulates, across the events it spans, the decoded content of one
// JSON path (or of a raw data payload). merged is the BackfillWriter's
// destination, so it receives only bytes the writer has already decided.
type pathState struct {
	key     string
	kind    pathKind
	w       *protocol.BackfillWriter
	merged  bytes.Buffer
	run     []int
	changed bool
	active  bool
	lastSeq int

	// W6.4 tool-call guard state. It lives on the path — never in a side map —
	// so forceFlush and Flush, which only walk b.paths, see it: an undecided
	// guard path must never be released as original bytes. guardArmed marks a
	// path whose final reference token is `arguments`; guardAccum is the
	// bounded (SSEGuardCap) accumulation the match decision uses; guardDecided
	// and guardHit record that decision. See sseguard.go.
	guardArmed   bool
	guardDecided bool
	guardHit     bool
	guardAccum   []byte
	// guardClass is the channel class a match decided ("" when the refusal came
	// from a fail-closed path), so releasePath can build the same structured
	// refusal envelope the buffered path delivers.
	guardClass string
}

// Write makes pathState the BackfillWriter destination; it never fails.
func (p *pathState) Write(b []byte) (int, error) { return p.merged.Write(b) }

// heldEvent is one dequeued-but-not-yet-emitted SSE record. jsonEdits and
// rawEdit are populated only when one of the record's paths releases, which
// happens at an event boundary once that path's window is empty.
type heldEvent struct {
	raw       []byte
	dataOff   int
	dataLen   int
	kind      pathKind
	jsonEdits map[string]string
	rawEdit   *string
	openRefs  int
}

// sseBackfiller backfills placeholders in an SSE stream with awareness of the
// `data:` framing: a placeholder split across several events (each carrying a
// JSON delta) is only visible after concatenating the decoded leaf contents, so
// the raw byte stream cannot be scanned for it. It feeds every single-line
// data payload's terminal string leaves into per-path windows, and when a path
// releases it rewrites the whole data payload of the events that contributed.
//
// Ordering: events are emitted in arrival order, so an event whose content is
// still undecided is held. A complete event with an idle window is emitted
// within the same Write; only events that contribute to an open path are held.
//
// Errors are sticky. sseBackfiller is not safe for concurrent use.
type sseBackfiller struct {
	dst       io.Writer
	maxLen    int
	replace   protocol.ReplaceFunc
	dec       *protocol.SSEDecoder
	order     []int
	held      map[int]*heldEvent
	nextSeq   int
	paths     map[string]*pathState
	touched   []*pathState
	heldBytes int
	err       error
	// onWalkFailure, when set, observes a payload the emit-time walker cannot
	// parse (the desync guard in emit). It receives the walker error, never
	// payload bytes, and the fallback — write the original event verbatim — is
	// unchanged. Nil is a no-op; see setWalkFailureObserver.
	onWalkFailure func(error)
	// guardDetect and onGuardRefusal are the W6.4 tool-call guard: when
	// guardDetect is set, every tool-call arguments path accumulates its
	// fragments under SSEGuardCap and a refusal is reported through
	// onGuardRefusal. Nil is a complete no-op; see setToolCallGuard.
	guardDetect    func(text string) (class string, matched bool)
	onGuardRefusal func(class, reason string)
	// guardDetectEncoded is the W6.4 matcher for the Encoded (valid-JSON)
	// arguments shape: the whole arguments value arrives in one event, so the
	// guard must feed the parent and match it with the buffered path's
	// concatenation logic. Nil leaves that shape unarmed; see
	// setToolCallGuardEncoded.
	guardDetectEncoded func(content []byte) (class string, matched bool)
}

// newSSEBackfiller returns a backfiller writing rewritten SSE bytes to dst.
// maxPlaceholderLen sizes each path's placeholder window and replace maps a
// complete placeholder token to the client-visible bytes.
func newSSEBackfiller(dst io.Writer, maxPlaceholderLen int, replace protocol.ReplaceFunc) *sseBackfiller {
	return &sseBackfiller{
		dst:     dst,
		maxLen:  maxPlaceholderLen,
		replace: replace,
		dec:     protocol.NewSSEDecoder(),
		held:    make(map[int]*heldEvent),
		paths:   make(map[string]*pathState),
	}
}

// setWalkFailureObserver installs the optional observer for payloads the
// emit-time walker cannot parse. It exists so the pipeline can count and report
// the otherwise-silent fallback without widening newSSEBackfiller's signature
// (tests construct backfillers directly). A nil backfiller or a nil fn are
// no-ops; fn receives the walker error, never the payload.
func (b *sseBackfiller) setWalkFailureObserver(fn func(error)) {
	if b == nil {
		return
	}
	b.onWalkFailure = fn
}

// Write feeds p to the SSE decoder and processes every completed record. It
// always reports len(p) on success; once an error occurs it is sticky and later
// calls return it without touching dst.
func (b *sseBackfiller) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	for _, ev := range b.dec.Feed(p) {
		if err := b.processEvent(ev); err != nil {
			b.err = err
			return 0, err
		}
	}
	return len(p), nil
}

// Flush finishes the stream: it drains decoder-close records, flushes every
// still-open path's window as literal bytes, releases those paths so their
// events can be emitted, and returns the sticky error (if any).
func (b *sseBackfiller) Flush() error {
	if b.err != nil {
		return b.err
	}
	for _, ev := range b.dec.Close() {
		if err := b.processEvent(ev); err != nil {
			b.err = err
			return err
		}
	}
	for _, p := range b.paths {
		if !p.active {
			continue
		}
		if err := p.w.Flush(); err != nil {
			b.err = err
			return err
		}
		b.releasePath(p)
	}
	if err := b.drain(); err != nil {
		b.err = err
		return err
	}
	// A Flush ends one stream. Reset the decoder so the same backfiller can
	// process a following independent stream without stale framing state; the
	// held map, order and every path are already empty or released above.
	b.dec = protocol.NewSSEDecoder()
	return b.err
}

// processEvent holds one record, feeds the decodable payload of a single-line
// data record into its leaves' paths, then runs the event-boundary release.
// A record that is not DataSingle is held for ordering only and never
// rewritten (multi-line and colon-less data stay byte-identical).
func (b *sseBackfiller) processEvent(ev protocol.SSEEvent) error {
	seq := b.nextSeq
	b.nextSeq++
	he := &heldEvent{
		raw:     ev.Raw,
		dataOff: ev.DataOffset,
		dataLen: ev.DataLen,
		kind:    kindJSON,
	}
	b.held[seq] = he
	b.order = append(b.order, seq)
	b.heldBytes += len(ev.Raw)

	if !ev.DataSingle {
		return b.afterEvent()
	}
	payload := ev.Raw[ev.DataOffset : ev.DataOffset+ev.DataLen]
	leaves, err := protocol.Walk(payload)
	if err != nil {
		he.kind = kindRaw
		if err := b.feed(sseRawPathKey, kindRaw, payload, seq); err != nil {
			return err
		}
		return b.afterEvent()
	}
	for _, leaf := range leaves {
		if leaf.Encoded {
			if err := b.feedGuardEncoded(leaf.Path, []byte(leaf.Content), seq); err != nil {
				return err
			}
			continue
		}
		if err := b.feed(leaf.Path, kindJSON, []byte(leaf.Content), seq); err != nil {
			return err
		}
	}
	return b.afterEvent()
}

// feed appends chunk to key's window and records that seq contributes to the
// path's current run. The writer is built here, at the only place replace is
// wrapped, so a replacement that leaves the token unchanged (an unknown
// placeholder) does NOT mark the run as changed.
func (b *sseBackfiller) feed(key string, kind pathKind, chunk []byte, seq int) error {
	p := b.paths[key]
	if p == nil || p.kind != kind {
		p = b.newPathState(key, kind)
		b.paths[key] = p
	}
	if !p.active {
		p.active = true
		p.run = p.run[:0]
		p.merged.Reset()
		p.changed = false
		b.guardReset(p)
	}
	if p.lastSeq != seq {
		p.lastSeq = seq
		p.run = append(p.run, seq)
		b.held[seq].openRefs++
		b.touched = append(b.touched, p)
	}
	if b.guardConsume(p, chunk) {
		// A refused tool call: this chunk still counts as a contributor (so the
		// notice can replace the whole run and the events stay held) but none of
		// its bytes may reach the output.
		return nil
	}
	_, err := p.w.Write(chunk)
	return err
}

// feedGuardEncoded feeds one Encoded arguments parent — a whole valid-JSON
// arguments value delivered in a single event — into the guard. protocol.Walk
// skips such a parent for the placeholder writer, so a guard that armed only the
// terminal `.../arguments` leaf never saw the mainstream OpenAI streaming shape
// and the command leaked verbatim. The parent content is matched with the
// buffered path's concatenation logic (guardDetectEncoded), so a command split
// across its nested leaves is still caught, and the refusal is recorded against
// the parent path so emit replaces the whole arguments value. The content is
// never written to the placeholder window: the nested terminal leaves keep their
// existing per-leaf backfill.
func (b *sseBackfiller) feedGuardEncoded(key string, content []byte, seq int) error {
	if b.guardDetect == nil || b.guardDetectEncoded == nil || !isMutationChannelArgumentsPath(key) {
		return nil
	}
	p := b.paths[key]
	if p == nil || p.kind != kindJSON {
		p = b.newPathState(key, kindJSON)
		b.paths[key] = p
	}
	if !p.active {
		p.active = true
		p.run = p.run[:0]
		p.merged.Reset()
		p.changed = false
		b.guardReset(p)
	}
	if p.lastSeq != seq {
		p.lastSeq = seq
		p.run = append(p.run, seq)
		b.held[seq].openRefs++
		b.touched = append(b.touched, p)
	}
	if p.guardDecided {
		return nil
	}
	n := min(len(content), SSEGuardCap)
	p.guardAccum = append(p.guardAccum[:0], content[:n]...)
	if class, matched := b.guardDetectEncoded(content); matched {
		p.guardDecided, p.guardHit = true, true
		p.guardClass = class
		b.noteGuardRefusal(class, sseGuardReasonMatch)
		return nil
	}
	if n >= SSEGuardCap {
		p.guardDecided, p.guardHit = true, true
		b.noteGuardRefusal("", sseGuardReasonCap)
	}
	return nil
}

// newPathState builds a path's state and its placeholder writer. The wrapper is
// the single point where the changed flag is decided: out != token, never
// "replace was called".
func (b *sseBackfiller) newPathState(key string, kind pathKind) *pathState {
	p := &pathState{key: key, kind: kind, lastSeq: -1, guardArmed: b.guardArms(kind, key)}
	p.w = protocol.NewBackfillWriter(p, b.maxLen, func(tok string) string {
		out := b.replace(tok)
		if out != tok {
			p.changed = true
		}
		return out
	})
	return p
}

// afterEvent performs every release at the event boundary: a path whose window
// is empty and whose guard decision is made is decided and released. A guarded
// path without a decision is held — it may still receive the fragment that makes
// a command match — and is only resolved by a path change, the cap, or
// forceFlush/Flush. It then enforces the holdback bound and emits whatever is
// now drainable.
func (b *sseBackfiller) afterEvent() error {
	for _, p := range b.touched {
		if p.active && p.w.Buffered() == 0 && p.guardReleasable() {
			b.releasePath(p)
		}
	}
	b.touched = b.touched[:0]
	if err := b.guardClose(); err != nil {
		return err
	}
	if b.heldBytes > sseBackfillMaxHoldbackBytes {
		if err := b.forceFlush(); err != nil {
			return err
		}
	}
	return b.drain()
}

// releasePath decides a path's run. When a replacement happened, the last
// contributing event receives the full merged content and every earlier one
// receives an empty string, so client-side concatenation of deltas yields the
// replacement exactly once. When nothing changed, no edit is recorded and every
// contributing event keeps its original bytes.
func (b *sseBackfiller) releasePath(p *pathState) {
	// W6.4: a guarded path is written back with the refusal notice unless the
	// guard decided it clean. A path released without a decision — forceFlush
	// or stream end — is refused here, fail-closed, and counted. The refusal is
	// expressed as a merged-content edit, never as a Write error, so the stream
	// keeps flowing; giving the last contributing event the notice and every
	// earlier one an empty string keeps the client's delta concatenation exact.
	if p.guardArmed && (!p.guardDecided || p.guardHit) {
		if !p.guardDecided {
			p.guardDecided, p.guardHit = true, true
			b.noteGuardRefusal("", sseGuardReasonUndecided)
		}
		p.changed = true
		p.merged.Reset()
		p.merged.Write(mutationChannelRefusalArguments(p.guardClass))
	}
	if p.changed {
		last := p.run[len(p.run)-1]
		content := p.merged.String()
		for _, seq := range p.run {
			if seq == last {
				b.setEdit(seq, p, content)
			} else {
				b.setEdit(seq, p, "")
			}
		}
	}
	for _, seq := range p.run {
		b.held[seq].openRefs--
	}
	p.active = false
	p.run = p.run[:0]
	p.merged.Reset()
	p.changed = false
}

// setEdit records the final decoded content for one held event's path.
func (b *sseBackfiller) setEdit(seq int, p *pathState, content string) {
	he := b.held[seq]
	if p.kind == kindRaw {
		he.rawEdit = &content
		return
	}
	if he.jsonEdits == nil {
		he.jsonEdits = make(map[string]string)
	}
	he.jsonEdits[p.key] = content
}

// drain emits held events from the front while nothing still references them.
func (b *sseBackfiller) drain() error {
	for len(b.order) > 0 {
		seq := b.order[0]
		he := b.held[seq]
		if he.openRefs != 0 {
			break
		}
		if err := b.emit(he); err != nil {
			return err
		}
		b.heldBytes -= len(he.raw)
		delete(b.held, seq)
		b.order = b.order[1:]
	}
	return nil
}

// forceFlush bounds held memory: it flushes every active window (its tail
// becomes literal), then releases the paths and drains. Flushing must precede
// releasing; releasing first would attach edits to events whose bytes are still
// buffered in a window that is about to be reset.
func (b *sseBackfiller) forceFlush() error {
	for _, p := range b.paths {
		if !p.active {
			continue
		}
		if err := p.w.Flush(); err != nil {
			return err
		}
	}
	for _, p := range b.paths {
		if p.active {
			b.releasePath(p)
		}
	}
	return b.drain()
}
