package protocol

import (
	"bytes"
	"io"
	"strconv"
	"strings"
)

// PlaceholderPrefix opens every PII placeholder token. The full grammar is
// owned by the redaction layer; pkg/protocol only needs the fixed opening so it
// can recognise tokens that may straddle chunk boundaries in a stream.
const PlaceholderPrefix = "__PII_"

// placeholderSuffix closes a PII placeholder token: __PII_<type>_<digest>__.
const placeholderSuffix = "__"

// ReplaceFunc maps one complete placeholder token to the bytes the client
// should see. Implementations are pure and must not retain their argument.
type ReplaceFunc func(string) string

// IdentityReplace returns s unchanged. It is the default replacement for
// callers that never expect placeholder tokens (the free core emits none
// outbound); backfill consumers pass the session's secret mapping instead.
func IdentityReplace(s string) string { return s }

// BackfillWriter rewrites complete PII placeholders in a byte stream and
// forwards everything else to dst unchanged.
//
// It is the streaming half of inbound backfill: an upstream response may split
// a placeholder across arbitrary chunk boundaries, so the writer retains a
// bounded window (maxPlaceholderLen bytes) until a token is either complete
// (replaced) or provably literal (forwarded). It never emits a partial
// placeholder: every byte written to dst is either ordinary input bytes or the
// replacement of a complete token, in input order. Call Flush at end of stream
// to release a trailing incomplete prefix as raw bytes.
//
// BackfillWriter is not safe for concurrent use. Once Write or Flush returns
// an error the writer is poisoned; later calls return the same error without
// touching dst again.
type BackfillWriter struct {
	dst               io.Writer
	maxPlaceholderLen int
	replace           ReplaceFunc
	buf               []byte
	err               error
}

// NewBackfillWriter returns a BackfillWriter over dst. maxPlaceholderLen bounds
// the number of bytes buffered while a token may still complete; values below
// len(PlaceholderPrefix) are clamped up so the writer can always hold a full
// opening. replace is called once per complete token and may be nil, which
// selects IdentityReplace.
func NewBackfillWriter(dst io.Writer, maxPlaceholderLen int, replace ReplaceFunc) *BackfillWriter {
	if maxPlaceholderLen < len(PlaceholderPrefix) {
		maxPlaceholderLen = len(PlaceholderPrefix)
	}
	if replace == nil {
		replace = IdentityReplace
	}
	return &BackfillWriter{dst: dst, maxPlaceholderLen: maxPlaceholderLen, replace: replace}
}

// Write buffers p and forwards every byte that can no longer become part of a
// placeholder. It always reports len(p) on success: Write retains only the
// bounded tail (at most maxPlaceholderLen bytes).
func (w *BackfillWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if err := w.process(p, false); err != nil {
		w.err = err
		return 0, err
	}
	return len(p), nil
}

// Flush marks the stream complete: a trailing candidate that never received a
// closing suffix is emitted as raw bytes (an incomplete prefix is not a
// placeholder). After Flush the writer still accepts more bytes, which are
// treated as a fresh continuation.
func (w *BackfillWriter) Flush() error {
	if w.err != nil {
		return w.err
	}
	if err := w.process(nil, true); err != nil {
		w.err = err
		return err
	}
	return nil
}

// process appends p to the internal window and drains everything decidable.
// final tells it that no more bytes will follow.
func (w *BackfillWriter) process(p []byte, final bool) error {
	if len(p) > 0 {
		w.buf = append(w.buf, p...)
	}
	buf := w.buf
	for len(buf) > 0 {
		i := bytes.Index(buf, []byte(PlaceholderPrefix))
		if i < 0 {
			if final {
				if err := w.emit(buf); err != nil {
					return err
				}
				buf = buf[:0]
				break
			}
			// Hold the longest tail that could still grow into the prefix;
			// everything before it is safe to forward.
			keep := suffixThatMayStartPlaceholder(buf)
			if err := w.emit(buf[:len(buf)-keep]); err != nil {
				return err
			}
			buf = buf[len(buf)-keep:]
			break
		}
		if i > 0 {
			if err := w.emit(buf[:i]); err != nil {
				return err
			}
			buf = buf[i:]
		}

		// buf begins with PlaceholderPrefix.
		if j := bytes.Index(buf[len(PlaceholderPrefix):], []byte(placeholderSuffix)); j >= 0 {
			candidateLen := len(PlaceholderPrefix) + j + len(placeholderSuffix)
			if candidateLen <= w.maxPlaceholderLen {
				token := string(buf[:candidateLen])
				if err := w.emit([]byte(w.replace(token))); err != nil {
					return err
				}
				buf = buf[candidateLen:]
				continue
			}
			// The suffix exists only beyond the window: this prefix can never
			// become a valid token, so the bytes are literal text.
		} else if !final && len(buf) < w.maxPlaceholderLen {
			break // the candidate may still complete within the window
		}
		// Emit the opening literally and rescan the remainder; a later prefix
		// inside the same window is still handled.
		if err := w.emit(buf[:len(PlaceholderPrefix)]); err != nil {
			return err
		}
		buf = buf[len(PlaceholderPrefix):]
	}
	w.buf = append(w.buf[:0], buf...)
	return nil
}

// emit forwards one decided span to dst.
func (w *BackfillWriter) emit(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	_, err := w.dst.Write(p)
	return err
}

// suffixThatMayStartPlaceholder returns the length of the longest suffix of
// buf that is a proper prefix of PlaceholderPrefix (at most
// len(PlaceholderPrefix)-1 bytes). Those bytes must be retained: the next
// chunk may complete the opening.
func suffixThatMayStartPlaceholder(buf []byte) int {
	max := min(len(PlaceholderPrefix)-1, len(buf))
	for n := max; n > 0; n-- {
		if bytes.Equal(buf[len(buf)-n:], []byte(PlaceholderPrefix[:n])) {
			return n
		}
	}
	return 0
}

// SSEEvent is one Server-Sent Events record produced by SSEDecoder.
//
// Raw is the exact slice of input bytes covered by the record, including its
// terminating line ending and any comment lines folded in from before it.
// Concatenating Raw over all returned events reproduces the input byte for
// byte, so a passthrough proxy can forward the original framing when it needs
// to. Raw is owned by the caller.
//
// Comments holds comment payloads (the text after ':' with one optional
// leading space removed) accumulated since the previous dispatch; comments
// never dispatch on their own.
//
// Event is the event: field, defaulting to "message" when absent while data is
// present. Data is the data: lines joined with "\n" (a record is dispatched
// only when at least one data: line was seen). ID is the last id: value seen
// on the stream, in effect at dispatch; it persists across records. Retry is
// the retry: value in milliseconds seen within this record and is 0 when
// absent; unlike ID it is not carried across records.
type SSEEvent struct {
	Raw      []byte
	Comments []string
	Event    string
	Data     string
	ID       string
	Retry    int
}

// SSEDecoder incrementally parses a Server-Sent Events stream. Feed chunks as
// they arrive; Close at end of stream. Line endings "\n", "\r\n", and lone
// "\r" are accepted, including terminators split across chunk boundaries.
//
// A record is dispatched by a blank line only when at least one data: line was
// seen; comment-only blocks fold into the next dispatched record so their bytes
// appear in its Raw. Close flushes a final record with no trailing blank line;
// if only comments/fields remain, a data-less record is returned so every
// input byte is still accounted for in some Raw.
//
// SSEDecoder is not safe for concurrent use.
type SSEDecoder struct {
	pending  []byte // partial line plus a possible trailing '\r'
	raw      []byte // bytes of the record being built
	comments []string
	data     []string
	hasData  bool
	event    string
	id       string
	retry    int
	closed   bool
}

// NewSSEDecoder returns a decoder with no stream state.
func NewSSEDecoder() *SSEDecoder { return &SSEDecoder{} }

// Feed consumes the next chunk and returns every record completed by it.
func (d *SSEDecoder) Feed(p []byte) []SSEEvent {
	if d.closed {
		return nil
	}
	d.pending = append(d.pending, p...)
	return d.consume(false)
}

// Close flushes the final record. It is idempotent: every call after the first
// returns nil, and Feed after Close returns nil.
func (d *SSEDecoder) Close() []SSEEvent {
	if d.closed {
		return nil
	}
	d.closed = true
	out := d.consume(true)
	if d.hasData || len(d.raw) > 0 {
		out = append(out, d.dispatch())
	}
	return out
}

// consume parses complete lines out of pending, dispatching records on blank
// lines. With final set, a trailing unterminated line is treated as a line and
// a trailing '\r' as a line ending.
func (d *SSEDecoder) consume(final bool) []SSEEvent {
	var out []SSEEvent
	buf := d.pending
	start := 0 // beginning of the current line within buf
	for i := 0; i < len(buf); {
		c := buf[i]
		if c != '\n' && c != '\r' {
			i++
			continue
		}
		n := 1
		if c == '\r' {
			if i+1 == len(buf) {
				if !final {
					break // a CRLF pair may straddle the chunk boundary
				}
			} else if buf[i+1] == '\n' {
				n = 2
			}
		}
		line := buf[start:i]
		d.raw = append(d.raw, buf[start:i+n]...)
		d.addLine(string(line))
		i += n
		start = i
		if len(line) == 0 {
			if d.hasData {
				out = append(out, d.dispatch())
			} else {
				// No data: nothing dispatches, but comment bytes fold forward.
				d.event = ""
				d.retry = 0
			}
		}
	}
	if final && start < len(buf) {
		line := buf[start:]
		d.raw = append(d.raw, line...)
		d.addLine(string(line))
		start = len(buf)
	}
	d.pending = append(d.pending[:0], buf[start:]...)
	return out
}

// addLine folds one parsed line into the record under construction.
func (d *SSEDecoder) addLine(line string) {
	if line == "" {
		return
	}
	if line[0] == ':' {
		d.comments = append(d.comments, strings.TrimPrefix(line[1:], " "))
		return
	}
	field, value, found := strings.Cut(line, ":")
	if found {
		value = strings.TrimPrefix(value, " ")
	}
	switch field {
	case "event":
		d.event = value
	case "data":
		d.data = append(d.data, value)
		d.hasData = true
	case "id":
		// A NUL byte in the value makes the field invalid per the SSE spec.
		if !strings.ContainsRune(value, 0) {
			d.id = value
		}
	case "retry":
		if allDigits(value) {
			if n, err := strconv.Atoi(value); err == nil {
				d.retry = n
			}
		}
	}
	// Unknown fields are ignored, as are malformed retry values.
}

// dispatch returns the record under construction and resets per-record state.
// The id field deliberately persists: it is the stream's last-event-id.
func (d *SSEDecoder) dispatch() SSEEvent {
	ev := SSEEvent{
		Raw:      d.raw,
		Comments: d.comments,
		Event:    d.event,
		Data:     strings.Join(d.data, "\n"),
		ID:       d.id,
		Retry:    d.retry,
	}
	if ev.Event == "" && d.hasData {
		ev.Event = "message"
	}
	d.raw = nil
	d.comments = nil
	d.data = nil
	d.hasData = false
	d.event = ""
	d.retry = 0
	return ev
}

// allDigits reports whether s is a non-empty run of ASCII digits, the only
// form the SSE spec accepts for retry.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
