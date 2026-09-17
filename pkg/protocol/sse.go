package protocol

import (
	"bytes"
	"errors"
)

// Span is a half-open byte range [Start, End).
type Span struct{ Start, End int }

// Event is one fully decoded SSE record.
type Event struct {
	// Event is the record's "event:" value, or "message" when the record
	// carried no event field or an empty one.
	Event string

	// Data is every "data:" value in the record joined with '\n'; the
	// final value carries no trailing newline.
	Data []byte

	// ID is this record's own "id:" value when HasID is true; otherwise
	// it is the most recent id seen on the stream (id fields persist).
	ID string

	// HasID reports whether this record carried its own "id:" field.
	HasID bool

	// Retry is the record's "retry:" value when present, verbatim.
	// Unlike ID, retry does not persist across records.
	Retry string

	// Raw is the exact record bytes as fed: every line since the previous
	// dispatch (field or comment) plus each line's terminator(s), up to
	// and including the blank line that dispatched the record, or the
	// final bytes for a record flushed by Close.
	Raw []byte

	// DataSpans holds the span of the data value inside Raw when the
	// record contained exactly one canonical "data:" line; it is nil
	// otherwise (multiple data lines, or a colon-less "data" line).
	DataSpans []Span
}

// ErrClosed reports that Feed was called after Close. It is the only error
// the decoder returns: SSE itself has no malformed input.
var ErrClosed = errors.New("protocol: sse decoder closed")

// Decoder incrementally decodes a Server-Sent Events stream.
//
// Chunks may split a record at any byte boundary: Feed buffers the partial
// line or CRLF pair until a later chunk completes it. Line terminators are
// "\n", "\r\n" and a lone "\r". Comment lines (":...") never contribute to
// Data and fold into the next dispatched record's Raw; unknown fields are
// ignored. A blank line dispatches a record only when at least one data:
// line was seen since the previous dispatch, and clears the pending
// event/retry fields when it does not; the last id persists regardless.
// Close flushes a trailing record that has data and is idempotent.
//
// A Decoder is not safe for concurrent use. The zero value is not usable;
// use NewDecoder.
type Decoder struct {
	buf  []byte // bytes of the current record, from its start to scan
	scan int    // offset in buf up to which lines are consumed

	event string
	data  []byte
	dataN int
	spans []Span
	id    string
	hasID bool
	retry string

	closed bool
}

// NewDecoder returns a Decoder ready to accept its first chunk.
func NewDecoder() *Decoder { return &Decoder{} }

// Feed consumes the next chunk of the stream and returns every record the
// chunk completes. Chunks may split a record at any byte boundary; every
// byte fed is retained byte-exactly in some record's Raw, except a
// trailing data-less tail that Close drops.
func (d *Decoder) Feed(chunk []byte) ([]Event, error) {
	if d.closed {
		return nil, ErrClosed
	}
	d.buf = append(d.buf, chunk...)
	return d.scanLines(false), nil
}

// Close flushes a trailing record that has no terminating blank line and
// marks the decoder closed. It is idempotent: a second call returns an
// empty result and no error.
func (d *Decoder) Close() ([]Event, error) {
	if d.closed {
		return []Event{}, nil
	}
	d.closed = true
	events := d.scanLines(true)
	if d.dataN > 0 {
		events = append(events, d.dispatch())
	}
	return events, nil
}

// scanLines consumes complete lines in order, dispatching a record on every
// blank line that follows at least one data: line. With final set, the end
// of buf terminates the last line (used by Close).
func (d *Decoder) scanLines(final bool) []Event {
	var events []Event
	for {
		start, end, next, ok := d.nextLine(final)
		if !ok {
			return events
		}
		d.scan = next
		if start == end {
			if d.dataN > 0 {
				events = append(events, d.dispatch())
			} else {
				d.event, d.retry = "", "" // comments fold forward; id persists
			}
			continue
		}
		d.field(start, end)
	}
}

// nextLine locates the next line at d.scan. It returns the line's content
// range [start, end), the offset just past its terminator, and whether a
// complete line is available. A line ends at "\n", "\r\n" or a lone "\r"; a
// trailing "\r" waits for the next chunk unless final is set.
func (d *Decoder) nextLine(final bool) (start, end, next int, ok bool) {
	start = d.scan
	for i := start; i < len(d.buf); i++ {
		switch d.buf[i] {
		case '\n':
			return start, i, i + 1, true
		case '\r':
			if i+1 < len(d.buf) {
				if d.buf[i+1] == '\n' {
					return start, i, i + 2, true
				}
				return start, i, i + 1, true
			}
			if final {
				return start, i, i + 1, true
			}
			return 0, 0, 0, false
		}
	}
	if final && start < len(d.buf) {
		return start, len(d.buf), len(d.buf), true
	}
	return 0, 0, 0, false
}

// field folds one non-blank line into the pending record. A colon-less line
// is a field with an empty value; exactly one space after the colon is
// stripped from the value. Comment and unknown-field lines are ignored.
func (d *Decoder) field(start, end int) {
	line := d.buf[start:end]
	if line[0] == ':' {
		return
	}
	colon := bytes.IndexByte(line, ':')
	name, value := line, []byte(nil)
	vstart := end // a colon-less value is empty and sits at line end
	if colon >= 0 {
		name, value = line[:colon], line[colon+1:]
		vstart = start + colon + 1
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
			vstart++
		}
	}
	switch string(name) {
	case "data":
		d.addData(value, vstart, colon >= 0)
	case "event":
		d.event = string(value)
	case "id":
		d.id, d.hasID = string(value), true
	case "retry":
		d.retry = string(value)
	}
}

// addData appends one data-line value to the record, joining values with
// '\n'. A value span is kept only for a record's single canonical data:
// line; a colon-less data line has no rewritable span.
func (d *Decoder) addData(value []byte, vstart int, canonical bool) {
	if d.dataN > 0 {
		d.data = append(d.data, '\n')
	}
	d.data = append(d.data, value...)
	d.dataN++
	d.spans = d.spans[:0]
	if d.dataN == 1 && canonical {
		d.spans = append(d.spans, Span{Start: vstart, End: vstart + len(value)})
	}
}

// dispatch builds the Event for the pending record and resets per-record
// state. Raw covers every fed byte of the record, including the blank
// line's terminator(s). The returned slices are copies, independent of
// decoder state.
func (d *Decoder) dispatch() Event {
	ev := Event{
		Event: "message",
		Data:  append([]byte(nil), d.data...),
		ID:    d.id,
		HasID: d.hasID,
		Retry: d.retry,
		Raw:   append([]byte(nil), d.buf[:d.scan]...),
	}
	if d.event != "" {
		ev.Event = d.event
	}
	if d.dataN == 1 {
		ev.DataSpans = append([]Span(nil), d.spans...)
	}
	d.buf = d.buf[d.scan:]
	d.scan = 0
	d.event = ""
	d.data, d.dataN = d.data[:0], 0
	d.spans = d.spans[:0]
	d.hasID, d.retry = false, ""
	return ev
}
