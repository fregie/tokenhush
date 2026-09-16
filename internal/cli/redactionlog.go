package cli

import (
	"fmt"
	"io"
	"sync"

	"github.com/fregie/tokenhush/pkg/proxy"
)

// redactionLogger renders the pipeline's RedactionEvents as one masked line
// each on the daemon's diagnostics stream. A redact line carries the detector
// type, the matched byte length and the masked value (never the value); a block
// line carries only the detector type, because a block aborts before egress. A
// walk-failure line names the action and says the body was forwarded unchanged:
// it must never claim a redaction, and it prints none of the empty detector
// fields (a walk failure skips the response body, it does not redact it).
//
// The pipeline calls Report from concurrent request goroutines, so a mutex
// serialises whole-line writes, and a recover guard keeps a rendering bug from
// failing a request — mirroring the audit rule that a diagnostic never changes
// the request outcome.
type redactionLogger struct {
	mu sync.Mutex
	w  io.Writer
}

// newRedactionLogger returns a logger writing to w.
func newRedactionLogger(w io.Writer) *redactionLogger {
	return &redactionLogger{w: w}
}

// Report renders one event on a single line. It never returns an error: a write
// failure or a render panic is swallowed so the data plane is unaffected.
func (l *redactionLogger) Report(ev proxy.RedactionEvent) {
	defer func() { _ = recover() }()
	if l == nil || l.w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch ev.Action {
	case proxy.RedactionActionBlock:
		fmt.Fprintf(l.w, "tokenhush: blocked %s by content policy: %s\n", ev.Direction, ev.Type)
	case proxy.RedactionActionResponseWalkFailed, proxy.RedactionActionSSEWalkFailed:
		fmt.Fprintf(l.w, "tokenhush: unparseable %s body skipped: %s (forwarded unchanged)\n", ev.Direction, ev.Action)
	default:
		fmt.Fprintf(l.w, "tokenhush: redacted %s %s (len=%d) %s\n",
			ev.Direction, ev.Type, ev.Length, ev.Masked)
	}
}
