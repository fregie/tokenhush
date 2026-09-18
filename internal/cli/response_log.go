package cli

import (
	"fmt"
	"io"

	"github.com/fregie/tokenhush/pkg/redact"
)

// responseLog decorates the session Backfiller for the client-bound path. It
// restores placeholders and emits one metadata-only line per call that actually
// restored something, so an operator can see the reverse direction of every
// request redaction. It prints only a count, never a secret or a body, and it
// shares the run command's redaction-log switch.
type responseLog struct {
	inner   *redact.Backfiller
	stderr  io.Writer
	enabled bool
}

// newResponseLog wraps backfiller for the response path.
func newResponseLog(backfiller *redact.Backfiller, stderr io.Writer, enabled bool) *responseLog {
	return &responseLog{inner: backfiller, stderr: stderr, enabled: enabled}
}

// Backfill implements proxy.Backfiller. A buffered response arrives as one
// whole body and logs its total; an SSE token arrives one token at a time and
// logs one line per restored placeholder. A foreign or excluded token restores
// nothing and stays silent.
func (l *responseLog) Backfill(body []byte) []byte {
	out, restored := l.inner.BackfillCount(body)
	if restored > 0 && l.enabled && l.stderr != nil {
		fmt.Fprintf(l.stderr, "tokenhush: restored response placeholders=%d\n", restored)
	}
	return out
}
