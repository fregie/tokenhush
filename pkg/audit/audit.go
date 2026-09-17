// Package audit is the metadata-only write seam for tokenhush. Invariant 2
// keeps request and response plaintext off disk, so a Record carries nothing
// but metadata — timing, status, byte counts and the identifiers of the rules
// that fired — and an AuditSink is the only way any of it can be persisted.
// The default sink is NoopSink.
//
// The sink-level half of invariant 2 lives here; the end-to-end plaintext
// assertion belongs to the on-disk guard.
package audit

import (
	"context"
	"time"
)

// Record is one metadata-only audit entry for a proxied exchange. It has no
// body, content or plaintext field by construction.
type Record struct {
	Time       time.Time `json:"time"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	Redactions int       `json:"redactions"`
	RuleIDs    []string  `json:"rule_ids"`
}

// AuditSink is the single write seam for audit records. Implementations must
// not extend Record with content fields.
type AuditSink interface {
	// Record writes rec, or returns the error that prevented the write.
	Record(ctx context.Context, rec Record) error
}
