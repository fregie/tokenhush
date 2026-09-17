package audit

import "context"

// NoopSink is the default AuditSink: it accepts every record and persists
// nothing, so metadata stays in memory unless a later wave opts into a writer.
type NoopSink struct{}

// Record implements AuditSink.
func (NoopSink) Record(context.Context, Record) error { return nil }

var _ AuditSink = NoopSink{}
