package audit

import "context"

// NoopSink discards every record. It is the default implementation injected
// before the real store is wired in.
type NoopSink struct{}

// Record implements AuditSink and always succeeds.
func (NoopSink) Record(Record) error { return nil }

// NoopQuerier returns no records. It is the default implementation injected
// into the control API before the real store is wired in.
type NoopQuerier struct{}

// Query implements AuditQuerier and always returns an empty, non-nil slice.
func (NoopQuerier) Query(context.Context, Query) ([]Record, error) {
	return []Record{}, nil
}

var _ AuditSink = NoopSink{}
var _ AuditQuerier = NoopQuerier{}
