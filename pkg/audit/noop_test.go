package audit

import (
	"context"
	"testing"
)

func TestNoopSinkRecordReturnsNil(t *testing.T) {
	var sink AuditSink = NoopSink{}
	if err := sink.Record(Record{Provider: "test", Path: "/v1/messages"}); err != nil {
		t.Fatalf("NoopSink.Record() error = %v, want nil", err)
	}
}

func TestNoopQuerierReturnsEmptyNonNilSlice(t *testing.T) {
	var querier AuditQuerier = NoopQuerier{}
	got, err := querier.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("NoopQuerier.Query() error = %v, want nil", err)
	}
	if got == nil {
		t.Fatal("NoopQuerier.Query() returned a nil slice, want an empty non-nil slice")
	}
	if len(got) != 0 {
		t.Fatalf("NoopQuerier.Query() returned %d records, want 0", len(got))
	}
}
