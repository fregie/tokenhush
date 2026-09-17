package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"testing"
	"time"
)

// contentField matches any field or JSON key that could carry request or
// response plaintext. Invariant 2 forbids them outright.
var contentField = regexp.MustCompile(`(?i)body|content|plaintext|payload|message|text`)

// sampleRecord is a fully populated record used across the sink-level tests.
func sampleRecord() Record {
	return Record{
		Time:       time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC),
		Method:     "POST",
		Path:       "/v1/messages",
		Status:     200,
		BytesIn:    42,
		BytesOut:   84,
		Redactions: 2,
		RuleIDs:    []string{"jwt", "pem"},
	}
}

// TestInvariant2JSONHasNoContentKeys pins the serialized key set: every key is
// metadata, and none names body, content or plaintext.
func TestInvariant2JSONHasNoContentKeys(t *testing.T) {
	raw, err := json.Marshal(sampleRecord())
	if err != nil {
		t.Fatalf("json.Marshal(Record) error = %v", err)
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
	}
	got := make([]string, 0, len(fields))
	for key := range fields {
		got = append(got, key)
	}
	sort.Strings(got)
	want := []string{"bytes_in", "bytes_out", "method", "path", "redactions", "rule_ids", "status", "time"}
	if !slices.Equal(got, want) {
		t.Fatalf("serialized keys = %v, want exactly %v", got, want)
	}
	for _, key := range got {
		if contentField.MatchString(key) {
			t.Errorf("serialized key %q names request/response content", key)
		}
	}
}

// TestInvariant2RecordFieldsAreMetadataOnly proves the struct itself cannot
// carry content: no body-as-bytes field and no field named for content.
func TestInvariant2RecordFieldsAreMetadataOnly(t *testing.T) {
	typ := reflect.TypeOf(Record{})
	if typ.NumField() == 0 {
		t.Fatal("Record has no fields")
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if contentField.MatchString(field.Name) {
			t.Errorf("Record field %q names request/response content", field.Name)
		}
		if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 {
			t.Errorf("Record field %q holds raw bytes", field.Name)
		}
	}
}

// TestInvariant2SinkHasSingleWriteMethod pins the seam to one write method:
// Must-NOT-Have #18 allows no read seam (no Query/AuditQuerier).
func TestInvariant2SinkHasSingleWriteMethod(t *testing.T) {
	typ := reflect.TypeOf((*AuditSink)(nil)).Elem()
	if typ.Kind() != reflect.Interface {
		t.Fatalf("AuditSink kind = %v, want interface", typ.Kind())
	}
	if got := typ.NumMethod(); got != 1 {
		t.Fatalf("AuditSink methods = %d, want exactly 1", got)
	}
	if got := typ.Method(0).Name; got != "Record" {
		t.Errorf("AuditSink method = %q, want %q", got, "Record")
	}
}

// TestInvariant2NoopSinkAcceptsRecord proves the default sink takes any record
// and succeeds.
func TestInvariant2NoopSinkAcceptsRecord(t *testing.T) {
	var sink AuditSink = NoopSink{}
	if err := sink.Record(context.Background(), sampleRecord()); err != nil {
		t.Fatalf("NoopSink.Record() error = %v, want nil", err)
	}
}

// TestInvariant2NoopSinkWritesNothing snapshots a temp directory around a
// record and requires it to stay byte-for-byte empty: the sink persists
// nothing, so no plaintext can reach disk through it.
func TestInvariant2NoopSinkWritesNothing(t *testing.T) {
	dir := t.TempDir()
	before := filesUnder(t, dir)
	sink := NoopSink{}
	if err := sink.Record(context.Background(), sampleRecord()); err != nil {
		t.Fatalf("NoopSink.Record() error = %v", err)
	}
	after := filesUnder(t, dir)
	if !slices.Equal(before, after) {
		t.Fatalf("NoopSink wrote into %s: before=%v after=%v", dir, before, after)
	}
	if len(after) != 0 {
		t.Fatalf("temp dir %s is not empty after a no-op record: %v", dir, after)
	}
}

// filesUnder returns the sorted, slash-separated paths of every regular file
// below dir. The slice is nil when the tree is empty.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	sort.Strings(files)
	return files
}
