package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// contentField matches any field or JSON key that could carry request or
// response plaintext. Invariant 2 forbids them outright.
var contentField = regexp.MustCompile(`(?i)body|content|plaintext|payload|message|text`)

// readSeamMethod matches the method names a read or query path would use. The
// sink is write-only by construction, so a method named for reading is itself
// the violation.
var readSeamMethod = regexp.MustCompile(`(?i)^(query|read|get|fetch|list|scan|lookup)$`)

// bannedSinkSymbols must not exist anywhere in the audit package: an exported
// query type or constructor would be a read seam by another name.
var bannedSinkSymbols = []string{"Query", "AuditQuerier", "NoopQuerier"}

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

// TestInvariant2NoPlaintextOnDisk is the sink-level half of invariant 2 and
// the test the invariant table in docs/security.md names at this path. It
// proves four things without leaving the package: the serialized Record
// carries metadata keys only, no Record field can hold content or raw bytes,
// the sink surface is exactly one write method with no read/query seam, and
// the default sink writes nothing into a temp directory - with a deliberately
// writing scratch sink proving the empty-tree predicate has teeth. The
// run-level half that drives the real binary end to end is
// TestOndiskGuardRunLevelPlaintext in internal/guards/ondisk_guard_test.go.
func TestInvariant2NoPlaintextOnDisk(t *testing.T) {
	t.Run("record JSON carries metadata keys only", assertJSONMetadataOnly)
	t.Run("record fields cannot carry content", assertRecordFieldsMetadataOnly)
	t.Run("sink surface is one write method with no query seam", func(t *testing.T) {
		assertSinkSingleWriteMethod(t)
		assertNoQuerySeam(t)
	})
	t.Run("sink persists nothing and the snapshot fires on a writer", assertSinkPersistsNothing)
}

// assertJSONMetadataOnly pins the serialized key set: every key is metadata,
// and none names body, content or plaintext. An added content field changes
// the exact set, which is the point of the comparison.
func assertJSONMetadataOnly(t *testing.T) {
	t.Helper()
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

// TestInvariant2JSONHasNoContentKeys is the focused form of the serialized-key
// assertion inside the named sink-level test.
func TestInvariant2JSONHasNoContentKeys(t *testing.T) {
	assertJSONMetadataOnly(t)
}

// assertRecordFieldsMetadataOnly proves the struct itself cannot carry
// content: no body-as-bytes field and no field named for content.
func assertRecordFieldsMetadataOnly(t *testing.T) {
	t.Helper()
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

// TestInvariant2RecordFieldsAreMetadataOnly is the focused form of the field
// assertion inside the named sink-level test.
func TestInvariant2RecordFieldsAreMetadataOnly(t *testing.T) {
	assertRecordFieldsMetadataOnly(t)
}

// assertSinkSingleWriteMethod pins the seam to one write method:
// Must-NOT-Have #18 allows no read seam (no Query/AuditQuerier).
func assertSinkSingleWriteMethod(t *testing.T) {
	t.Helper()
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

// TestInvariant2SinkHasSingleWriteMethod is the focused form of the interface
// assertion inside the named sink-level test.
func TestInvariant2SinkHasSingleWriteMethod(t *testing.T) {
	assertSinkSingleWriteMethod(t)
}

// assertNoQuerySeam parses the package's production sources and fails when any
// read path exists: a declaration or method named Query, AuditQuerier or
// NoopQuerier, or a method a read seam would carry. The interface assertion
// above covers AuditSink; this covers the package surface around it.
func assertNoQuerySeam(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the audit package directory: %v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch decl := node.(type) {
			case *ast.FuncDecl:
				if slices.Contains(bannedSinkSymbols, decl.Name.Name) || readSeamMethod.MatchString(decl.Name.Name) {
					t.Errorf("%s declares %s, a read/query seam", name, decl.Name.Name)
				}
			case *ast.TypeSpec:
				if slices.Contains(bannedSinkSymbols, decl.Name.Name) {
					t.Errorf("%s declares type %s, a read/query seam", name, decl.Name.Name)
				}
			case *ast.ValueSpec:
				for _, ident := range decl.Names {
					if slices.Contains(bannedSinkSymbols, ident.Name) {
						t.Errorf("%s declares %s, a read/query seam", name, ident.Name)
					}
				}
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("no production Go files found in the package directory: the query-seam assertion would be vacuous")
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

// scratchSink is a deliberately writing AuditSink: the positive control that
// proves the empty-tree predicate below can notice a persisting sink, so the
// NoopSink assertion cannot pass vacuously.
type scratchSink struct{ dir string }

// Record writes a file, exactly what invariant 2 forbids a sink from doing.
func (s scratchSink) Record(context.Context, Record) error {
	return os.WriteFile(filepath.Join(s.dir, "scratch-plaintext.txt"), []byte("scratch body"), 0o600)
}

var _ AuditSink = scratchSink{}

// assertSinkPersistsNothing snapshots a temp directory around one recorded
// call. The scratch sink must change the tree - proving the snapshot predicate
// fires - and the default NoopSink must leave it byte-identical and empty.
func assertSinkPersistsNothing(t *testing.T) {
	t.Helper()
	cases := []struct {
		name      string
		sink      func(dir string) AuditSink
		wantWrite bool
	}{
		{
			name:      "scratch sink writes, so the empty-tree assertion is not vacuous",
			sink:      func(dir string) AuditSink { return scratchSink{dir: dir} },
			wantWrite: true,
		},
		{
			name: "NoopSink leaves the tree byte-identical and empty",
			sink: func(string) AuditSink { return NoopSink{} },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			before := snapshotTree(t, dir)
			if err := tc.sink(dir).Record(context.Background(), sampleRecord()); err != nil {
				t.Fatalf("Record() error = %v", err)
			}
			after := snapshotTree(t, dir)
			if wrote := !slices.Equal(before, after); wrote != tc.wantWrite {
				t.Fatalf("sink wrote = %v, want %v (before=%v after=%v)", wrote, tc.wantWrite, before, after)
			}
			if !tc.wantWrite && len(after) != 0 {
				t.Fatalf("temp dir is not empty after a no-op record: %v", after)
			}
		})
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

// fileStamp is one snapshot entry: a file's path, byte length and SHA-256
// digest. Two trees are byte-identical exactly when their stamps are equal.
type fileStamp struct {
	path   string
	size   int64
	digest [sha256.Size]byte
}

// String renders a stamp for failure messages.
func (s fileStamp) String() string {
	return fmt.Sprintf("%s (%d bytes, sha256 %x)", s.path, s.size, s.digest)
}

// snapshotTree returns the sorted byte-level fingerprint of every regular file
// below dir. An empty tree yields an empty snapshot.
func snapshotTree(t *testing.T, dir string) []fileStamp {
	t.Helper()
	var stamps []fileStamp
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
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		stamps = append(stamps, fileStamp{
			path:   filepath.ToSlash(rel),
			size:   int64(len(data)),
			digest: sha256.Sum256(data),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	slices.SortFunc(stamps, func(a, b fileStamp) int { return strings.Compare(a.path, b.path) })
	return stamps
}

// filesUnder returns the sorted, slash-separated paths of every regular file
// below dir. The slice is nil when the tree is empty.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	stamps := snapshotTree(t, dir)
	if len(stamps) == 0 {
		return nil
	}
	paths := make([]string, 0, len(stamps))
	for _, stamp := range stamps {
		paths = append(paths, stamp.path)
	}
	return paths
}
