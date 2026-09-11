package audit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/platform"
)

// memSecrets is a minimal in-memory platform.SecretStore for tests.
type memSecrets struct {
	mu sync.Mutex
	m  map[string]string
}

func newMemSecrets() *memSecrets { return &memSecrets{m: map[string]string{}} }

func (s *memSecrets) Get(service, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[service+"\x00"+key]
	if !ok {
		return "", fmt.Errorf("%w: %s/%s", platform.ErrNotFound, service, key)
	}
	return v, nil
}

func (s *memSecrets) Set(service, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[service+"\x00"+key] = value
	return nil
}

func (s *memSecrets) Delete(service, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := service + "\x00" + key
	if _, ok := s.m[k]; !ok {
		return platform.ErrNotFound
	}
	delete(s.m, k)
	return nil
}

func (s *memSecrets) Backend() string { return "memory" }

func testKeys() (hashKey, anchorKey []byte) {
	hashKey = bytes.Repeat([]byte{0x11}, keyLen)
	anchorKey = bytes.Repeat([]byte{0x22}, keyLen)
	return hashKey, anchorKey
}

func openStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	hashKey, anchorKey := testKeys()
	s, err := OpenStore(StoreConfig{
		Path:      path,
		Secrets:   newMemSecrets(),
		HashKey:   hashKey,
		AnchorKey: anchorKey,
	})
	if err != nil {
		t.Fatalf("OpenStore(%q): %v", path, err)
	}
	return s
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return openStoreAt(t, filepath.Join(t.TempDir(), "audit.db"))
}

func sampleRecord(i int) Record {
	return Record{
		TS:         int64(1_700_000_000_000 + i),
		Provider:   "anthropic",
		Path:       "/v1/messages",
		Method:     "POST",
		Status:     200,
		ReqBytes:   int64(100 + i),
		RespBytes:  int64(200 + i),
		Redactions: i,
		Detectors:  []string{"prefix", "email"},
		Client:     "claude-code",
	}
}

func TestAppend(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	for i := 1; i <= 4; i++ {
		if err := s.Record(sampleRecord(i)); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}

	got, err := s.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("Query returned %d rows, want 4", len(got))
	}
	for i, rec := range got {
		want := sampleRecord(i + 1)
		if rec.ID != int64(i+1) {
			t.Fatalf("row %d id = %d, want %d", i, rec.ID, i+1)
		}
		if rec.Provider != want.Provider || rec.Path != want.Path || rec.Method != want.Method {
			t.Fatalf("row %d metadata = %+v, want %+v", i, rec, want)
		}
		if rec.ReqBytes != want.ReqBytes || rec.RespBytes != want.RespBytes || rec.Redactions != want.Redactions {
			t.Fatalf("row %d counters = %+v, want %+v", i, rec, want)
		}
		if len(rec.Detectors) != 2 || rec.Detectors[0] != "prefix" || rec.Detectors[1] != "email" {
			t.Fatalf("row %d detectors = %v, want [prefix email]", i, rec.Detectors)
		}
		if len(rec.Hash) != 32 || len(rec.PrevHash) != 32 {
			t.Fatalf("row %d hash sizes = %d/%d, want 32/32", i, len(rec.Hash), len(rec.PrevHash))
		}
		if i > 0 && !bytes.Equal(rec.PrevHash, got[i-1].Hash) {
			t.Fatalf("row %d prev_hash does not link to row %d", i+1, i)
		}
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestAppendDefaultsTimestamp(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	if err := s.Record(Record{Provider: "openai", Path: "/v1/chat/completions", Method: "POST"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, err := s.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].TS == 0 {
		t.Fatalf("expected one row with a generated timestamp, got %+v", got)
	}
}

func TestQueryFilters(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	if err := s.Record(Record{TS: 1000, Provider: "anthropic", Path: "/a", Method: "POST"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Record{TS: 2000, Provider: "openai", Path: "/b", Method: "POST"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(Record{TS: 3000, Provider: "openai", Path: "/c", Method: "POST"}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if got, _ := s.Query(ctx, Query{Since: time.UnixMilli(2000)}); len(got) != 2 {
		t.Fatalf("Since filter: got %d rows, want 2", len(got))
	}
	if got, _ := s.Query(ctx, Query{Until: time.UnixMilli(2000)}); len(got) != 2 {
		t.Fatalf("Until filter: got %d rows, want 2", len(got))
	}
	if got, _ := s.Query(ctx, Query{Provider: "openai"}); len(got) != 2 {
		t.Fatalf("Provider filter: got %d rows, want 2", len(got))
	}
	if got, _ := s.Query(ctx, Query{Limit: 1}); len(got) != 1 {
		t.Fatalf("Limit: got %d rows, want 1", len(got))
	}
}

func TestRetention(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	now := time.UnixMilli(1_700_000_000_000)
	oldTS := now.AddDate(0, 0, -40).UnixMilli()
	newTS := now.AddDate(0, 0, -1).UnixMilli()
	for i := range 5 {
		if err := s.Record(Record{TS: oldTS + int64(i), Provider: "anthropic", Path: "/old", Method: "POST"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		if err := s.Record(Record{TS: newTS + int64(i), Provider: "anthropic", Path: "/new", Method: "POST"}); err != nil {
			t.Fatal(err)
		}
	}

	deleted, err := s.PruneBefore(now.AddDate(0, 0, -7))
	if err != nil {
		t.Fatalf("PruneBefore: %v", err)
	}
	if deleted != 5 {
		t.Fatalf("PruneBefore deleted %d rows, want 5", deleted)
	}

	got, err := s.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 3 || got[0].ID != 6 {
		t.Fatalf("after retention: %d rows starting at id %d, want 3 starting at 6", len(got), firstID(got))
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify after retention: %v", err)
	}

	aTip, ok := s.anchors.tip()
	if !ok {
		t.Fatal("retention did not write an anchor")
	}
	if aTip.RowID != 6 {
		t.Fatalf("anchor row id = %d, want 6 (first surviving row)", aTip.RowID)
	}
}

func TestRetentionAlwaysKeepsTip(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	oldTS := time.Now().AddDate(0, 0, -90).UnixMilli()
	if err := s.Record(Record{TS: oldTS, Provider: "anthropic", Path: "/only", Method: "POST"}); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.PruneBefore(time.Now())
	if err != nil {
		t.Fatalf("PruneBefore: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("PruneBefore deleted %d rows, want 0 (tip is retained)", deleted)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func firstID(recs []Record) int64 {
	if len(recs) == 0 {
		return 0
	}
	return recs[0].ID
}

func TestCrashWindowRowCommitWitnessMiss(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	if err := s.Record(sampleRecord(1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.insertRow(sampleRecord(2)); err != nil {
		t.Fatalf("insertRow (simulated crash): %v", err)
	}
	if tip, _ := s.witness.tip(); tip.RowID != 1 {
		t.Fatalf("precondition: witness tip = %d, want 1", tip.RowID)
	}

	if err := s.Verify(); err != nil {
		t.Fatalf("Verify should heal the one-append crash window: %v", err)
	}
	if tip, _ := s.witness.tip(); tip.RowID != 2 {
		t.Fatalf("after heal: witness tip = %d, want 2", tip.RowID)
	}
	hw, ok, err := s.readHighWater()
	if err != nil || !ok || hw.RowID != 2 {
		t.Fatalf("after heal: high-water = %+v ok=%v err=%v, want row 2", hw, ok, err)
	}
}

func TestCrashWindowWitnessHighWaterMiss(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	if err := s.Record(sampleRecord(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.secrets.Delete(secretService, highWaterKey); err != nil {
		t.Fatalf("simulate high-water loss: %v", err)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify should re-publish a one-entry high-water gap: %v", err)
	}
	if _, ok, _ := s.readHighWater(); !ok {
		t.Fatal("high-water was not re-published")
	}
}

func TestVerifyDetectsRowTamper(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	if err := s.Record(sampleRecord(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(sampleRecord(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE requests SET path = '/tampered' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after row tamper = %v, want ErrTampered", err)
	}
}

func TestVerifyDetectsTipTruncation(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	for i := 1; i <= 3; i++ {
		if err := s.Record(sampleRecord(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM requests WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after tip truncation = %v, want ErrTampered", err)
	}
}

func TestVerifyDetectsForgedAnchor(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	now := time.UnixMilli(1_700_000_000_000)
	oldTS := now.AddDate(0, 0, -40).UnixMilli()
	for i := range 3 {
		if err := s.Record(Record{TS: oldTS + int64(i), Provider: "anthropic", Path: "/old", Method: "POST"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		if err := s.Record(Record{TS: now.UnixMilli() + int64(i), Provider: "anthropic", Path: "/new", Method: "POST"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PruneBefore(now.AddDate(0, 0, -7)); err != nil {
		t.Fatal(err)
	}

	anchorPath := s.path + anchorSuffix
	data, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Replace(data, []byte(`"row_hash":"`), []byte(`"row_hash":"ff`), 1)
	if bytes.Equal(forged, data) {
		t.Fatal("could not forge anchor: row_hash not found")
	}
	if err := os.WriteFile(anchorPath, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after forged anchor = %v, want ErrTampered", err)
	}
}

func TestReopenVerifiesCleanState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	secrets := newMemSecrets()
	hashKey, anchorKey := testKeys()

	s, err := OpenStore(StoreConfig{Path: path, Secrets: secrets, HashKey: hashKey, AnchorKey: anchorKey})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	for i := 1; i <= 3; i++ {
		if err := s.Record(sampleRecord(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(StoreConfig{Path: path, Secrets: secrets, HashKey: hashKey, AnchorKey: anchorKey})
	if err != nil {
		t.Fatalf("reopen with the same secret store: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if err := reopened.Verify(); err != nil {
		t.Fatalf("Verify after reopen: %v", err)
	}
}

func TestVerifyDetectsHighWaterRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	secrets := newMemSecrets()
	hashKey, anchorKey := testKeys()

	s, err := OpenStore(StoreConfig{Path: path, Secrets: secrets, HashKey: hashKey, AnchorKey: anchorKey})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	for i := 1; i <= 3; i++ {
		if err := s.Record(sampleRecord(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a high-water rollback: the witness still proves row 3, but the
	// bounded high-water was rolled back below the documented one-entry window.
	if err := secrets.Delete(secretService, highWaterKey); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := OpenStore(StoreConfig{Path: path, Secrets: secrets, HashKey: hashKey, AnchorKey: anchorKey})
	if err == nil {
		_ = rolledBack.Close()
		t.Fatal("reopen with a rolled-back high-water returned nil error")
	}
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("reopen with a rolled-back high-water = %v, want ErrTampered", err)
	}
}

func TestOpenRejectsCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	if err := os.WriteFile(path, []byte("this is not a sqlite database at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	hashKey, anchorKey := testKeys()
	s, err := OpenStore(StoreConfig{
		Path:      path,
		Secrets:   newMemSecrets(),
		HashKey:   hashKey,
		AnchorKey: anchorKey,
	})
	if err == nil {
		_ = s.Close()
		t.Fatal("OpenStore on a corrupt database returned nil error")
	}
}

func TestOpenRejectsReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits only")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	hashKey, anchorKey := testKeys()
	s, err := OpenStore(StoreConfig{
		Path:      filepath.Join(dir, "audit.db"),
		Secrets:   newMemSecrets(),
		HashKey:   hashKey,
		AnchorKey: anchorKey,
	})
	if err == nil {
		_ = s.Close()
		t.Fatal("OpenStore in a read-only directory returned nil error")
	}
}

func TestChainLogCorruptLineFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.witness")
	if err := os.WriteFile(path, []byte("this is not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, anchorKey := testKeys()
	if _, err := loadChainLog(path, "witness", anchorKey); !errors.Is(err, ErrTampered) {
		t.Fatalf("loadChainLog on corrupt input = %v, want ErrTampered", err)
	}
}

func TestChainLogCompaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.anchors")
	hashKey, anchorKey := testKeys()
	_ = hashKey
	log, err := loadChainLog(path, "anchor", anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 8; i++ {
		if _, err := log.append(int64(i), bytes.Repeat([]byte{byte(i)}, 32)); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.compact(3); err != nil {
		t.Fatalf("compact: %v", err)
	}
	reloaded, err := loadChainLog(path, "anchor", anchorKey)
	if err != nil {
		t.Fatalf("reload after compaction: %v", err)
	}
	entries, err := reloaded.read()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 || entries[0].Kind != sealKind {
		t.Fatalf("compacted log = %d entries first=%q, want 4 starting with a seal", len(entries), entries[0].Kind)
	}
	if entries[1].RowID != 6 {
		t.Fatalf("first kept entry row id = %d, want 6", entries[1].RowID)
	}
	tip, ok := reloaded.tip()
	if !ok || tip.RowID != 8 {
		t.Fatalf("compacted tip = %+v ok=%v, want row 8", tip, ok)
	}
}

func TestOpenStoreRejectsMissingSecrets(t *testing.T) {
	_, err := OpenStore(StoreConfig{Path: filepath.Join(t.TempDir(), "audit.db")})
	if !errors.Is(err, ErrSecretStoreRequired) {
		t.Fatalf("OpenStore without secrets = %v, want ErrSecretStoreRequired", err)
	}
}

func TestNoContentColumn(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	rows, err := s.db.Query(`PRAGMA table_info(requests)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	allowed := map[string]bool{
		"id": true, "ts": true, "provider": true, "path": true, "method": true,
		"status": true, "req_bytes": true, "resp_bytes": true, "redactions": true,
		"detectors": true, "client": true, "prev_hash": true, "hash": true,
	}
	count := 0
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			dflt       sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &primaryKey); err != nil {
			t.Fatal(err)
		}
		count++
		if !allowed[name] {
			t.Fatalf("unexpected column %q in the metadata-only requests table", name)
		}
	}
	if count != len(allowed) {
		t.Fatalf("requests has %d columns, want exactly %d", count, len(allowed))
	}
}

func TestEncodedCanonicalIsStable(t *testing.T) {
	detectors := encodeDetectors([]string{"prefix"})
	if detectors != `["prefix"]` {
		t.Fatalf("encodeDetectors = %q", detectors)
	}
	if encodeDetectors(nil) != "[]" {
		t.Fatalf("empty detectors should encode as []")
	}
	if got := decodeDetectors(`["a","b"]`); len(got) != 2 || got[0] != "a" {
		t.Fatalf("decodeDetectors = %v", got)
	}
	if got := decodeDetectors(""); got != nil {
		t.Fatalf("decodeDetectors(\"\") = %v, want nil", got)
	}
}

func TestClampRetentionDays(t *testing.T) {
	cases := []struct{ in, want int }{{0, 14}, {1, 7}, {7, 7}, {14, 14}, {30, 30}, {99, 30}}
	for _, c := range cases {
		if got := clampRetentionDays(c.in); got != c.want {
			t.Fatalf("clampRetentionDays(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestRetentionWindow(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	if s.RetentionDays() != defaultRetentionDays {
		t.Fatalf("RetentionDays = %d, want %d", s.RetentionDays(), defaultRetentionDays)
	}
	if got := strings.TrimSpace(s.Path()); got == "" {
		t.Fatal("Path is empty")
	}
}
