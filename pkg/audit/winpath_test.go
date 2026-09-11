package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestStorePathWithSpaceAndCJK opens the WAL database inside a data directory
// whose name contains a space plus CJK and emoji, inserts, reads back and
// verifies. The same test runs on the Windows CI runner, exercising the
// %LOCALAPPDATA%-style Unicode path end to end.
func TestStorePathWithSpaceAndCJK(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "My 数据 🚀")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create data dir: %v", err)
	}
	path := filepath.Join(dir, "audit.db")

	s := openStoreAt(t, path)
	defer func() { _ = s.Close() }()

	if err := s.Record(sampleRecord(1)); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, err := s.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].Provider != "anthropic" {
		t.Fatalf("Query returned %+v, want one anthropic row", got)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var journalMode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	t.Logf("opened %q, journal_mode=%s, rows=%d", path, journalMode, len(got))
}
