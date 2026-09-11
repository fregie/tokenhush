package audit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// recordSample appends n deterministic sample rows, failing on the first error.
func recordSample(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if err := s.Record(sampleRecord(i)); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
}

// TestChainVerify is the W5.2 acceptance matrix for the HMAC chain and its
// tamper detection. Every negative case asserts errors.Is(err, ErrTampered) —
// never a bare non-nil check — so a guard that fails with an unrelated error
// cannot be mistaken for a working detector.
func TestChainVerify(t *testing.T) {
	t.Run("intact_chain_passes", testChainVerifyIntact)
	t.Run("row_tamper_fails", testChainVerifyRowTamper)
	t.Run("retention_keeps_verifiable", testChainVerifyRetention)
	t.Run("forged_anchor_rejected", testChainVerifyForgedAnchor)
	t.Run("tip_truncation_fails", testChainVerifyTipTruncation)
	t.Run("crash_between_anchor_and_delete_verifiable", testChainVerifyAnchorDeleteCrash)
	t.Run("crash_row_commit_witness_miss_heals", testChainVerifyRowCommitCrash)
	t.Run("crash_witness_high_water_miss_heals", testChainVerifyWitnessCrash)
	t.Run("tip_truncation_and_witness_rollback_fails", testChainVerifyWitnessRollback)
	t.Run("tip_truncation_and_forged_witness_fails", testChainVerifyForgedWitness)
	t.Run("corrupt_witness_line_fails", testChainVerifyCorruptWitness)
	t.Run("stale_reopen_detects_row_tamper", testChainVerifyStaleReopen)
}

func testChainVerifyIntact(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	recordSample(t, s, 4)

	got, err := s.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("recorded %d rows, want 4 (non-vacuous verify)", len(got))
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify on an intact chain = %v, want nil", err)
	}
}

func testChainVerifyRowTamper(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	recordSample(t, s, 3)
	if err := s.Verify(); err != nil {
		t.Fatalf("precondition: Verify on a clean chain = %v", err)
	}

	if _, err := s.db.Exec(`UPDATE requests SET path = '/tampered' WHERE id = 1`); err != nil {
		t.Fatalf("tamper historical row: %v", err)
	}
	if err := s.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after historical row tamper = %v, want ErrTampered", err)
	}
}

func testChainVerifyRetention(t *testing.T) {
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
		t.Fatalf("Verify after retention deleted the older half = %v, want nil", err)
	}
}

func testChainVerifyForgedAnchor(t *testing.T) {
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
	if err := s.Verify(); err != nil {
		t.Fatalf("precondition: Verify after retention = %v", err)
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

func testChainVerifyTipTruncation(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	recordSample(t, s, 3)

	if _, err := s.db.Exec(`DELETE FROM requests WHERE id = 3`); err != nil {
		t.Fatalf("delete tip row: %v", err)
	}
	if err := s.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after tip truncation = %v, want ErrTampered", err)
	}
}

func testChainVerifyAnchorDeleteCrash(t *testing.T) {
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

	deleteThrough, ok, err := s.anchorBeforeDelete(now.AddDate(0, 0, -7))
	if err != nil {
		t.Fatalf("anchorBeforeDelete: %v", err)
	}
	if !ok {
		t.Fatal("anchorBeforeDelete reported no work with 5 expired rows present")
	}
	// Simulated crash: the anchor is on disk, the DELETE has not run yet.
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify after crash between anchor write and row delete = %v, want nil", err)
	}

	if _, err := s.db.Exec(`DELETE FROM requests WHERE id <= ?`, deleteThrough); err != nil {
		t.Fatalf("complete the delete: %v", err)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify after completing the delete = %v, want nil", err)
	}
}

func testChainVerifyRowCommitCrash(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	if err := s.Record(sampleRecord(1)); err != nil {
		t.Fatal(err)
	}

	// Simulated crash after the row committed but before the witness write.
	if _, _, err := s.insertRow(sampleRecord(2)); err != nil {
		t.Fatalf("insertRow (simulated crash): %v", err)
	}
	if tip, _ := s.witness.tip(); tip.RowID != 1 {
		t.Fatalf("precondition: witness tip = %d, want 1", tip.RowID)
	}

	if err := s.Verify(); err != nil {
		t.Fatalf("Verify must heal the one-append crash window, not alarm: %v", err)
	}
	if tip, _ := s.witness.tip(); tip.RowID != 2 {
		t.Fatalf("after recovery: witness tip = %d, want 2 (re-witnessed)", tip.RowID)
	}
	hw, ok, err := s.readHighWater()
	if err != nil || !ok || hw.RowID != 2 {
		t.Fatalf("after recovery: high-water = %+v ok=%v err=%v, want row 2", hw, ok, err)
	}
}

func testChainVerifyWitnessCrash(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	if err := s.Record(sampleRecord(1)); err != nil {
		t.Fatal(err)
	}

	// Simulated crash after the witness entry persisted but before the
	// SecretStore high-water update.
	if err := s.secrets.Delete(secretService, highWaterKey); err != nil {
		t.Fatalf("simulate high-water loss: %v", err)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify must re-publish the one-entry high-water gap, not alarm: %v", err)
	}
	hw, ok, err := s.readHighWater()
	if err != nil || !ok || hw.RowID != 1 {
		t.Fatalf("after recovery: high-water = %+v ok=%v err=%v, want row 1 (re-published)", hw, ok, err)
	}
}

func testChainVerifyWitnessRollback(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	recordSample(t, s, 3)

	// Attacker truncates the tip: delete the two newest rows AND roll the
	// witness file back to its first (validly MAC'd) entry. The DB tip and the
	// witness tip then agree at row 1, so only the non-rollback SecretStore
	// high-water can catch it.
	if _, err := s.db.Exec(`DELETE FROM requests WHERE id IN (2, 3)`); err != nil {
		t.Fatalf("truncate tip rows: %v", err)
	}
	witnessPath := s.path + witnessSuffix
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("witness file has %d entries, want >= 2", len(lines))
	}
	if err := os.WriteFile(witnessPath, lines[0], 0o600); err != nil {
		t.Fatalf("roll back witness file: %v", err)
	}

	if err := s.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after tip truncation + witness rollback = %v, want ErrTampered", err)
	}
}

func testChainVerifyForgedWitness(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	recordSample(t, s, 3)

	if _, err := s.db.Exec(`DELETE FROM requests WHERE id IN (2, 3)`); err != nil {
		t.Fatalf("truncate tip rows: %v", err)
	}
	witnessPath := s.path + witnessSuffix
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Replace(data, []byte(`"mac":"`), []byte(`"mac":"00`), 1)
	if bytes.Equal(forged, data) {
		t.Fatal("could not forge witness: mac not found")
	}
	if err := os.WriteFile(witnessPath, forged, 0o600); err != nil {
		t.Fatalf("write forged witness: %v", err)
	}

	if err := s.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after tip truncation + forged witness = %v, want ErrTampered", err)
	}
}

func testChainVerifyCorruptWitness(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()
	recordSample(t, s, 2)

	witnessPath := s.path + witnessSuffix
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(witnessPath, append(data, []byte("not-json\n")...), 0o600); err != nil {
		t.Fatalf("corrupt witness file: %v", err)
	}
	if err := s.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after a malformed witness line = %v, want ErrTampered", err)
	}
}

func testChainVerifyStaleReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	secrets := newMemSecrets()
	hashKey, anchorKey := testKeys()

	s, err := OpenStore(StoreConfig{Path: path, Secrets: secrets, HashKey: hashKey, AnchorKey: anchorKey})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	recordSample(t, s, 3)
	if _, err := s.db.Exec(`UPDATE requests SET method = 'GET' WHERE id = 2`); err != nil {
		t.Fatalf("tamper historical row: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Verify(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Verify after Close = %v, want ErrClosed", err)
	}

	reopened, err := OpenStore(StoreConfig{Path: path, Secrets: secrets, HashKey: hashKey, AnchorKey: anchorKey})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if err := reopened.Verify(); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after reopen with a tampered historical row = %v, want ErrTampered", err)
	}
}
