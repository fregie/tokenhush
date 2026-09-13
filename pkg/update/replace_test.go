package update

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// mustLayout resolves the sibling staging paths for target and fails the test
// on an invalid path.
func mustLayout(t *testing.T, target string) layout {
	t.Helper()
	l, err := newLayout(target)
	if err != nil {
		t.Fatalf("newLayout(%q): %v", target, err)
	}
	return l
}

// TestRecoverCompletesInterruptedStagedUpdate simulates a crash after the
// candidate was staged but before the swap: the journal and the verified .new
// survive, so Recover must finish the upgrade and preserve the original as
// last-known-good.
func TestRecoverCompletesInterruptedStagedUpdate(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-0.3.0")
	next := []byte("CANDIDATE-0.4.0")
	writeBinary(t, target, original)

	l := mustLayout(t, target)
	writeBinary(t, l.new, next)
	if err := l.writeJournal(journal{Phase: phaseStaged, Version: "0.4.0", Serial: 10}); err != nil {
		t.Fatalf("writeJournal: %v", err)
	}

	got, err := Recover(target)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != RecoveryCompleted {
		t.Fatalf("Recover = %q, want %q", got, RecoveryCompleted)
	}
	if !bytes.Equal(readBinary(t, target), next) {
		t.Fatalf("target = %q, want the staged candidate", readBinary(t, target))
	}
	if !bytes.Equal(readBinary(t, l.lkg), original) {
		t.Fatalf("last-known-good = %q, want the original binary", readBinary(t, l.lkg))
	}
	if fileExists(l.new) || fileExists(l.journal) {
		t.Fatal("a completed recovery must leave no staging or journal files")
	}
}

// TestRecoverRollsBackWhenTargetMissing simulates a crash after the backup
// rename but with the candidate lost: the original must be restored from
// last-known-good so the machine never loses its working binary.
func TestRecoverRollsBackWhenTargetMissing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-0.3.0")

	l := mustLayout(t, target)
	writeBinary(t, l.lkg, original)
	if err := l.writeJournal(journal{Phase: phaseStaged}); err != nil {
		t.Fatalf("writeJournal: %v", err)
	}
	if fileExists(target) {
		t.Fatal("fixture must start with no target binary")
	}

	got, err := Recover(target)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != RecoveryRolledBack {
		t.Fatalf("Recover = %q, want %q", got, RecoveryRolledBack)
	}
	if !bytes.Equal(readBinary(t, target), original) {
		t.Fatalf("target = %q, want the restored original", readBinary(t, target))
	}
	if fileExists(l.journal) {
		t.Fatal("journal must be cleared after rollback")
	}
}

// TestRecoverRemovesOrphanCandidateWithoutJournal asserts a crash before the
// journal was written leaves an orphan .new that startup cleans up without
// ever touching the live binary.
func TestRecoverRemovesOrphanCandidateWithoutJournal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	original := []byte("ORIGINAL-0.3.0")
	writeBinary(t, target, original)

	l := mustLayout(t, target)
	writeBinary(t, l.new, []byte("ORPHAN"))

	got, err := Recover(target)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != RecoveryCleaned {
		t.Fatalf("Recover = %q, want %q", got, RecoveryCleaned)
	}
	if !bytes.Equal(readBinary(t, target), original) {
		t.Fatal("orphan cleanup must not touch the live binary")
	}
	if fileExists(l.new) {
		t.Fatal("orphan candidate must be removed")
	}
}

// TestRecoverCleansJournalAfterCompletedSwap asserts a crash between the swap
// and the journal removal is detected and repaired as "already applied": the
// journal is discarded and the installed binary is left in place.
func TestRecoverCleansJournalAfterCompletedSwap(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	installed := []byte("INSTALLED-0.4.0")
	original := []byte("ORIGINAL-0.3.0")
	writeBinary(t, target, installed)

	l := mustLayout(t, target)
	writeBinary(t, l.lkg, original)
	if err := l.writeJournal(journal{Phase: phaseStaged}); err != nil {
		t.Fatalf("writeJournal: %v", err)
	}

	got, err := Recover(target)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != RecoveryCleaned {
		t.Fatalf("Recover = %q, want %q", got, RecoveryCleaned)
	}
	if !bytes.Equal(readBinary(t, target), installed) {
		t.Fatal("a completed swap must be left in place")
	}
	if fileExists(l.journal) {
		t.Fatal("stale journal must be removed")
	}
}

// TestRecoverNoStateIsNone asserts a clean install is a no-op that never
// invents work.
func TestRecoverNoStateIsNone(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	writeBinary(t, target, []byte("ORIGINAL"))

	got, err := Recover(target)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got != RecoveryNone {
		t.Fatalf("Recover = %q, want %q", got, RecoveryNone)
	}
}

// TestRollbackRestoresLastKnownGood asserts an explicit rollback swaps the
// backup back into place.
func TestRollbackRestoresLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	writeBinary(t, target, []byte("BROKEN-0.4.0"))
	l := mustLayout(t, target)
	writeBinary(t, l.lkg, []byte("ORIGINAL-0.3.0"))

	if err := Rollback(target); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !bytes.Equal(readBinary(t, target), []byte("ORIGINAL-0.3.0")) {
		t.Fatalf("target = %q, want the last-known-good binary", readBinary(t, target))
	}
}

// TestRollbackWithoutLastKnownGood asserts rollback refuses when there is
// nothing to fall back to, instead of deleting the live binary.
func TestRollbackWithoutLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	writeBinary(t, target, []byte("ONLY-COPY"))

	if err := Rollback(target); !errors.Is(err, ErrNoLastKnownGood) {
		t.Fatalf("Rollback error = %v, want ErrNoLastKnownGood", err)
	}
	if !bytes.Equal(readBinary(t, target), []byte("ONLY-COPY")) {
		t.Fatal("a refused rollback must leave the binary untouched")
	}
}

// TestRollbackDiscardsPendingCandidate asserts rolling back a Windows
// pending-restart update removes the staged candidate and its journal.
func TestRollbackDiscardsPendingCandidate(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	writeBinary(t, target, []byte("ORIGINAL-0.3.0"))
	l := mustLayout(t, target)
	writeBinary(t, l.lkg, []byte("ORIGINAL-0.3.0"))
	writeBinary(t, l.new, []byte("CANDIDATE-0.4.0"))
	if err := l.writeJournal(journal{Phase: phasePendingRestart}); err != nil {
		t.Fatalf("writeJournal: %v", err)
	}

	if err := Rollback(target); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if fileExists(l.new) || fileExists(l.journal) {
		t.Fatal("rollback must discard the pending candidate and journal")
	}
	if !bytes.Equal(readBinary(t, target), []byte("ORIGINAL-0.3.0")) {
		t.Fatal("rollback must keep the working binary")
	}
}

// TestRecoverRejectsRelativeTarget asserts a non-absolute target is refused
// before any filesystem work.
func TestRecoverRejectsRelativeTarget(t *testing.T) {
	if _, err := Recover("tokenhush"); !errors.Is(err, ErrNoTarget) {
		t.Fatalf("Recover(relative) error = %v, want ErrNoTarget", err)
	}
}

// TestFinishCommitIsIdempotentWithoutTarget asserts the swap helper skips the
// backup step when the target was already moved aside, which is the state a
// recovery resumes from.
func TestFinishCommitIsIdempotentWithoutTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	l := mustLayout(t, target)
	writeBinary(t, l.lkg, []byte("ORIGINAL"))
	writeBinary(t, l.new, []byte("CANDIDATE"))

	if err := l.finishCommit(); err != nil {
		t.Fatalf("finishCommit: %v", err)
	}
	if !bytes.Equal(readBinary(t, target), []byte("CANDIDATE")) {
		t.Fatal("finishCommit must place the candidate when the target is absent")
	}
	if !bytes.Equal(readBinary(t, l.lkg), []byte("ORIGINAL")) {
		t.Fatal("finishCommit must preserve the existing last-known-good")
	}
}

// TestRecoverDoesNotFollowSymlinkTargetPath guards the layout against being
// tricked into rewriting a different file: the journal paths are derived from
// the target path, never from symlink resolution, so a stale symlink target
// cannot redirect the swap.
func TestRecoverDoesNotFollowSymlinkTargetPath(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-binary")
	target := filepath.Join(dir, "tokenhush")
	writeBinary(t, real, []byte("ORIGINAL"))
	if err := os.Symlink(real, target); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	l := mustLayout(t, target)

	// A symlink in place of the binary has no staging state: Recover must be a
	// no-op and must not rewrite the symlink destination.
	if got, err := Recover(target); err != nil || got != RecoveryNone {
		t.Fatalf("Recover = (%q, %v), want (%q, nil)", got, err, RecoveryNone)
	}
	if fileExists(l.new) {
		t.Fatal("recover must not create staging files for a symlink target")
	}
}
