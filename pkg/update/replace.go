// Crash-safe binary replacement. An update is committed in two phases around a
// journal: the verified candidate is staged as a sibling of the live binary,
// then the current binary is backed up as last-known-good and the candidate is
// renamed into place. If the process dies at any point, Recover finishes or
// rolls back the swap so the machine is never left without a working binary.
package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoTarget reports an empty or relative target path. Staging paths are
// derived from it, so an unusable target is refused up front.
var ErrNoTarget = errors.New("update: target binary path is empty or not absolute")

// ErrNoLastKnownGood reports a rollback with no backup to restore.
var ErrNoLastKnownGood = errors.New("update: no last-known-good binary to roll back to")

// Journal phases recorded before a commit begins.
const (
	phaseStaged         = "staged"
	phasePendingRestart = "pending-restart"
)

// fileSuffixes hide the staging files beside the target binary.
const (
	newSuffix     = ".new"
	lkgSuffix     = ".lkg"
	journalSuffix = ".update-journal"
)

// RecoveryResult is what a startup self-heal did to an install.
type RecoveryResult string

const (
	// RecoveryNone means no half-applied state was found.
	RecoveryNone RecoveryResult = "none"
	// RecoveryCompleted means a staged candidate was swapped in.
	RecoveryCompleted RecoveryResult = "completed"
	// RecoveryRolledBack means the target was restored from last-known-good.
	RecoveryRolledBack RecoveryResult = "rolled-back"
	// RecoveryCleaned means a stale journal or orphan candidate was removed.
	RecoveryCleaned RecoveryResult = "cleaned"
)

// layout is the set of sibling paths used during an atomic update. Keeping all
// of them in the target's directory makes every rename same-filesystem and thus
// atomic.
type layout struct {
	target  string
	new     string
	lkg     string
	journal string
}

// newLayout derives the staging paths for an absolute target path.
func newLayout(target string) (layout, error) {
	target = strings.TrimSpace(target)
	if target == "" || !filepath.IsAbs(target) {
		return layout{}, ErrNoTarget
	}
	dir := filepath.Dir(target)
	hidden := "." + filepath.Base(target)
	return layout{
		target:  target,
		new:     filepath.Join(dir, hidden+newSuffix),
		lkg:     filepath.Join(dir, hidden+lkgSuffix),
		journal: filepath.Join(dir, hidden+journalSuffix),
	}, nil
}

// journal is the on-disk commit marker. Version and Serial are informational;
// the phase drives recovery.
type journal struct {
	Phase   string `json:"phase"`
	Version string `json:"version,omitempty"`
	Serial  uint64 `json:"serial,omitempty"`
}

// writeJournal persists the commit marker atomically.
func (l layout) writeJournal(j journal) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writeFileAtomic(l.journal, raw, 0o600)
}

// removeJournal clears the marker, ignoring its absence.
func (l layout) removeJournal() { _ = os.Remove(l.journal) }

// finishCommit backs up the live binary and moves the candidate into place. It
// is idempotent: if the target is already absent (a recovery resuming after the
// backup rename), only the candidate is placed.
func (l layout) finishCommit() error {
	if fileExists(l.target) {
		if err := renameOver(l.target, l.lkg); err != nil {
			return fmt.Errorf("update: back up current binary: %w", err)
		}
	}
	if err := renameOver(l.new, l.target); err != nil {
		return fmt.Errorf("update: install candidate: %w", err)
	}
	return nil
}

// commit performs the platform-specific two-phase replacement. On Unix the
// swap happens inline; on Windows it is staged for completion at the next
// reboot or start, because a running executable cannot replace itself. The
// returned bool reports whether a restart is required.
func (l layout) commit(goos, version string, serial uint64) (bool, error) {
	if goos == "windows" {
		return l.stageForRestart(version, serial)
	}
	if err := l.writeJournal(journal{Phase: phaseStaged, Version: version, Serial: serial}); err != nil {
		return false, err
	}
	if err := l.finishCommit(); err != nil {
		// The journal and candidate stay behind so Recover can finish later.
		return false, err
	}
	l.removeJournal()
	return false, nil
}

// stageForRestart prepares a Windows update that cannot be applied while the
// binary is running: the candidate stays staged and a pending-restart journal
// is written. scheduleRebootReplace is a best effort; the journal-based Recover
// path completes the swap if the OS cannot schedule it.
func (l layout) stageForRestart(version string, serial uint64) (bool, error) {
	if err := l.writeJournal(journal{Phase: phasePendingRestart, Version: version, Serial: serial}); err != nil {
		return false, err
	}
	if fileExists(l.target) {
		_ = copyFile(l.target, l.lkg)
	}
	_ = scheduleRebootReplace(l.new, l.target)
	return true, nil
}

// Recover repairs any half-applied update for target using the running OS
// semantics. It is safe to call on every startup.
func Recover(target string) (RecoveryResult, error) {
	return recoverFor(target)
}

// recoverFor is the pure recovery state machine shared by every platform.
func recoverFor(target string) (RecoveryResult, error) {
	l, err := newLayout(target)
	if err != nil {
		return RecoveryNone, err
	}
	if !fileExists(l.journal) {
		if fileExists(l.new) {
			_ = os.Remove(l.new)
			return RecoveryCleaned, nil
		}
		return RecoveryNone, nil
	}
	if fileExists(l.new) {
		if err := l.finishCommit(); err != nil {
			return RecoveryNone, err
		}
		l.removeJournal()
		return RecoveryCompleted, nil
	}
	if !fileExists(l.target) && fileExists(l.lkg) {
		if err := renameOver(l.lkg, l.target); err != nil {
			return RecoveryNone, err
		}
		l.removeJournal()
		return RecoveryRolledBack, nil
	}
	l.removeJournal()
	return RecoveryCleaned, nil
}

// Rollback restores the last-known-good binary and discards any pending
// candidate. It refuses when no backup exists rather than deleting the live
// binary.
func Rollback(target string) error {
	l, err := newLayout(target)
	if err != nil {
		return err
	}
	if !fileExists(l.lkg) {
		return ErrNoLastKnownGood
	}
	_ = os.Remove(l.new)
	l.removeJournal()
	return renameOver(l.lkg, l.target)
}

// HasLastKnownGood reports whether a rollback target is available.
func HasLastKnownGood(target string) bool {
	l, err := newLayout(target)
	return err == nil && fileExists(l.lkg)
}

// fileExists reports whether path exists, following symlinks.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// renameOver renames src to dst, removing an existing dst when the platform
// refuses to overwrite it (Windows). The unix rename is atomic.
func renameOver(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if rerr := os.Remove(dst); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return err
	}
	if rerr := os.Rename(src, dst); rerr != nil {
		return err
	}
	return nil
}

// copyFile copies src to dst, creating dst with the executable bit set.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// writeFileAtomic writes data to path via a temp file and rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".update-journal-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
