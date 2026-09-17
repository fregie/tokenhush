// recover.go repairs an interrupted two-phase replace (D13).
//
// Recover is the single entry point a startup path calls before it reads any
// update state: it looks at the journal and the three sibling files and leaves
// the install with a runnable binary — the previous one or the new one — no
// matter which rename the process died around. It is idempotent, so calling it
// on every start is free, and it never downloads, verifies or installs
// anything on its own.
package supply

import (
	"errors"
	"fmt"
	"os"
)

// ErrRecoveryStuck reports an install where the journal survived but every
// binary it could restore from is gone. Nothing can be repaired without
// re-installing, so the caller must fail loudly instead of starting empty.
var ErrRecoveryStuck = errors.New("supply: interrupted update cannot be repaired")

// RecoveryResult is what a startup self-heal did to an install.
type RecoveryResult string

const (
	// RecoveryNone means no half-applied state was found.
	RecoveryNone RecoveryResult = "none"
	// RecoveryCompleted means a staged candidate was swapped into place.
	RecoveryCompleted RecoveryResult = "completed"
	// RecoveryRolledBack means the target was restored from last-known-good.
	RecoveryRolledBack RecoveryResult = "rolled-back"
	// RecoveryCleaned means a stale journal or orphan candidate was removed.
	RecoveryCleaned RecoveryResult = "cleaned"
)

// Recover repairs any half-applied update for target. It is safe to call on
// every start, performs no I/O beyond the target's own directory, and returns
// the repair it performed.
func Recover(target string) (RecoveryResult, error) {
	l, err := newLayout(target)
	if err != nil {
		return RecoveryNone, err
	}
	return l.recover()
}

// recover is the pure recovery state machine. Which sibling files exist is
// what the interrupted renames actually changed, so that — not the journal
// contents — drives the repair.
func (l layout) recover() (RecoveryResult, error) {
	switch {
	case fileExists(l.journal):
		return l.recoverJournaled()
	case !fileExists(l.target) && fileExists(l.backup):
		// A committed install whose target later disappeared: restore the
		// last-known-good binary rather than leave none.
		if err := renameOver(l.backup, l.target); err != nil {
			return RecoveryNone, fmt.Errorf("supply: restore last-known-good: %w", err)
		}
		_ = os.Remove(l.candidate)
		return RecoveryRolledBack, nil
	case fileExists(l.candidate):
		// A crash after staging but before the journal: the live binary was
		// never touched, so the orphan candidate is discarded.
		if err := os.Remove(l.candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			return RecoveryNone, fmt.Errorf("supply: discard orphan candidate: %w", err)
		}
		return RecoveryCleaned, nil
	default:
		return RecoveryNone, nil
	}
}

// recoverJournaled finishes or rolls back a commit whose journal survived.
func (l layout) recoverJournaled() (RecoveryResult, error) {
	if fileExists(l.candidate) {
		// Killed after the journal, before the candidate was installed:
		// finishing the swap yields the new binary.
		if err := l.finishCommit(nil); err != nil {
			return RecoveryNone, err
		}
		l.removeJournal()
		return RecoveryCompleted, nil
	}
	if !fileExists(l.target) {
		// Killed between the backup rename and the candidate rename: the
		// backup is the only runnable binary, so roll back to it.
		if !fileExists(l.backup) {
			return RecoveryNone, fmt.Errorf("%w: journal present but no candidate, target or backup", ErrRecoveryStuck)
		}
		if err := renameOver(l.backup, l.target); err != nil {
			return RecoveryNone, fmt.Errorf("supply: roll back to last-known-good: %w", err)
		}
		l.removeJournal()
		return RecoveryRolledBack, nil
	}
	// Killed after the candidate rename, before the journal removal: only the
	// marker is stale. The installed binary stays.
	l.removeJournal()
	return RecoveryCleaned, nil
}
