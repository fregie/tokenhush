// replace.go owns the crash-safe two-phase binary replacement (D13).
//
// Phase 1 stages the verified artifact as <bin>.new, beside the live binary so
// every rename below stays on one filesystem and is therefore atomic. Phase 2
// writes the JOURNAL, backs the live binary up as <bin>.lkg and renames the
// candidate into place, removing the journal last. A crash therefore leaves
// either the old binary, the new binary, or a state recover.go can repair to
// one of them: never a truncated or missing binary.
//
// The journal is a plain 0600 marker naming the version and serial being
// committed. Recovery decides from which of the three sibling files exist,
// because that is what the interrupted renames actually changed; the journal
// is what says a commit was in flight.
package supply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoTarget reports an empty or relative target binary path. The staging
// paths are derived from it, so an unusable target is refused up front.
var ErrNoTarget = errors.New("supply: update target path is empty or not absolute")

// Staging suffixes. All three files live beside the target so the renames
// never cross a filesystem boundary.
const (
	candidateSuffix     = ".new"
	lastKnownGoodSuffix = ".lkg"
	journalSuffix       = ".update-journal"
)

// The named commit steps a test can inject a crash after: once the candidate
// is staged, once the journal is written, between the two renames, and once
// the candidate is installed.
const (
	stepCandidateStaged = "candidate-staged"
	stepJournalWritten  = "journal-written"
	stepBackedUp        = "backed-up"
	stepInstalled       = "installed"
)

// layout is the sibling path set of one install.
type layout struct {
	target    string
	candidate string
	backup    string
	journal   string
}

// newLayout derives the staging paths for an absolute target path.
func newLayout(target string) (layout, error) {
	target = strings.TrimSpace(target)
	if target == "" || !filepath.IsAbs(target) {
		return layout{}, ErrNoTarget
	}
	return layout{
		target:    target,
		candidate: target + candidateSuffix,
		backup:    target + lastKnownGoodSuffix,
		journal:   target + journalSuffix,
	}, nil
}

// journalDoc is the on-disk commit marker. It is informational for recovery —
// the surviving files decide the repair — and human-readable for an operator
// looking at an install that will not update.
type journalDoc struct {
	Version string `json:"version,omitempty"`
	Serial  uint64 `json:"serial,omitempty"`
}

// killFunc is the crash-injection seam of the two-phase replace. Production
// passes nil; the interrupted-commit tests return a sentinel error after a
// named step to simulate a process death between two renames.
type killFunc func(step string) error

// killAt invokes an injected crash, if any.
func killAt(kill killFunc, step string) error {
	if kill == nil {
		return nil
	}
	return kill(step)
}

// stageCandidate writes the verified artifact as <bin>.new, atomically and
// executable, so a crash mid-write can never leave a half-written candidate.
func (l layout) stageCandidate(data []byte) error {
	return writeFileMode(l.candidate, data, 0o755)
}

// writeJournal persists the commit marker atomically at 0600.
func (l layout) writeJournal(version string, serial uint64) error {
	raw, err := json.Marshal(journalDoc{Version: version, Serial: serial})
	if err != nil {
		return fmt.Errorf("supply: encode update journal: %w", err)
	}
	return writeFileAtomic(l.journal, raw)
}

// removeJournal clears the marker, ignoring its absence.
func (l layout) removeJournal() { _ = os.Remove(l.journal) }

// commit is the two-phase commit: the journal first, then the committing
// renames, then the journal removal. A failure leaves the journal and the
// staged candidate behind so Recover can finish the swap on the next start.
func (l layout) commit(version string, serial uint64, kill killFunc) error {
	if err := l.writeJournal(version, serial); err != nil {
		return err
	}
	if err := killAt(kill, stepJournalWritten); err != nil {
		return err
	}
	if err := l.finishCommit(kill); err != nil {
		return err
	}
	l.removeJournal()
	return nil
}

// finishCommit backs the live binary up as last-known-good and moves the
// candidate into place. It is idempotent: a resuming recovery that already
// performed the backup rename finds no target and only places the candidate.
// If the candidate cannot be installed, the backup is restored in place, so a
// failed commit never leaves the install without a runnable binary.
func (l layout) finishCommit(kill killFunc) error {
	if fileExists(l.target) {
		if err := renameOver(l.target, l.backup); err != nil {
			return fmt.Errorf("supply: back up the running binary: %w", err)
		}
	}
	if err := killAt(kill, stepBackedUp); err != nil {
		return err
	}
	if err := renameOver(l.candidate, l.target); err != nil {
		l.restoreBackup()
		return fmt.Errorf("supply: install the staged candidate: %w", err)
	}
	return killAt(kill, stepInstalled)
}

// restoreBackup puts the last-known-good binary back when a failed commit has
// already moved the target away. It is best effort: the journal and the backup
// remain for Recover either way.
func (l layout) restoreBackup() {
	if !fileExists(l.target) && fileExists(l.backup) {
		_ = renameOver(l.backup, l.target)
	}
}

// downloadArtifact performs the artifact half of the sequence: the signed URL
// must be absolute https, the bounded fetch enforces MaxArtifactBytes, and the
// SHA-256 is compared against the signed manifest in CONSTANT TIME.
func downloadArtifact(ctx context.Context, fetcher Fetcher, manifest UpdateManifestPayload) ([]byte, error) {
	if err := checkArtifactURL(manifest.URL); err != nil {
		return nil, err
	}
	artifact, err := fetcher.Get(ctx, manifest.URL)
	if err != nil {
		return nil, err
	}
	if int64(len(artifact)) > MaxArtifactBytes {
		return nil, fmt.Errorf("%w: artifact is %d bytes, cap %d", ErrDocTooLarge, len(artifact), MaxArtifactBytes)
	}
	if err := checkBundleDigest(manifest.SHA256, artifact); err != nil {
		return nil, err
	}
	return artifact, nil
}

// checkArtifactURL requires the signed artifact URL to be absolute https. The
// digest authenticates the bytes; the scheme check keeps a signed manifest
// from downgrading the transport.
func checkArtifactURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%w: manifest artifact url must be absolute https", ErrMalformedDoc)
	}
	return nil
}

// commitArtifact stages the verified artifact as <bin>.new and commits it
// through the two-phase replace.
func commitArtifact(target string, artifact []byte, version string, serial uint64, kill killFunc) error {
	l, err := newLayout(target)
	if err != nil {
		return err
	}
	if err := l.stageCandidate(artifact); err != nil {
		return err
	}
	if err := killAt(kill, stepCandidateStaged); err != nil {
		return err
	}
	return l.commit(version, serial, kill)
}

// writeFileMode writes data to path through a temp file in the same directory,
// chmods it mode, syncs it and renames it into place. A reader of path never
// observes a partial write.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("supply: create update dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tokenhush-*.tmp")
	if err != nil {
		return fmt.Errorf("supply: create staged candidate temp: %w", err)
	}
	tmpPath := tmp.Name()
	if err := writeTempMode(tmp, data, mode); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("supply: stage %s: %w", path, err)
	}
	return nil
}

// writeTempMode fills, chmods, syncs and closes one temp file.
func writeTempMode(tmp *os.File, data []byte, mode os.FileMode) error {
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: write staged candidate: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: chmod staged candidate: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: sync staged candidate: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("supply: close staged candidate: %w", err)
	}
	return nil
}

// fileExists reports whether path exists, following symlinks.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// renameOver renames src to dst, removing an existing dst only when the
// platform refuses to overwrite it (Windows). The unix rename is atomic.
func renameOver(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if rerr := os.Remove(dst); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return err
	}
	return os.Rename(src, dst)
}
