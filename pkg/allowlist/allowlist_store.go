// Package allowlist implements the C7 runtime-mutable allowlist store.
//
// The matching semantics do not live here: they stay frozen in pkg/redact as
// byte-exact contains, global and case-sensitive. This package owns exactly
// three things:
//
//   - persistence of runtime additions/removals at <DataDir>/allowlist.json
//     (mode 0600, same-directory temp file + rename, schema_version). The file
//     is not a session file: a clean exit keeps it (pkg/gateway's session
//     cleanup removes run.json and control.token only);
//   - the union merge: the tokenhush.yaml `allowlist:` entries are imported as
//     the seed at startup (effective set = seed ∪ persisted runtime entries,
//     the seed never replaces the runtime set) while the original key keeps
//     being read by the detector path, so an entry that exists only in YAML
//     still takes effect;
//   - content validation on load and on every mutation (non-empty, no control
//     characters, at most maxEntryBytes, de-duplicated).
//
// Store satisfies gateway.AllowlistStore structurally, so this package never
// imports pkg/gateway (see ADR-0012 A2).
package allowlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode"
)

const (
	// FileName is the frozen persistence file name below the data directory:
	// <DataDir>/allowlist.json. It is deliberately not a session file, so a
	// clean exit never removes it.
	FileName = "allowlist.json"

	// SchemaVersion is the persisted schema version. A file carrying any other
	// version (including a missing field, which decodes to 0) is rejected with
	// a warning instead of being reset: the original bytes are left untouched
	// and the store degrades to an empty runtime set.
	SchemaVersion = 1

	// maxEntryBytes is the per-entry length limit. It matches pkg/config's
	// maxConfigEntryBytes so the static YAML path and the runtime store accept
	// exactly the same entry shapes.
	maxEntryBytes = 4096

	// warnPrefix is the stable, greppable prefix of every degradation warning.
	warnPrefix = "tokenhush: allowlist: "
)

// Store is the runtime-mutable allowlist. It is safe for concurrent use: all
// state is guarded by mu, and Entries returns an independent copy.
//
// Effective entries are the union of the static seed (imported at Open) and
// the persisted runtime entries. Only runtime entries are written to disk: the
// YAML seed stays authoritative for its own entries, so removing an entry from
// tokenhush.yaml takes effect on the next start.
type Store struct {
	path string
	warn io.Writer

	mu      sync.Mutex
	entries []string            // effective set: sorted, de-duplicated
	seed    map[string]struct{} // entries that came from the static seed
}

// Errors returned by Add and Remove. They are sentinels so a control-plane
// caller (W5.3) can map them onto distinct HTTP statuses without string
// matching.
var (
	// ErrDuplicate reports Add of an entry that is already present (a static
	// seed counts as present).
	ErrDuplicate = errors.New("allowlist: entry already present")
	// ErrNotFound reports Remove of an entry that is not present.
	ErrNotFound = errors.New("allowlist: entry not present")
	// ErrInvalidEntry reports an entry that fails content validation: empty,
	// containing control characters, or longer than maxEntryBytes.
	ErrInvalidEntry = errors.New("allowlist: invalid entry")
)

// fileDoc is the on-disk shape:
//
//	{"schema_version":1,"entries":["..."]}
//
// entries holds runtime entries only; the static seed is never persisted.
type fileDoc struct {
	SchemaVersion int      `json:"schema_version"`
	Entries       []string `json:"entries"`
}

// Open builds a Store rooted at dataDir. seed is the static tokenhush.yaml
// `allowlist:` list, imported as the seed at startup: the effective set is
// seed ∪ persisted runtime entries, and the seed never replaces the runtime
// set. The original tokenhush.yaml key keeps being read by the detector path,
// so an entry that exists only in YAML still takes effect.
//
// The only hard error is a blank dataDir. A missing file is an empty runtime
// set (first run, no warning). A file that exists but cannot be read, is not
// valid JSON, carries an unsupported schema_version, or contains an invalid
// entry degrades to an empty runtime set with an explicit warning written to
// warn (nil discards it): the store is rejected rather than silently reset,
// the original file is left byte-for-byte untouched, and the daemon still
// starts. A later explicit mutation writes a fresh valid file.
func Open(dataDir string, seed []string, warn io.Writer) (*Store, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("allowlist: data directory is required")
	}
	if warn == nil {
		warn = io.Discard
	}
	s := &Store{
		path: filepath.Join(dataDir, FileName),
		warn: warn,
		seed: make(map[string]struct{}, len(seed)),
	}
	s.importSeed(seed)
	runtime, err := s.load()
	if err != nil {
		s.warnf("%v; keeping the file untouched and starting with no runtime allowlist entries", err)
	}
	for _, entry := range runtime {
		if idx := s.indexOfLocked(entry); idx < 0 {
			s.entries = append(s.entries, entry)
		}
	}
	slices.Sort(s.entries)
	return s, nil
}

// Entries returns the current effective set (static seed ∪ runtime entries),
// de-duplicated and sorted byte-wise so the order is deterministic. The caller
// receives an independent copy and may never mutate the store through it.
func (s *Store) Entries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.entries)
}

// Add inserts a runtime entry and persists the runtime set atomically. An
// invalid entry returns ErrInvalidEntry; an entry that is already present
// (including a static seed entry) returns ErrDuplicate. A persistence failure
// returns the error and leaves both the in-memory state and the on-disk file
// unchanged (the mutation is rolled back).
func (s *Store) Add(entry string) error {
	if reason, bad := entryProblem(entry); bad {
		return fmt.Errorf("%w: %s", ErrInvalidEntry, reason)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.indexOfLocked(entry) >= 0 {
		return fmt.Errorf("%w: %q", ErrDuplicate, entry)
	}
	next := append(slices.Clone(s.entries), entry)
	slices.Sort(next)
	if err := s.persist(next); err != nil {
		return err
	}
	s.entries = next
	return nil
}

// Remove deletes an entry from the effective set and persists the runtime set
// atomically. A missing entry returns ErrNotFound; a persistence failure
// returns the error and leaves the store unchanged.
//
// Removing a static seed entry is allowed: it disappears from Entries()
// immediately, but the tokenhush.yaml key re-imports it on the next start
// (removing it from YAML, not from the store, is what makes it durable). The
// seed was never persisted, so the file only ever holds runtime entries.
func (s *Store) Remove(entry string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.indexOfLocked(entry)
	if idx < 0 {
		return fmt.Errorf("%w: %q", ErrNotFound, entry)
	}
	next := slices.Clone(s.entries[:idx])
	next = append(next, s.entries[idx+1:]...)
	if err := s.persist(next); err != nil {
		return err
	}
	s.entries = next
	return nil
}

// importSeed validates and imports the static seed. Invalid entries are
// dropped with a warning (pkg/config already rejects them at load time, so
// this is defence in depth for programmatic callers; Open must never fail
// because of the seed). Duplicates collapse.
func (s *Store) importSeed(seed []string) {
	for i, entry := range seed {
		if reason, bad := entryProblem(entry); bad {
			s.warnf("static allowlist entry %d dropped (%s)", i, reason)
			continue
		}
		if s.indexOfLocked(entry) >= 0 {
			continue
		}
		s.entries = append(s.entries, entry)
		s.seed[entry] = struct{}{}
	}
}

// load reads and validates the persisted file. A missing file is not an error
// (nil, nil). Every other failure — read error, corrupt JSON, unsupported
// schema_version, invalid entry — returns (nil, error) after which Open
// degrades to an empty runtime set and warns; the file is never rewritten or
// removed here. Duplicate entries collapse silently (they are equivalent).
func (s *Store) load() ([]string, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: read failed: %w", s.path, err)
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: corrupt allowlist file: %w", s.path, err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s: unsupported schema_version %d (want %d)",
			s.path, doc.SchemaVersion, SchemaVersion)
	}
	seen := make(map[string]struct{}, len(doc.Entries))
	out := make([]string, 0, len(doc.Entries))
	for i, entry := range doc.Entries {
		if reason, bad := entryProblem(entry); bad {
			return nil, fmt.Errorf("%s: entry %d %s (the whole file is rejected, never partially imported)",
				s.path, i, reason)
		}
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return out, nil
}

// persist atomically writes the runtime set (entries minus the static seed,
// which is never persisted) to the data file. On failure the previous file is
// untouched and no temp file is left behind, so the caller can roll back.
func (s *Store) persist(entries []string) error {
	runtimeEntries := make([]string, 0, len(entries))
	for _, entry := range entries {
		if _, isSeed := s.seed[entry]; isSeed {
			continue
		}
		runtimeEntries = append(runtimeEntries, entry)
	}
	payload, err := json.Marshal(fileDoc{SchemaVersion: SchemaVersion, Entries: runtimeEntries})
	if err != nil {
		return fmt.Errorf("allowlist: encode %s: %w", s.path, err)
	}
	payload = append(payload, '\n')
	if err := writeFileAtomic(s.path, payload, 0o600); err != nil {
		return fmt.Errorf("allowlist: persist %s: %w", s.path, err)
	}
	return nil
}

// indexOfLocked returns the index of entry in the effective set, or -1. The
// caller holds s.mu or is the single-threaded constructor.
func (s *Store) indexOfLocked(entry string) int {
	for i, e := range s.entries {
		if e == entry {
			return i
		}
	}
	return -1
}

// warnf writes one explicit degradation warning. It never includes entry
// values beyond what the error text already carries (paths and reasons only).
func (s *Store) warnf(format string, args ...any) {
	if s.warn == nil {
		return
	}
	fmt.Fprintf(s.warn, warnPrefix+format+"\n", args...)
}

// entryProblem reports why an entry is unusable. The judgement mirrors
// pkg/config's entryProblem exactly (empty, control characters, over-long) so
// the static YAML path and the runtime store accept the same entry shapes.
func entryProblem(entry string) (string, bool) {
	switch {
	case entry == "":
		return "must not be empty", true
	case strings.IndexFunc(entry, unicode.IsControl) >= 0:
		return "must not contain control characters", true
	case len(entry) > maxEntryBytes:
		return fmt.Sprintf("must be at most %d bytes, got %d", maxEntryBytes, len(entry)), true
	}
	return "", false
}

// writeFileAtomic writes data to path via a temp file in the same directory
// and a rename, so a crash never leaves a torn file. It mirrors the
// same-directory temp + rename + 0600 pattern of pkg/rules/store.go
// (writeFileAtomic): MkdirAll 0700 for the parent, and the temp file is
// removed on every failure path. There is deliberately no fsync.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
