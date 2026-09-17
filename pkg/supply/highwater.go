package supply

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// ErrReplay is returned when a serial is lower than the current high-water
// mark. Callers reject the payload: a stale serial must never be applied.
var ErrReplay = errors.New("supply: serial replay rejected")

// ErrHighWaterCorrupt is returned when the persisted high-water state cannot
// be read or decoded. The store fails closed instead of resetting to zero.
var ErrHighWaterCorrupt = errors.New("supply: corrupt high-water state")

// ReplayError carries the offending serial and the retained high-water mark.
type ReplayError struct {
	Current   int64
	Attempted int64
}

func (e *ReplayError) Error() string {
	return fmt.Sprintf("supply: serial %d is below high-water mark %d", e.Attempted, e.Current)
}

// Unwrap makes errors.Is(err, ErrReplay) succeed.
func (e *ReplayError) Unwrap() error { return ErrReplay }

// HighWater tracks the highest serial applied for one signed stream. It is
// shared by both rule packs and binary updates.
type HighWater interface {
	// Advance records serial. Higher serials advance; an equal serial is
	// idempotent; a lower serial fails with a ReplayError wrapping ErrReplay.
	Advance(serial int64) error
	// Current returns the highest serial accepted so far.
	Current() int64
}

type serialState struct {
	mu     sync.Mutex
	serial int64
}

// MemHighWater is an in-memory HighWater for tests and ephemeral stores.
type MemHighWater struct {
	state serialState
}

// NewMemHighWater returns a HighWater starting at serial zero.
func NewMemHighWater() *MemHighWater { return &MemHighWater{} }

// Advance implements HighWater.
func (m *MemHighWater) Advance(serial int64) error {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	if serial < m.state.serial {
		return &ReplayError{Current: m.state.serial, Attempted: serial}
	}
	m.state.serial = serial
	return nil
}

// Current implements HighWater.
func (m *MemHighWater) Current() int64 {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	return m.state.serial
}

// FileHighWater persists the mark atomically at a frozen supply path.
type FileHighWater struct {
	path  string
	state serialState
}

const (
	rulesHighWaterRelPath  = "rules/highwater.json"
	updateHighWaterRelPath = "update/highwater.json"
)

// NewFileHighWater loads the mark stored at path. A missing file starts at
// zero; an unreadable or malformed file returns ErrHighWaterCorrupt.
func NewFileHighWater(path string) (*FileHighWater, error) {
	serial, err := readHighWater(path)
	if err != nil {
		return nil, err
	}
	return &FileHighWater{path: path, state: serialState{serial: serial}}, nil
}

// NewRulesHighWater opens <dataDir>/rules/highwater.json.
func NewRulesHighWater(dataDir string) (*FileHighWater, error) {
	return NewFileHighWater(filepath.Join(dataDir, filepath.FromSlash(rulesHighWaterRelPath)))
}

// NewUpdateHighWater opens <dataDir>/update/highwater.json.
func NewUpdateHighWater(dataDir string) (*FileHighWater, error) {
	return NewFileHighWater(filepath.Join(dataDir, filepath.FromSlash(updateHighWaterRelPath)))
}

// Advance implements HighWater. The mark is persisted before it is visible in
// memory, so a failed write never advances the store.
func (f *FileHighWater) Advance(serial int64) error {
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	if serial < f.state.serial {
		return &ReplayError{Current: f.state.serial, Attempted: serial}
	}
	if serial == f.state.serial {
		return nil
	}
	if err := persistHighWater(f.path, serial); err != nil {
		return err
	}
	f.state.serial = serial
	return nil
}

// Current implements HighWater.
func (f *FileHighWater) Current() int64 {
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	return f.state.serial
}

type highWaterDoc struct {
	Serial int64 `json:"serial"`
}

func readHighWater(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: read %s: %w", ErrHighWaterCorrupt, path, err)
	}
	var doc highWaterDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("%w: decode %s: %w", ErrHighWaterCorrupt, path, err)
	}
	if doc.Serial < 0 {
		return 0, fmt.Errorf("%w: negative serial in %s", ErrHighWaterCorrupt, path)
	}
	return doc.Serial, nil
}

func persistHighWater(path string, serial int64) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("supply: create high-water dir %s: %w", dir, err)
	}
	raw, err := json.Marshal(highWaterDoc{Serial: serial})
	if err != nil {
		return fmt.Errorf("supply: encode high-water: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".highwater-*.json")
	if err != nil {
		return fmt.Errorf("supply: create high-water temp: %w", err)
	}
	tmpPath := tmp.Name()
	if err := writeTempHighWater(tmp, raw); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("supply: replace high-water %s: %w", path, err)
	}
	return nil
}

func writeTempHighWater(tmp *os.File, raw []byte) error {
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: write high-water temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: chmod high-water temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("supply: sync high-water temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("supply: close high-water temp: %w", err)
	}
	return nil
}
