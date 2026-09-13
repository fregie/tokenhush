// Persisted anti-rollback marks. Each signed document kind has its own
// monotonic serial sequence; the client records the highest accepted serial
// and refuses anything at or below it, which turns a replayed or rolled-back
// document into a rejection instead of a silent downgrade.
package update

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// HighWaterStore persists the highest accepted serial per document kind.
type HighWaterStore interface {
	// Highest returns the highest accepted serial for kind; ok is false when
	// nothing has been recorded yet.
	Highest(kind string) (serial uint64, ok bool, err error)
	// Advance records serial as the new high-water mark for kind. A serial at
	// or below the stored value is refused with ErrReplayed.
	Advance(kind string, serial uint64) error
}

// MemHighWater is an in-process HighWaterStore for tests and single-shot use.
type MemHighWater struct {
	mu      sync.Mutex
	serials map[string]uint64
}

// NewMemHighWater returns an empty in-memory store.
func NewMemHighWater() *MemHighWater {
	return &MemHighWater{serials: make(map[string]uint64)}
}

// Highest implements HighWaterStore.
func (m *MemHighWater) Highest(kind string) (uint64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.serials[kind]
	return v, ok, nil
}

// Advance implements HighWaterStore.
func (m *MemHighWater) Advance(kind string, serial uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.serials[kind]; ok && serial <= prev {
		return ErrReplayed
	}
	m.serials[kind] = serial
	return nil
}

// FileHighWater persists the marks as JSON so anti-rollback survives process
// restarts. Writes are atomic (temp file + rename) to avoid a torn file on
// crash.
type FileHighWater struct {
	mu      sync.Mutex
	path    string
	serials map[string]uint64
}

// OpenFileHighWater loads marks from path, or starts empty when the file does
// not exist yet.
func OpenFileHighWater(path string) (*FileHighWater, error) {
	f := &FileHighWater{path: path, serials: make(map[string]uint64)}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &f.serials); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// Highest implements HighWaterStore.
func (f *FileHighWater) Highest(kind string) (uint64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.serials[kind]
	return v, ok, nil
}

// Advance implements HighWaterStore and persists the new mark before returning.
func (f *FileHighWater) Advance(kind string, serial uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if prev, ok := f.serials[kind]; ok && serial <= prev {
		return ErrReplayed
	}
	f.serials[kind] = serial
	return f.persist()
}

// persist writes the mark map atomically.
func (f *FileHighWater) persist() error {
	raw, err := json.Marshal(f.serials)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(f.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".highwater-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
