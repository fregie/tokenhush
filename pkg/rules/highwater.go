package rules

// Persisted anti-rollback marks for the rule channel. The rules schema has a
// monotonic serial, so a client records the highest accepted serial and refuses
// anything below it: a replayed or rolled-back manifest becomes a rejection
// instead of a silent downgrade. The store is deliberately independent of
// pkg/update (separate key and serial sequences), mirroring the deliberate
// independence noted in verify.go.

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// KindRules names the anti-rollback sequence a rule manifest serial belongs to.
const KindRules = "rules"

// HighWaterStore persists the highest accepted serial per document kind.
type HighWaterStore interface {
	// Highest returns the highest accepted serial for kind; ok is false when
	// nothing has been recorded yet.
	Highest(kind string) (serial uint64, ok bool, err error)
	// Advance records serial as the new high-water mark for kind. A serial at
	// or below the stored value is refused with ErrPackReplayed.
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
		return ErrPackReplayed
	}
	m.serials[kind] = serial
	return nil
}

// FileHighWater persists the marks as JSON so anti-rollback survives process
// restarts. Writes are atomic (temp file + rename) to avoid a torn file.
type FileHighWater struct {
	mu      sync.Mutex
	path    string
	serials map[string]uint64
}

// OpenFileHighWater loads marks from path, or starts empty when the file does
// not exist yet.
func OpenFileHighWater(path string) (*FileHighWater, error) {
	h := &FileHighWater{path: path, serials: make(map[string]uint64)}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &h.serials); err != nil {
			return nil, err
		}
	}
	return h, nil
}

// Highest implements HighWaterStore.
func (h *FileHighWater) Highest(kind string) (uint64, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.serials[kind]
	return v, ok, nil
}

// Advance implements HighWaterStore and persists the mark before returning.
func (h *FileHighWater) Advance(kind string, serial uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if prev, ok := h.serials[kind]; ok && serial <= prev {
		return ErrPackReplayed
	}
	h.serials[kind] = serial
	raw, err := json.Marshal(h.serials)
	if err != nil {
		return err
	}
	return writeFileAtomic(h.path, raw, 0o600)
}
