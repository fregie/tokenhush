package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fregie/tokenhush/pkg/proxy"
)

// RunStateFileName is the per-session pid/port file below the data directory:
// <DataDir>/run.json. It carries no secrets and lets a later `tokenhush status`
// find the running process and its bound port. It is removed on graceful
// shutdown.
const RunStateFileName = "run.json"

// RunState is the metadata-only session snapshot persisted for discovery. It
// never contains the control token or any request content.
type RunState struct {
	PID       int      `json:"pid"`
	Port      int      `json:"port"`
	Addrs     []string `json:"addrs"`
	StartedAt int64    `json:"started_at"` // unix milliseconds
}

// WriteRunState atomically persists st to <dataDir>/run.json, creating the data
// directory if needed. The write is same-directory temp file + rename, so a
// concurrent reader never sees a half-written file and a previous session's
// file is replaced rather than truncated in place. CreateTemp yields 0600.
func WriteRunState(dataDir string, st RunState) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("run: create data dir: %w", err)
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("run: encode session state: %w", err)
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(dataDir, ".run-state-*")
	if err != nil {
		return fmt.Errorf("run: create session state file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("run: write session state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("run: write session state: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dataDir, RunStateFileName)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("run: persist session state: %w", err)
	}
	return nil
}

// cleanupSessionFiles removes the per-session discovery files after a clean
// shutdown: the pid/port file and the control token. A missing file is not an
// error; a removal failure is ignored because the process is exiting and the
// next run overwrites both files anyway.
func cleanupSessionFiles(dataDir string) {
	for _, name := range []string{RunStateFileName, proxy.ControlTokenFileName} {
		_ = os.Remove(filepath.Join(dataDir, name))
	}
}

// controlTokenPath is the absolute path of the session control token.
func controlTokenPath(dataDir string) string {
	return filepath.Join(dataDir, proxy.ControlTokenFileName)
}
