package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Session file names under the data directory.
const (
	runFileName   = "run.json"
	tokenFileName = "control.token"
)

// runFileMode is the strict 0600 mode both session files are written with.
const runFileMode = 0o600

// RunState is the token-free runtime metadata written to run.json. It carries
// exactly four keys: pid, port, addrs and started_at. The control token is
// deliberately absent, because run.json is the readable half of the session.
type RunState struct {
	PID       int      `json:"pid"`
	Port      int      `json:"port"`
	Addrs     []string `json:"addrs"`
	StartedAt string   `json:"started_at"`
}

// NewRunState describes the current process listening on port at addrs.
func NewRunState(port int, addrs []string) RunState {
	return RunState{
		PID:       os.Getpid(),
		Port:      port,
		Addrs:     slices.Clone(addrs),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// SessionPaths returns the run.json and control.token paths under dir.
func SessionPaths(dir string) (runPath, tokenPath string) {
	return filepath.Join(dir, runFileName), filepath.Join(dir, tokenFileName)
}

// WriteSession writes run.json and control.token under dir, each atomically
// (temp file + rename) with mode 0600. run.json never receives the token.
func WriteSession(dir string, state RunState, token Token) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("proxy: create data dir %s: %w", dir, err)
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("proxy: encode %s: %w", runFileName, err)
	}
	runPath, tokenPath := SessionPaths(dir)
	if err := writeFileAtomic(runPath, append(payload, '\n')); err != nil {
		return err
	}
	if err := writeFileAtomic(tokenPath, []byte(token.String()+"\n")); err != nil {
		_ = os.Remove(runPath)
		return err
	}
	return nil
}

// ReadSession reads and decodes run.json from dir.
func ReadSession(dir string) (RunState, error) {
	runPath, _ := SessionPaths(dir)
	data, err := os.ReadFile(runPath)
	if err != nil {
		return RunState{}, fmt.Errorf("proxy: read %s: %w", runFileName, err)
	}
	var state RunState
	if err := json.Unmarshal(data, &state); err != nil {
		return RunState{}, fmt.Errorf("proxy: decode %s: %w", runFileName, err)
	}
	return state, nil
}

// RemoveSession deletes both session files. Missing files are not an error,
// so a clean shutdown can call it repeatedly.
func RemoveSession(dir string) error {
	runPath, tokenPath := SessionPaths(dir)
	var errs []error
	for _, path := range []string{runPath, tokenPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("proxy: remove %s: %w", filepath.Base(path), err))
		}
	}
	return errors.Join(errs...)
}

// writeFileAtomic writes data to path via a temporary file in the same
// directory, fsynced and renamed into place, so a reader never observes a
// half-written session file and no temp file survives a failure.
func writeFileAtomic(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("proxy: create temp for %s: %w", filepath.Base(path), err)
	}
	tempPath := temp.Name()
	discard := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	if err := temp.Chmod(runFileMode); err != nil {
		discard()
		return fmt.Errorf("proxy: chmod temp for %s: %w", filepath.Base(path), err)
	}
	if _, err := temp.Write(data); err != nil {
		discard()
		return fmt.Errorf("proxy: write temp for %s: %w", filepath.Base(path), err)
	}
	if err := temp.Sync(); err != nil {
		discard()
		return fmt.Errorf("proxy: sync temp for %s: %w", filepath.Base(path), err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("proxy: close temp for %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("proxy: rename temp for %s: %w", filepath.Base(path), err)
	}
	return nil
}
