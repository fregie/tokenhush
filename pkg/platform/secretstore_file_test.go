package platform

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestSecretStoreEncryptedFileHidesPlaintext proves the encrypted layer never
// writes the plaintext (or its base64 form) to disk.
func TestSecretStoreEncryptedFileHidesPlaintext(t *testing.T) {
	t.Parallel()

	scenario := secretStoreScenario{
		keyring:       unreachableKeyring(),
		machineSecret: healthyMachineSecret,
	}
	cfg := scenario.config(t, nil)
	store, err := openSecretStore(cfg)
	if err != nil {
		t.Fatalf("openSecretStore() error = %v", err)
	}
	if got := store.Backend(); got != "file-encrypted" {
		t.Fatalf("Backend() = %q, want %q", got, "file-encrypted")
	}
	if err := store.Set(testService, testAccount, testSecret); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	files := readSecretFiles(t, cfg.dataDir)
	if len(files) != 1 {
		t.Fatalf("secret files = %d, want exactly 1", len(files))
	}
	needles := [][]byte{
		[]byte(testSecret),
		[]byte(base64.StdEncoding.EncodeToString([]byte(testSecret))),
	}
	for name, data := range files {
		for _, needle := range needles {
			if bytes.Contains(data, needle) {
				t.Fatalf("encrypted file %s contains plaintext secret bytes", name)
			}
		}
	}
}

// TestSecretStoreCorruptEncryptedEntry proves a damaged entry yields a typed
// error instead of a panic or a silent empty value.
func TestSecretStoreCorruptEncryptedEntry(t *testing.T) {
	t.Parallel()

	scenario := secretStoreScenario{
		keyring:       unreachableKeyring(),
		machineSecret: healthyMachineSecret,
	}
	cfg := scenario.config(t, nil)
	store, err := openSecretStore(cfg)
	if err != nil {
		t.Fatalf("openSecretStore() error = %v", err)
	}
	if err := store.Set(testService, testAccount, testSecret); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	files := readSecretFiles(t, cfg.dataDir)
	if len(files) != 1 {
		t.Fatalf("secret files = %d, want exactly 1", len(files))
	}

	garbage := map[string][]byte{
		"truncated":      []byte("short"),
		"authentication": bytes.Repeat([]byte{0xA5}, 64),
	}
	for name, data := range garbage {
		t.Run(name, func(t *testing.T) {
			for fileName := range files {
				path := filepath.Join(cfg.dataDir, secretsDirName, fileName)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatalf("WriteFile(%s) error = %v", path, err)
				}
			}
			_, err := store.Get(testService, testAccount)
			if err == nil {
				t.Fatal("Get() on a corrupt entry succeeded, want an error")
			}
			if !errors.Is(err, ErrSecretCorrupt) {
				t.Fatalf("Get() error = %v, want ErrSecretCorrupt", err)
			}
		})
	}
}

// TestSecretStoreLeavesNoScratchFiles covers stale_state: constructors clean up
// their self-test entries and Delete removes the only secret file.
func TestSecretStoreLeavesNoScratchFiles(t *testing.T) {
	t.Parallel()

	for name, machineSecret := range map[string]func() ([]byte, error){
		"file-encrypted": healthyMachineSecret,
		"file-plaintext": brokenMachineSecret,
	} {
		t.Run(name, func(t *testing.T) {
			scenario := secretStoreScenario{
				keyring:       unreachableKeyring(),
				machineSecret: machineSecret,
			}
			cfg := scenario.config(t, nil)
			store, err := openSecretStore(cfg)
			if err != nil {
				t.Fatalf("openSecretStore() error = %v", err)
			}
			dir := filepath.Join(cfg.dataDir, secretsDirName)
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("after open: ReadDir(%s) entries = %d, err = %v, want 0", dir, len(entries), err)
			}

			if err := store.Set(testService, testAccount, testSecret); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
			if err := store.Delete(testService, testAccount); err != nil {
				t.Fatalf("Delete() error = %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("ReadDir(%s) error = %v", dir, err)
			}
			if len(entries) != 0 {
				t.Fatalf("after Delete: %d scratch files left", len(entries))
			}
		})
	}
}

// readSecretFiles returns every file below the data dir's secrets directory,
// keyed by file name.
func readSecretFiles(t *testing.T, dataDir string) map[string][]byte {
	t.Helper()

	dir := filepath.Join(dataDir, secretsDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", dir, err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", entry.Name(), err)
		}
		files[entry.Name()] = data
	}
	return files
}
