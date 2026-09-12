package platform

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSecretStoreKeyringAbsentEdges pins the fallback-chain decisions the W2.2
// table does not: factories that are absent, a keyring whose availability probe
// is not wired, a systemd prober that declines, and machine-secret sources that
// cannot key encryption. Configs are built inline because the shared scenario
// helper hard-wires a working keyring probe and an accepting systemd prober.
func TestSecretStoreKeyringAbsentEdges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		keyring       func() keyringBackend
		keyringWorks  func(keyringBackend) bool
		systemd       func(string) (storeBackend, bool)
		machineSecret func() ([]byte, error)
		wantBackend   string
		wantWarn      bool
	}{
		{
			name:          "nil keyring primitive falls through to encrypted",
			keyring:       func() keyringBackend { return nil },
			keyringWorks:  nativeKeyringAvailable,
			machineSecret: healthyMachineSecret,
			wantBackend:   BackendFileEncrypted,
		},
		{
			name:          "nil keyring factory falls through to encrypted",
			keyring:       nil,
			machineSecret: healthyMachineSecret,
			wantBackend:   BackendFileEncrypted,
		},
		{
			name:          "unwired availability probe skips a live keyring",
			keyring:       func() keyringBackend { return newFakeKeyring() },
			keyringWorks:  nil,
			machineSecret: healthyMachineSecret,
			wantBackend:   BackendFileEncrypted,
		},
		{
			name:          "declining systemd probe falls through to encrypted",
			keyring:       func() keyringBackend { return unreachableKeyring() },
			keyringWorks:  nativeKeyringAvailable,
			systemd:       func(string) (storeBackend, bool) { return newMemStore(), false },
			machineSecret: healthyMachineSecret,
			wantBackend:   BackendFileEncrypted,
		},
		{
			name:          "systemd probe with nil backend falls through to encrypted",
			keyring:       func() keyringBackend { return unreachableKeyring() },
			keyringWorks:  nativeKeyringAvailable,
			systemd:       func(string) (storeBackend, bool) { return nil, true },
			machineSecret: healthyMachineSecret,
			wantBackend:   BackendFileEncrypted,
		},
		{
			name:          "nil machine-secret source falls through to plaintext",
			keyring:       func() keyringBackend { return unreachableKeyring() },
			keyringWorks:  nativeKeyringAvailable,
			machineSecret: nil,
			wantBackend:   BackendFilePlaintext,
			wantWarn:      true,
		},
		{
			name:          "empty machine secret falls through to plaintext",
			keyring:       func() keyringBackend { return unreachableKeyring() },
			keyringWorks:  nativeKeyringAvailable,
			machineSecret: func() ([]byte, error) { return []byte{}, nil },
			wantBackend:   BackendFilePlaintext,
			wantWarn:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &warningRecorder{}
			cfg := secretStoreConfig{
				dataDir:       t.TempDir(),
				keyring:       tc.keyring,
				keyringWorks:  tc.keyringWorks,
				systemd:       tc.systemd,
				machineSecret: tc.machineSecret,
				warnf:         rec.warnf,
			}

			store, err := openSecretStore(cfg)
			if err != nil {
				t.Fatalf("openSecretStore() error = %v", err)
			}
			if got := store.Backend(); got != tc.wantBackend {
				t.Fatalf("Backend() = %q, want %q", got, tc.wantBackend)
			}
			if gotWarn := strings.Contains(rec.joined(), PlaintextWarningMarker); gotWarn != tc.wantWarn {
				t.Fatalf("plaintext warning emitted = %v (warnings %q), want %v", gotWarn, rec.joined(), tc.wantWarn)
			}

			assertSecretNotFound(t, store)
			assertSecretRoundTrip(t, store)
		})
	}
}

// TestSecretStoreFallbackInSpacedUnicodeDataDir exercises the spaced/Unicode
// data-dir case (docs/deployment.md §5)
// on the keyring-absent path: with no native keyring the encrypted-file layer
// must be selected, write its entry below a data dir containing spaces and
// non-ASCII characters, and round-trip through it.
func TestSecretStoreFallbackInSpacedUnicodeDataDir(t *testing.T) {
	t.Parallel()

	dataDir := filepath.Join(t.TempDir(), "My Config 数据", "tokenhush")
	rec := &warningRecorder{}
	cfg := secretStoreConfig{
		dataDir:       dataDir,
		keyring:       nil,
		systemd:       nil,
		machineSecret: healthyMachineSecret,
		warnf:         rec.warnf,
	}

	store, err := openSecretStore(cfg)
	if err != nil {
		t.Fatalf("openSecretStore() error = %v", err)
	}
	if got := store.Backend(); got != BackendFileEncrypted {
		t.Fatalf("Backend() = %q, want %q", got, BackendFileEncrypted)
	}
	if strings.Contains(rec.joined(), PlaintextWarningMarker) {
		t.Fatalf("encrypted fallback emitted the plaintext warning: %q", rec.joined())
	}

	assertSecretRoundTrip(t, store)

	if err := store.Set(testService, testAccount, testSecret); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	files := readSecretFiles(t, dataDir)
	if len(files) != 1 {
		t.Fatalf("secret files below %q = %d, want exactly 1", dataDir, len(files))
	}
	if err := store.Delete(testService, testAccount); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

// TestSecretStoreReadOnlyDataDir proves the file layers degrade honestly when
// the data dir is unwritable: constructors return errors.Is-checkable
// fs.ErrPermission errors, the full fallback chain exhausts to
// ErrNoSecretBackend without panicking, and the plaintext warning is NOT emitted
// for a layer that never opened. chmod 0555 is meaningless on Windows, so the
// test skips there; pure-path coverage of the read-only prefix lives in
// TestPathsReadOnlyPrefixWriteAttempts and runs on every OS.
func TestSecretStoreReadOnlyDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod cannot make a directory unwritable on Windows")
	}

	dataDir := filepath.Join(t.TempDir(), "My Config 数据", "read-only")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dataDir, err)
	}
	if err := os.Chmod(dataDir, 0o555); err != nil {
		t.Fatalf("Chmod(%q, 0555): %v", dataDir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o755) })

	probe := filepath.Join(dataDir, "writability-probe.tmp")
	if err := os.WriteFile(probe, []byte("probe"), 0o600); err == nil {
		_ = os.Remove(probe)
		t.Skipf("directory %q is still writable (privileged runner or permission-less FS)", dataDir)
	}

	constructors := map[string]func() (storeBackend, error){
		"plaintext": func() (storeBackend, error) { return newPlaintextFileStore(dataDir) },
		"encrypted": func() (storeBackend, error) {
			return newEncryptedFileStore(dataDir, []byte("machine-secret"))
		},
	}
	for name, newStore := range constructors {
		t.Run(name, func(t *testing.T) {
			backend, err := newStore() // must not panic
			if err == nil {
				t.Fatal("constructor into a read-only data dir succeeded, want an error")
			}
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("constructor error = %v, want errors.Is(err, fs.ErrPermission)", err)
			}
			if backend != nil {
				t.Fatalf("constructor returned backend %v alongside error, want nil", backend)
			}
		})
	}

	rec := &warningRecorder{}
	store, err := openSecretStore(secretStoreConfig{
		dataDir:       dataDir,
		keyring:       nil,
		systemd:       nil,
		machineSecret: healthyMachineSecret,
		warnf:         rec.warnf,
	})
	if !errors.Is(err, ErrNoSecretBackend) {
		t.Fatalf("openSecretStore() error = %v, want ErrNoSecretBackend", err)
	}
	if store != nil {
		t.Fatalf("openSecretStore() = %v alongside error, want nil", store)
	}
	if strings.Contains(rec.joined(), PlaintextWarningMarker) {
		t.Fatalf("plaintext warning emitted although no plaintext store opened: %q", rec.joined())
	}
}
