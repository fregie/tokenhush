package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotFound reports that a requested secret does not exist in the active
// backend. SecretStore.Get and SecretStore.Delete return it (possibly wrapped),
// so callers must probe with errors.Is.
var ErrNotFound = errors.New("secret not found")

// ErrSecretCorrupt reports that a secret entry exists but could not be decoded,
// for example a truncated or tampered encrypted file. It is deliberately
// distinct from ErrNotFound: a damaged entry must be surfaced, never silently
// treated as absent.
var ErrSecretCorrupt = errors.New("platform: secret store entry is corrupt")

// ErrNoSecretBackend reports that no layer of the fallback chain is usable: no
// native keyring, no systemd-creds, and neither the encrypted nor the plaintext
// file store could be opened.
var ErrNoSecretBackend = errors.New("platform: no usable secret store backend")

// errEmptyCredential rejects blank service or key names before they reach a
// backend: an empty keyring account is meaningless, and file paths must never
// be derivable from empty input.
var errEmptyCredential = errors.New("platform: service and key must be non-empty")

// Stable backend labels reported by SecretStore.Backend(). tokenhush doctor and
// audit output branch on these exact strings.
const (
	// BackendKeyring is the native OS keyring selected by W2.0: macOS Keychain
	// via security(1) (stdin), Windows Credential Manager or Linux Secret
	// Service via go-keyring.
	BackendKeyring = "keyring"

	// BackendSystemdCreds is the Linux systemd-creds layer (systemd >= 250).
	BackendSystemdCreds = "systemd-creds"

	// BackendFileEncrypted is the AES-256-GCM file layer whose key is derived
	// with HKDF-SHA256 from an injectable machine-bound secret source.
	BackendFileEncrypted = "file-encrypted"

	// BackendFilePlaintext is the last-resort 0600 plaintext file layer. It is
	// NOT secure and always emits PlaintextWarningMarker.
	BackendFilePlaintext = "file-plaintext"
)

// PlaintextWarningMarker is the stable marker emitted whenever the plaintext
// fallback is selected. tokenhush doctor greps for it and the CLI must display
// it verbatim.
const PlaintextWarningMarker = "tokenhush: WARNING: plaintext secret store in use; secrets are NOT encrypted"

// SecretStore is the only component allowed to touch an OS secret store. It is
// implemented by the graded fallback chain (native keyring -> systemd-creds ->
// encrypted file -> plaintext file) selected at OpenSecretStore time.
//
// The audit subsystem uses the namespace service "tokenhush/audit" with key
// "hmac-key" (docs/13 §3.2); V1 stores no provider keys.
type SecretStore interface {
	// Get returns the stored secret. A missing entry yields an error matching
	// ErrNotFound.
	Get(service, key string) (string, error)

	// Set stores value. Native backends have hard size limits: the macOS
	// security(1) command line is capped at 4096 bytes (service + account +
	// base64-encoded secret) and the Windows Credential Manager blob at 2560
	// bytes. Oversized values fail with errSecretTooBig; the store never
	// silently downgrades to another backend mid-flight.
	Set(service, key, value string) error

	// Delete removes an entry. Deleting a missing entry yields an error
	// matching ErrNotFound.
	Delete(service, key string) error

	// Backend returns the stable label of the selected backend (one of the
	// Backend* constants) for doctor and audit output.
	Backend() string
}

// storeBackend is the per-layer primitive the selection chain composes.
// keyringBackend (W2.0) satisfies it directly.
type storeBackend interface {
	get(service, key string) (string, error)
	set(service, key, value string) error
	delete(service, key string) error
}

// secretStore adapts the selected layer to the exported SecretStore contract.
type secretStore struct {
	backend storeBackend
	label   string
}

// Get returns the stored secret or an error matching ErrNotFound.
func (s *secretStore) Get(service, key string) (string, error) {
	if err := validateCredential(service, key); err != nil {
		return "", err
	}
	return s.backend.get(service, key)
}

// Set stores value in the already-selected backend.
func (s *secretStore) Set(service, key, value string) error {
	if err := validateCredential(service, key); err != nil {
		return err
	}
	return s.backend.set(service, key, value)
}

// Delete removes the entry or returns an error matching ErrNotFound.
func (s *secretStore) Delete(service, key string) error {
	if err := validateCredential(service, key); err != nil {
		return err
	}
	return s.backend.delete(service, key)
}

// Backend reports the label of the selected layer.
func (s *secretStore) Backend() string { return s.label }

// probeService and probeKey name the read-only availability probe. The probe
// never writes: a backend that answers ErrNotFound is healthy, while any other
// error (no D-Bus session, locked keychain, unsupported platform) tells the
// selection chain that the next layer must take over.
const (
	probeService = "tokenhush/probe"
	probeKey     = "backend-availability"
)

// secretStoreConfig is the injectable selection seam. Production uses
// defaultSecretStoreConfig; tests substitute factories to simulate availability
// without touching the machine's keyring.
type secretStoreConfig struct {
	dataDir       string
	keyring       func() keyringBackend
	keyringWorks  func(keyringBackend) bool
	systemd       func(dataDir string) (storeBackend, bool)
	machineSecret func() ([]byte, error)
	warnf         func(format string, args ...any)
}

// OpenSecretStore resolves the platform data dir and selects the strongest
// available backend per the docs/13 §3.2 fallback chain.
func OpenSecretStore() (SecretStore, error) {
	dataDir, err := DataDir()
	if err != nil {
		return nil, err
	}
	return openSecretStore(defaultSecretStoreConfig(dataDir))
}

// defaultSecretStoreConfig wires the production seam: W2.0's native keyring
// factory, the systemd-creds prober (Linux only; a stub elsewhere), the
// best-effort machine secret source and stderr warnings.
func defaultSecretStoreConfig(dataDir string) secretStoreConfig {
	return secretStoreConfig{
		dataDir:       dataDir,
		keyring:       newKeyringBackend,
		keyringWorks:  nativeKeyringAvailable,
		systemd:       newSystemdCredsStore,
		machineSecret: defaultMachineSecret,
		warnf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	}
}

// openSecretStore walks the fallback chain deterministically: native keyring,
// systemd-creds, encrypted file, plaintext file. The first layer that proves
// itself usable wins and is reported by Backend() for the whole store lifetime.
func openSecretStore(cfg secretStoreConfig) (SecretStore, error) {
	if cfg.keyring != nil {
		if backend := cfg.keyring(); backend != nil && cfg.keyringWorks != nil && cfg.keyringWorks(backend) {
			return &secretStore{backend: backend, label: BackendKeyring}, nil
		}
	}

	if cfg.systemd != nil {
		if backend, ok := cfg.systemd(cfg.dataDir); ok && backend != nil {
			return &secretStore{backend: backend, label: BackendSystemdCreds}, nil
		}
	}

	if cfg.machineSecret != nil && cfg.dataDir != "" {
		if machineSecret, err := cfg.machineSecret(); err == nil && len(machineSecret) > 0 {
			if backend, err := newEncryptedFileStore(cfg.dataDir, machineSecret); err == nil {
				return &secretStore{backend: backend, label: BackendFileEncrypted}, nil
			}
		}
	}

	if cfg.dataDir != "" {
		if backend, err := newPlaintextFileStore(cfg.dataDir); err == nil {
			warnPlaintextFallback(cfg, cfg.dataDir)
			return &secretStore{backend: backend, label: BackendFilePlaintext}, nil
		}
	}

	return nil, ErrNoSecretBackend
}

// nativeKeyringAvailable probes a native backend without writing anything.
func nativeKeyringAvailable(backend keyringBackend) bool {
	if backend == nil {
		return false
	}
	_, err := backend.get(probeService, probeKey)
	return err == nil || errors.Is(err, ErrNotFound)
}

// warnPlaintextFallback is never silent: the last-resort layer always reports
// the stable marker and the directory that now holds unencrypted secrets.
func warnPlaintextFallback(cfg secretStoreConfig, dataDir string) {
	if cfg.warnf == nil {
		return
	}
	cfg.warnf("%s (dir: %s)", PlaintextWarningMarker, filepath.Join(dataDir, secretsDirName))
}

// validateCredential is the parse-don't-validate gate every backend call passes
// through.
func validateCredential(service, key string) error {
	if strings.TrimSpace(service) == "" || strings.TrimSpace(key) == "" {
		return errEmptyCredential
	}
	return nil
}
