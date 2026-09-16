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

// Key source kinds reported by stores that can identify where their key comes
// from (KeySourceReporter). These strings are frozen: W3.2's degradation
// warning, tokenhush doctor and the Pro layer branch on these exact values.
const (
	// KeySourceOSBound is an OS-protected source: the native keyring or
	// systemd-creds, where the operating system mediates access to the key
	// material.
	KeySourceOSBound = "os-bound"

	// KeySourceMachineBound is the encrypted-file layer, whose AES key is
	// derived from best-effort machine identity. It is defense in depth above
	// plaintext, not an OS trust boundary.
	KeySourceMachineBound = "machine-bound"

	// KeySourceNone is the plaintext last-resort layer: it has no key source at
	// all. It always emits PlaintextWarningMarker, and reporting "none" keeps
	// it distinct from both keyed kinds so no consumer mistakes an unencrypted
	// store for a keyed one.
	KeySourceNone = "none"
)

// PlaintextWarningMarker is the stable marker emitted whenever the plaintext
// fallback is selected. tokenhush doctor greps for it and the CLI must display
// it verbatim.
const PlaintextWarningMarker = "tokenhush: WARNING: plaintext secret store in use; secrets are NOT encrypted"

// MachineBoundWarningMarker is the stable marker emitted whenever the encrypted
// file layer is selected: entries do have a key, but that key is derived from
// best-effort machine identity rather than an OS keychain, so the layer is
// defense in depth above plaintext, not an OS trust boundary. It is
// deliberately a separate constant from PlaintextWarningMarker — the two name
// different facts ("a key, but only machine-bound" vs "no key at all") and
// must never be conflated. tokenhush doctor greps for it and the CLI must
// display it verbatim.
const MachineBoundWarningMarker = "tokenhush: WARNING: secret store uses a machine-bound key; entries are not protected by an OS keychain"

// SecretStore is the only component allowed to touch an OS secret store. It is
// implemented by the graded fallback chain (native keyring -> systemd-creds ->
// encrypted file -> plaintext file) selected at OpenSecretStore time.
//
// The audit subsystem uses the namespace service "tokenhush/audit" with key
// "hmac-key" (docs/security.md); V1 stores no provider keys.
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

// KeySourceReporter is implemented by secret stores that can report where the
// key protecting their entries comes from; the method name and its values are
// frozen by W3.1. KeySourceKindOf asks a plain SecretStore.
//
// It is deliberately an optional interface instead of a fourth SecretStore
// method: adding a method to the exported SecretStore interface would break
// every external implementation at compile time (the Pro module keeps several
// in-memory SecretStore doubles), while consumers only ever need to ask.
type KeySourceReporter interface {
	// KeySourceKind returns one of KeySourceOSBound, KeySourceMachineBound or
	// KeySourceNone, decided by the branch openSecretStore actually selected.
	KeySourceKind() string
}

// KeySourceKindOf reports the key-source kind of any SecretStore. A nil store,
// or one that does not implement KeySourceReporter (a third-party backend or a
// decorator), reports "" — "cannot report" — never a guessed kind.
func KeySourceKindOf(store SecretStore) string {
	if store == nil {
		return ""
	}
	if reporter, ok := store.(KeySourceReporter); ok {
		return reporter.KeySourceKind()
	}
	return ""
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
	kind    string
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

// KeySourceKind reports where the key of the selected layer comes from,
// decided by the branch openSecretStore actually took: the native keyring and
// systemd-creds report KeySourceOSBound, the encrypted file layer reports
// KeySourceMachineBound, and the plaintext layer reports KeySourceNone (it has
// no key at all).
func (s *secretStore) KeySourceKind() string { return s.kind }

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
// available backend per the docs/security.md fallback chain. Its signature and
// behaviour are unchanged: it is OpenSecretStoreWith with no injected options.
func OpenSecretStore() (SecretStore, error) {
	return OpenSecretStoreWith()
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
// itself usable wins and is reported by Backend() and KeySourceKind() for the
// whole store lifetime.
func openSecretStore(cfg secretStoreConfig) (SecretStore, error) {
	if cfg.keyring != nil {
		if backend := cfg.keyring(); backend != nil && cfg.keyringWorks != nil && cfg.keyringWorks(backend) {
			return &secretStore{backend: backend, label: BackendKeyring, kind: KeySourceOSBound}, nil
		}
	}

	if cfg.systemd != nil {
		if backend, ok := cfg.systemd(cfg.dataDir); ok && backend != nil {
			return &secretStore{backend: backend, label: BackendSystemdCreds, kind: KeySourceOSBound}, nil
		}
	}

	if cfg.machineSecret != nil && cfg.dataDir != "" {
		if machineSecret, err := cfg.machineSecret(); err == nil && len(machineSecret) > 0 {
			if backend, err := newEncryptedFileStore(cfg.dataDir, machineSecret); err == nil {
				warnMachineBoundFallback(cfg, cfg.dataDir)
				return &secretStore{backend: backend, label: BackendFileEncrypted, kind: KeySourceMachineBound}, nil
			}
		}
	}

	if cfg.dataDir != "" {
		if backend, err := newPlaintextFileStore(cfg.dataDir); err == nil {
			warnPlaintextFallback(cfg, cfg.dataDir)
			return &secretStore{backend: backend, label: BackendFilePlaintext, kind: KeySourceNone}, nil
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

// warnMachineBoundFallback reports the recorded degradation through the same
// writer as the plaintext marker: the encrypted layer has a key, but only a
// machine-bound one. The warning is informational and never fails selection —
// a failing writer is ignored, exactly like the plaintext marker.
func warnMachineBoundFallback(cfg secretStoreConfig, dataDir string) {
	if cfg.warnf == nil {
		return
	}
	cfg.warnf("%s (dir: %s)", MachineBoundWarningMarker, filepath.Join(dataDir, secretsDirName))
}

// validateCredential is the parse-don't-validate gate every backend call passes
// through.
func validateCredential(service, key string) error {
	if strings.TrimSpace(service) == "" || strings.TrimSpace(key) == "" {
		return errEmptyCredential
	}
	return nil
}
