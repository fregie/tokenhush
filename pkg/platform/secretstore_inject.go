package platform

import (
	"fmt"
	"io"
)

// SecretSource is the exported injection form of one secret-store layer
// primitive. The unexported storeBackend/keyringBackend interfaces cannot be
// implemented from another Go module, so OpenSecretStoreWith accepts injected
// layers in this exported shape and adapts them internally. Both the
// native-keyring layer and the systemd-creds layer speak it.
//
// A SecretSource must behave like a backend: Get returns an error matching
// ErrNotFound for a missing entry, Set stores the value and Delete removes it,
// reporting ErrNotFound when the entry does not exist.
type SecretSource interface {
	Get(service, key string) (string, error)
	Set(service, key, value string) error
	Delete(service, key string) error
}

// injectedSource adapts an exported SecretSource to the internal layer
// primitive. It satisfies both storeBackend and keyringBackend; the extra name
// method is a fixed, non-secret label.
type injectedSource struct{ source SecretSource }

func (s injectedSource) get(service, key string) (string, error) {
	return s.source.Get(service, key)
}

func (s injectedSource) set(service, key, value string) error {
	return s.source.Set(service, key, value)
}

func (s injectedSource) delete(service, key string) error {
	return s.source.Delete(service, key)
}

func (s injectedSource) name() string { return "injected secret source" }

// SecretStoreOption configures OpenSecretStoreWith. The zero set of options
// keeps every production default, so OpenSecretStore() is exactly
// OpenSecretStoreWith().
type SecretStoreOption func(*secretStoreOptions)

// secretStoreOptions is the mutable accumulator the options write into. It
// starts from the production seam and is converted to a secretStoreConfig once
// all options have been applied; dataDir is resolved lazily so an injected
// WithDataDir can bypass platform resolution.
type secretStoreOptions struct {
	cfg        secretStoreConfig
	dataDir    string
	dataDirSet bool
}

// newSecretStoreOptions seeds the production configuration without a data dir.
func newSecretStoreOptions() *secretStoreOptions {
	return &secretStoreOptions{cfg: defaultSecretStoreConfig("")}
}

// OpenSecretStoreWith is OpenSecretStore with an injectable selection seam. It
// is the W3.1 entry point the Pro layer uses to inject the OS-bound sources,
// the machine-secret derivation and the data dir, and to observe the resulting
// provenance through KeySourceKindOf.
//
// With no options it keeps the production behaviour byte for byte: resolve the
// platform data dir (DataDir), then walk keyring -> systemd-creds -> encrypted
// file -> plaintext file. Options never weaken a default silently: a failing
// injected layer degrades along the same chain, and the plaintext last resort
// still emits PlaintextWarningMarker.
func OpenSecretStoreWith(opts ...SecretStoreOption) (SecretStore, error) {
	o := newSecretStoreOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	if o.dataDirSet {
		o.cfg.dataDir = o.dataDir
	} else {
		dataDir, err := DataDir()
		if err != nil {
			return nil, err
		}
		o.cfg.dataDir = dataDir
	}
	return openSecretStore(o.cfg)
}

// WithDataDir overrides the platform data dir. Passing "" keeps an empty data
// dir, which disables both file layers exactly like the internal configuration
// (useful to prove the no-backend path). Omitting the option resolves the
// platform default via DataDir().
func WithDataDir(dir string) SecretStoreOption {
	return func(o *secretStoreOptions) {
		o.dataDir, o.dataDirSet = dir, true
	}
}

// WithKeyringSource injects the native-keyring layer: source constructs the
// backend primitive (returning nil disables the layer) and probe reports
// availability. A nil probe applies the production rule — a backend answering
// ErrNotFound is healthy, any other error means the next layer takes over. A
// nil source factory disables the layer entirely, which is how a machine
// without a keyring is simulated.
func WithKeyringSource(source func() SecretSource, probe func(SecretSource) bool) SecretStoreOption {
	return func(o *secretStoreOptions) {
		if source == nil {
			o.cfg.keyring, o.cfg.keyringWorks = nil, nil
			return
		}
		o.cfg.keyring = func() keyringBackend {
			if src := source(); src != nil {
				return injectedSource{source: src}
			}
			return nil
		}
		o.cfg.keyringWorks = func(backend keyringBackend) bool {
			if probe == nil {
				return nativeKeyringAvailable(backend)
			}
			injected, ok := backend.(injectedSource)
			return ok && probe(injected.source)
		}
	}
}

// WithSystemdSource injects the systemd-creds layer lookup. The lookup gets the
// resolved data dir and reports (source, ok); ok=false or a nil source means
// the layer is unavailable and the chain continues. A nil lookup disables the
// layer entirely.
func WithSystemdSource(lookup func(dataDir string) (SecretSource, bool)) SecretStoreOption {
	return func(o *secretStoreOptions) {
		if lookup == nil {
			o.cfg.systemd = nil
			return
		}
		o.cfg.systemd = func(dataDir string) (storeBackend, bool) {
			source, ok := lookup(dataDir)
			if !ok || source == nil {
				return nil, false
			}
			return injectedSource{source: source}, true
		}
	}
}

// WithMachineSecretSource injects the machine-bound secret derivation behind
// the encrypted-file layer. An error or an empty secret makes the layer report
// itself unavailable so the chain falls through to the warned plaintext layer;
// a nil source disables the layer entirely. The derivation itself is unchanged
// (HKDF-SHA256 over the machine secret), so existing ciphertext keeps
// decrypting.
func WithMachineSecretSource(source func() ([]byte, error)) SecretStoreOption {
	return func(o *secretStoreOptions) {
		o.cfg.machineSecret = source
	}
}

// WithWarningWriter redirects the store's degradation warnings (currently the
// plaintext fallback marker) to w. A nil writer is ignored, so the never-silent
// stderr sink is never accidentally removed.
func WithWarningWriter(w io.Writer) SecretStoreOption {
	return func(o *secretStoreOptions) {
		if w == nil {
			return
		}
		o.cfg.warnf = func(format string, args ...any) {
			fmt.Fprintf(w, format+"\n", args...)
		}
	}
}
