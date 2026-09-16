package platform

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// exportedSource adapts the in-package storeBackend fakes to the exported
// SecretSource injection surface. The injection tests must drive the public
// entry point (OpenSecretStoreWith), so they cannot hand the unexported
// interfaces to the options; this adapter is the test-side bridge.
type exportedSource struct{ inner storeBackend }

func (e exportedSource) Get(service, key string) (string, error) {
	return e.inner.get(service, key)
}

func (e exportedSource) Set(service, key, value string) error {
	return e.inner.set(service, key, value)
}

func (e exportedSource) Delete(service, key string) error {
	return e.inner.delete(service, key)
}

var _ SecretSource = exportedSource{}

// failingSource is a SecretSource whose every operation fails with the same
// error, simulating an OS-bound layer that is present but unusable (locked
// keychain, no D-Bus session, systemd-creds refusing).
type failingSource struct{ err error }

func (f failingSource) Get(string, string) (string, error) { return "", f.err }
func (f failingSource) Set(string, string, string) error   { return f.err }
func (f failingSource) Delete(string, string) error        { return f.err }

var _ SecretSource = failingSource{}

// nonReportingStore implements SecretStore without KeySourceKind, the shape a
// third-party implementation or a decorator keeps. KeySourceKindOf must treat
// it as "unknown" instead of panicking or guessing.
type nonReportingStore struct{}

func (nonReportingStore) Get(string, string) (string, error) { return "", ErrNotFound }
func (nonReportingStore) Set(string, string, string) error   { return nil }
func (nonReportingStore) Delete(string, string) error        { return ErrNotFound }
func (nonReportingStore) Backend() string                    { return "third-party" }

// TestKeySourceKindConstants pins the frozen kind strings so W3.2/W3.3 and the
// Pro module cannot drift from the values this store reports.
func TestKeySourceKindConstants(t *testing.T) {
	t.Parallel()

	kinds := map[string]string{
		KeySourceOSBound:      "os-bound",
		KeySourceMachineBound: "machine-bound",
		KeySourceNone:         "none",
	}
	for got, want := range kinds {
		if got != want {
			t.Fatalf("key source kind = %q, want %q", got, want)
		}
	}
}

// TestOpenSecretStoreWithBranchKinds drives every fallback-chain branch
// through the exported injection entry and asserts both the unchanged
// Backend() label and the new KeySourceKind() provenance.
func TestOpenSecretStoreWithBranchKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		opts        func(t *testing.T) []SecretStoreOption
		wantBackend string
		wantKind    string
		wantWarn    bool
	}{
		{
			name: "keyring_available_is_os_bound",
			opts: func(t *testing.T) []SecretStoreOption {
				return []SecretStoreOption{
					WithDataDir(t.TempDir()),
					WithKeyringSource(func() SecretSource { return exportedSource{newFakeKeyring()} }, nil),
					WithSystemdSource(func(string) (SecretSource, bool) { return exportedSource{newMemStore()}, true }),
					WithMachineSecretSource(healthyMachineSecret),
				}
			},
			wantBackend: BackendKeyring,
			wantKind:    KeySourceOSBound,
		},
		{
			name: "systemd_creds_available_is_os_bound",
			opts: func(t *testing.T) []SecretStoreOption {
				return []SecretStoreOption{
					WithDataDir(t.TempDir()),
					WithKeyringSource(func() SecretSource {
						return failingSource{err: errors.New("no D-Bus secret service")}
					}, nil),
					WithSystemdSource(func(string) (SecretSource, bool) { return exportedSource{newMemStore()}, true }),
					WithMachineSecretSource(healthyMachineSecret),
				}
			},
			wantBackend: BackendSystemdCreds,
			wantKind:    KeySourceOSBound,
		},
		{
			name: "encrypted_file_is_machine_bound",
			opts: func(t *testing.T) []SecretStoreOption {
				return []SecretStoreOption{
					WithDataDir(t.TempDir()),
					WithKeyringSource(func() SecretSource {
						return failingSource{err: errors.New("no D-Bus secret service")}
					}, nil),
					WithSystemdSource(func(string) (SecretSource, bool) { return nil, false }),
					WithMachineSecretSource(healthyMachineSecret),
				}
			},
			wantBackend: BackendFileEncrypted,
			wantKind:    KeySourceMachineBound,
		},
		{
			name: "plaintext_file_has_no_key_source",
			opts: func(t *testing.T) []SecretStoreOption {
				return []SecretStoreOption{
					WithDataDir(t.TempDir()),
					WithKeyringSource(func() SecretSource {
						return failingSource{err: errors.New("no D-Bus secret service")}
					}, nil),
					WithSystemdSource(func(string) (SecretSource, bool) { return nil, false }),
					WithMachineSecretSource(brokenMachineSecret),
				}
			},
			wantBackend: BackendFilePlaintext,
			wantKind:    KeySourceNone,
			wantWarn:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var warnings bytes.Buffer
			opts := append(tc.opts(t), WithWarningWriter(&warnings))
			store, err := OpenSecretStoreWith(opts...)
			if err != nil {
				t.Fatalf("OpenSecretStoreWith() error = %v", err)
			}
			if got := store.Backend(); got != tc.wantBackend {
				t.Fatalf("Backend() = %q, want %q", got, tc.wantBackend)
			}
			reporter, ok := store.(KeySourceReporter)
			if !ok {
				t.Fatal("store does not implement KeySourceReporter")
			}
			if got := reporter.KeySourceKind(); got != tc.wantKind {
				t.Fatalf("KeySourceKind() = %q, want %q", got, tc.wantKind)
			}
			if got := KeySourceKindOf(store); got != tc.wantKind {
				t.Fatalf("KeySourceKindOf() = %q, want %q", got, tc.wantKind)
			}
			gotWarn := strings.Contains(warnings.String(), PlaintextWarningMarker)
			if gotWarn != tc.wantWarn {
				t.Fatalf("plaintext warning emitted = %v (warnings %q), want %v", gotWarn, warnings.String(), tc.wantWarn)
			}
			t.Logf("backend=%q kind=%q warnings=%q", store.Backend(), KeySourceKindOf(store), strings.TrimSpace(warnings.String()))

			assertSecretNotFound(t, store)
			assertSecretRoundTrip(t, store)
		})
	}
}

// TestOpenSecretStoreWithPreferenceOrder pins the unchanged order keyring >
// systemd-creds > encrypted file > plaintext, driven entirely through the new
// injection entry (no real keyring or systemd-creds on the machine is needed).
func TestOpenSecretStoreWithPreferenceOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		keyring       func() SecretSource
		keyringProbe  func(SecretSource) bool
		systemd       func(string) (SecretSource, bool)
		machineSecret func() ([]byte, error)
		wantBackend   string
		wantWarn      bool
	}{
		{
			name:          "keyring_wins_over_everything",
			keyring:       func() SecretSource { return exportedSource{newFakeKeyring()} },
			systemd:       func(string) (SecretSource, bool) { return exportedSource{newMemStore()}, true },
			machineSecret: healthyMachineSecret,
			wantBackend:   BackendKeyring,
		},
		{
			name:          "systemd_wins_over_encrypted_file",
			keyring:       func() SecretSource { return failingSource{err: errors.New("unusable")} },
			systemd:       func(string) (SecretSource, bool) { return exportedSource{newMemStore()}, true },
			machineSecret: healthyMachineSecret,
			wantBackend:   BackendSystemdCreds,
		},
		{
			name:          "encrypted_file_wins_over_plaintext",
			keyring:       func() SecretSource { return failingSource{err: errors.New("unusable")} },
			systemd:       func(string) (SecretSource, bool) { return nil, false },
			machineSecret: healthyMachineSecret,
			wantBackend:   BackendFileEncrypted,
		},
		{
			name:          "plaintext_is_the_documented_last_resort",
			keyring:       func() SecretSource { return failingSource{err: errors.New("unusable")} },
			systemd:       func(string) (SecretSource, bool) { return nil, false },
			machineSecret: brokenMachineSecret,
			wantBackend:   BackendFilePlaintext,
			wantWarn:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var warnings bytes.Buffer
			store, err := OpenSecretStoreWith(
				WithDataDir(t.TempDir()),
				WithKeyringSource(tc.keyring, tc.keyringProbe),
				WithSystemdSource(tc.systemd),
				WithMachineSecretSource(tc.machineSecret),
				WithWarningWriter(&warnings),
			)
			if err != nil {
				t.Fatalf("OpenSecretStoreWith() error = %v", err)
			}
			if got := store.Backend(); got != tc.wantBackend {
				t.Fatalf("Backend() = %q, want %q", got, tc.wantBackend)
			}
			if gotWarn := strings.Contains(warnings.String(), PlaintextWarningMarker); gotWarn != tc.wantWarn {
				t.Fatalf("plaintext warning emitted = %v (warnings %q), want %v", gotWarn, warnings.String(), tc.wantWarn)
			}
			t.Logf("scenario=%q backend=%q kind=%q", tc.name, store.Backend(), KeySourceKindOf(store))
		})
	}
}

// TestOpenSecretStoreWithDegradesOnInjectedFailures is the never-silent gate:
// an injected seam that fails must fall through along the existing chain and,
// if the chain lands on plaintext, the stable warning marker must be emitted.
func TestOpenSecretStoreWithDegradesOnInjectedFailures(t *testing.T) {
	t.Parallel()

	unusable := errors.New("injected OS-bound source is unusable")

	t.Run("keyring_failure_falls_through_to_systemd", func(t *testing.T) {
		t.Parallel()

		var warnings bytes.Buffer
		store, err := OpenSecretStoreWith(
			WithDataDir(t.TempDir()),
			WithKeyringSource(func() SecretSource { return failingSource{err: unusable} }, nil),
			WithSystemdSource(func(string) (SecretSource, bool) { return exportedSource{newMemStore()}, true }),
			WithMachineSecretSource(healthyMachineSecret),
			WithWarningWriter(&warnings),
		)
		if err != nil {
			t.Fatalf("OpenSecretStoreWith() error = %v", err)
		}
		if got := store.Backend(); got != BackendSystemdCreds {
			t.Fatalf("Backend() = %q, want %q after a failing keyring seam", got, BackendSystemdCreds)
		}
		if strings.Contains(warnings.String(), PlaintextWarningMarker) {
			t.Fatalf("plaintext warning emitted although the encrypted chain held: %q", warnings.String())
		}
		t.Logf("keyring(failing) -> backend=%q kind=%q warnings=%q", store.Backend(), KeySourceKindOf(store), strings.TrimSpace(warnings.String()))
	})

	t.Run("explicit_keyring_probe_veto_falls_through", func(t *testing.T) {
		t.Parallel()

		store, err := OpenSecretStoreWith(
			WithDataDir(t.TempDir()),
			WithKeyringSource(
				func() SecretSource { return exportedSource{newFakeKeyring()} },
				func(SecretSource) bool { return false },
			),
			WithSystemdSource(func(string) (SecretSource, bool) { return exportedSource{newMemStore()}, true }),
			WithMachineSecretSource(healthyMachineSecret),
			WithWarningWriter(&bytes.Buffer{}),
		)
		if err != nil {
			t.Fatalf("OpenSecretStoreWith() error = %v", err)
		}
		if got := store.Backend(); got != BackendSystemdCreds {
			t.Fatalf("Backend() = %q, want %q after a probe veto", got, BackendSystemdCreds)
		}
		t.Logf("keyring(probe veto) -> backend=%q kind=%q", store.Backend(), KeySourceKindOf(store))
	})

	t.Run("systemd_failure_falls_through_to_encrypted_file", func(t *testing.T) {
		t.Parallel()

		var warnings bytes.Buffer
		store, err := OpenSecretStoreWith(
			WithDataDir(t.TempDir()),
			WithKeyringSource(func() SecretSource { return failingSource{err: unusable} }, nil),
			WithSystemdSource(func(string) (SecretSource, bool) { return nil, false }),
			WithMachineSecretSource(healthyMachineSecret),
			WithWarningWriter(&warnings),
		)
		if err != nil {
			t.Fatalf("OpenSecretStoreWith() error = %v", err)
		}
		if got := store.Backend(); got != BackendFileEncrypted {
			t.Fatalf("Backend() = %q, want %q after a failing systemd seam", got, BackendFileEncrypted)
		}
		if got := KeySourceKindOf(store); got != KeySourceMachineBound {
			t.Fatalf("KeySourceKindOf() = %q, want %q", got, KeySourceMachineBound)
		}
		if strings.Contains(warnings.String(), PlaintextWarningMarker) {
			t.Fatalf("plaintext warning emitted although encryption held: %q", warnings.String())
		}
		t.Logf("systemd(declining) -> backend=%q kind=%q warnings=%q", store.Backend(), KeySourceKindOf(store), strings.TrimSpace(warnings.String()))
	})

	t.Run("machine_secret_failure_lands_on_plaintext_with_warning", func(t *testing.T) {
		t.Parallel()

		var warnings bytes.Buffer
		store, err := OpenSecretStoreWith(
			WithDataDir(t.TempDir()),
			WithKeyringSource(func() SecretSource { return failingSource{err: unusable} }, nil),
			WithSystemdSource(func(string) (SecretSource, bool) { return nil, false }),
			WithMachineSecretSource(func() ([]byte, error) { return nil, errNoMachineSecret }),
			WithWarningWriter(&warnings),
		)
		if err != nil {
			t.Fatalf("OpenSecretStoreWith() error = %v", err)
		}
		if got := store.Backend(); got != BackendFilePlaintext {
			t.Fatalf("Backend() = %q, want %q", got, BackendFilePlaintext)
		}
		if got := KeySourceKindOf(store); got != KeySourceNone {
			t.Fatalf("KeySourceKindOf() = %q, want %q (plaintext has no key source)", got, KeySourceNone)
		}
		if !strings.Contains(warnings.String(), PlaintextWarningMarker) {
			t.Fatalf("plaintext fallback was silent: warnings = %q, want marker %q", warnings.String(), PlaintextWarningMarker)
		}
		t.Logf("machine-secret(failing) -> backend=%q kind=%q warning=%q", store.Backend(), KeySourceKindOf(store), strings.TrimSpace(warnings.String()))
	})

	t.Run("absent_machine_secret_source_lands_on_plaintext_with_warning", func(t *testing.T) {
		t.Parallel()

		var warnings bytes.Buffer
		store, err := OpenSecretStoreWith(
			WithDataDir(t.TempDir()),
			WithKeyringSource(nil, nil),
			WithSystemdSource(nil),
			WithMachineSecretSource(nil),
			WithWarningWriter(&warnings),
		)
		if err != nil {
			t.Fatalf("OpenSecretStoreWith() error = %v", err)
		}
		if got := store.Backend(); got != BackendFilePlaintext {
			t.Fatalf("Backend() = %q, want %q", got, BackendFilePlaintext)
		}
		if !strings.Contains(warnings.String(), PlaintextWarningMarker) {
			t.Fatalf("plaintext fallback was silent: warnings = %q, want marker %q", warnings.String(), PlaintextWarningMarker)
		}
		t.Logf("all sealed layers absent -> backend=%q kind=%q warning=%q", store.Backend(), KeySourceKindOf(store), strings.TrimSpace(warnings.String()))
	})

	t.Run("no_layer_usable_fails_typed_not_plaintext", func(t *testing.T) {
		t.Parallel()

		store, err := OpenSecretStoreWith(
			WithDataDir(""),
			WithKeyringSource(nil, nil),
			WithSystemdSource(nil),
			WithMachineSecretSource(nil),
		)
		if !errors.Is(err, ErrNoSecretBackend) {
			t.Fatalf("OpenSecretStoreWith() error = %v, want ErrNoSecretBackend", err)
		}
		if store != nil {
			t.Fatalf("OpenSecretStoreWith() = %v alongside error, want nil", store)
		}
	})
}

// TestKeySourceKindOfTolerantOfForeignStores proves the accessor is safe for
// plain SecretStore values: nil and stores without the optional interface
// report "unknown" (empty string) instead of panicking or mislabelling.
func TestKeySourceKindOfTolerantOfForeignStores(t *testing.T) {
	t.Parallel()

	if got := KeySourceKindOf(nil); got != "" {
		t.Fatalf("KeySourceKindOf(nil) = %q, want empty", got)
	}
	if got := KeySourceKindOf(nonReportingStore{}); got != "" {
		t.Fatalf("KeySourceKindOf(third-party store) = %q, want empty", got)
	}

	store, err := OpenSecretStoreWith(
		WithDataDir(t.TempDir()),
		WithKeyringSource(func() SecretSource { return exportedSource{newFakeKeyring()} }, nil),
	)
	if err != nil {
		t.Fatalf("OpenSecretStoreWith() error = %v", err)
	}
	if got := KeySourceKindOf(store); got != KeySourceOSBound {
		t.Fatalf("KeySourceKindOf(keyring store) = %q, want %q", got, KeySourceOSBound)
	}
}

// TestOpenSecretStoreStillResolvesThroughTheChain pins the unchanged public
// entry: OpenSecretStore keeps its signature and still resolves the platform
// data dir through the same production chain (no options = defaults).
func TestOpenSecretStoreStillResolvesThroughTheChain(t *testing.T) {
	t.Setenv(homeEnvVar, t.TempDir())

	var _ func() (SecretStore, error) = OpenSecretStore // signature pin

	store, err := OpenSecretStore()
	if err != nil {
		t.Fatalf("OpenSecretStore() error = %v", err)
	}
	switch got := store.Backend(); got {
	case BackendKeyring, BackendSystemdCreds, BackendFileEncrypted, BackendFilePlaintext:
	default:
		t.Fatalf("Backend() = %q, want one of the four stable labels", got)
	}
	switch got := KeySourceKindOf(store); got {
	case KeySourceOSBound, KeySourceMachineBound, KeySourceNone:
	default:
		t.Fatalf("KeySourceKindOf() = %q, want a documented kind", got)
	}
	t.Logf("OpenSecretStore backend=%q kind=%q", store.Backend(), KeySourceKindOf(store))
}
