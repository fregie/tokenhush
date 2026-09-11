package platform

import (
	"errors"
	"strings"
	"testing"
)

// TestSecretStore runs the same contract (Backend label, ErrNotFound semantics,
// lossless round trip including a non-ASCII multi-line secret) across every
// injected availability scenario of the fallback chain.
func TestSecretStore(t *testing.T) {
	t.Parallel()

	scenarios := []secretStoreScenario{
		{
			name:          "native keyring available",
			keyring:       newFakeKeyring(),
			machineSecret: healthyMachineSecret,
			wantBackend:   "keyring",
		},
		{
			name:          "native unavailable falls back to encrypted file",
			keyring:       unreachableKeyring(),
			machineSecret: healthyMachineSecret,
			wantBackend:   "file-encrypted",
		},
		{
			name:          "systemd-creds preferred over encrypted file when available",
			keyring:       unreachableKeyring(),
			systemd:       newMemStore(),
			machineSecret: healthyMachineSecret,
			wantBackend:   "systemd-creds",
		},
		{
			name:          "encrypted unavailable falls back to plaintext",
			keyring:       unreachableKeyring(),
			machineSecret: brokenMachineSecret,
			wantBackend:   "file-plaintext",
			wantWarn:      true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()

			rec := &warningRecorder{}
			store, err := openSecretStore(scenario.config(t, rec))
			if err != nil {
				t.Fatalf("openSecretStore() error = %v", err)
			}
			if got := store.Backend(); got != scenario.wantBackend {
				t.Fatalf("Backend() = %q, want %q", got, scenario.wantBackend)
			}
			t.Logf("scenario=%q backend=%q warnings=%q", scenario.name, store.Backend(), strings.TrimSpace(rec.joined()))

			if scenario.wantWarn && !strings.Contains(rec.joined(), PlaintextWarningMarker) {
				t.Fatalf("plaintext fallback did not emit %q; warnings = %q", PlaintextWarningMarker, rec.joined())
			}
			if !scenario.wantWarn && strings.Contains(rec.joined(), PlaintextWarningMarker) {
				t.Fatalf("non-plaintext backend emitted the plaintext warning marker: %q", rec.joined())
			}

			assertSecretNotFound(t, store)
			assertSecretRoundTrip(t, store)
		})
	}
}

// TestSecretStoreBackendLabelStrings pins the four stable labels doctor and
// audit output rely on.
func TestSecretStoreBackendLabelStrings(t *testing.T) {
	t.Parallel()

	labels := map[string]string{
		BackendKeyring:       "keyring",
		BackendSystemdCreds:  "systemd-creds",
		BackendFileEncrypted: "file-encrypted",
		BackendFilePlaintext: "file-plaintext",
	}
	for got, want := range labels {
		if got != want {
			t.Fatalf("backend label = %q, want %q", got, want)
		}
	}
}

// TestSecretStorePlaintextWarning proves the last-resort layer is never silent:
// the store reports file-plaintext AND emits the warning marker.
func TestSecretStorePlaintextWarning(t *testing.T) {
	t.Parallel()

	scenario := secretStoreScenario{
		keyring:       unreachableKeyring(),
		machineSecret: brokenMachineSecret,
	}
	rec := &warningRecorder{}
	store, err := openSecretStore(scenario.config(t, rec))
	if err != nil {
		t.Fatalf("openSecretStore() error = %v", err)
	}
	if got := store.Backend(); got != "file-plaintext" {
		t.Fatalf("Backend() = %q, want %q", got, "file-plaintext")
	}
	warnings := rec.joined()
	if !strings.Contains(warnings, PlaintextWarningMarker) {
		t.Fatalf("warnings = %q, want marker %q", warnings, PlaintextWarningMarker)
	}
	t.Logf("plaintext fallback: backend=%q warning=%q", store.Backend(), strings.TrimSpace(warnings))
}

// TestSecretStoreNativeProbe pins the availability rule: a backend answering
// "not found" is healthy, any other error (no D-Bus, locked keychain, platform
// without a keyring) means the next layer must take over.
func TestSecretStoreNativeProbe(t *testing.T) {
	t.Parallel()

	if !nativeKeyringAvailable(newFakeKeyring()) {
		t.Fatal("nativeKeyringAvailable() = false for a backend answering ErrNotFound, want true")
	}
	if nativeKeyringAvailable(unreachableKeyring()) {
		t.Fatal("nativeKeyringAvailable() = true for a failing backend, want false")
	}
	if nativeKeyringAvailable(nil) {
		t.Fatal("nativeKeyringAvailable() = true for a nil backend, want false")
	}
}

// TestSecretStoreOpenFailsWithoutBackend proves the selector reports a typed
// error instead of panicking when no layer is usable.
func TestSecretStoreOpenFailsWithoutBackend(t *testing.T) {
	t.Parallel()

	cfg := secretStoreConfig{
		keyring:       func() keyringBackend { return unreachableKeyring() },
		keyringWorks:  nativeKeyringAvailable,
		systemd:       func(string) (storeBackend, bool) { return nil, false },
		machineSecret: brokenMachineSecret,
		warnf:         (&warningRecorder{}).warnf,
	}
	if _, err := openSecretStore(cfg); !errors.Is(err, ErrNoSecretBackend) {
		t.Fatalf("openSecretStore() error = %v, want ErrNoSecretBackend", err)
	}
}
