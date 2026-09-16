package platform

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// failingSink is an io.Writer that always fails, proving the degradation
// warning path is non-fatal: a broken sink must never break store selection.
type failingSink struct{}

func (failingSink) Write([]byte) (int, error) {
	return 0, errors.New("warning sink unavailable")
}

// TestSecretStoreMachineBoundWarning is the W3.2 gate: selecting the encrypted
// file layer (machine-bound key) emits its own stable, greppable marker, while
// the OS-bound layers stay silent and the plaintext last resort keeps emitting
// only its own PlaintextWarningMarker. The two markers name different facts
// ("a key, but only machine-bound" vs "no key at all") and must never be
// conflated.
func TestSecretStoreMachineBoundWarning(t *testing.T) {
	t.Parallel()

	if MachineBoundWarningMarker == PlaintextWarningMarker {
		t.Fatalf("MachineBoundWarningMarker and PlaintextWarningMarker must be distinct; both are %q", PlaintextWarningMarker)
	}

	unusable := errors.New("injected OS-bound source is unusable")
	bothMarkers := []string{MachineBoundWarningMarker, PlaintextWarningMarker}

	tests := []struct {
		name          string
		keyring       func() SecretSource
		systemd       func(string) (SecretSource, bool)
		machineSecret func() ([]byte, error)
		wantKind      string
		wantMarker    string
		forbidMarkers []string
	}{
		{
			name:          "machine_bound_emits_its_own_marker",
			keyring:       func() SecretSource { return failingSource{err: unusable} },
			systemd:       func(string) (SecretSource, bool) { return nil, false },
			machineSecret: healthyMachineSecret,
			wantKind:      KeySourceMachineBound,
			wantMarker:    MachineBoundWarningMarker,
			forbidMarkers: []string{PlaintextWarningMarker},
		},
		{
			name:          "os_bound_keyring_is_silent",
			keyring:       func() SecretSource { return exportedSource{newFakeKeyring()} },
			systemd:       func(string) (SecretSource, bool) { return nil, false },
			machineSecret: healthyMachineSecret,
			wantKind:      KeySourceOSBound,
			forbidMarkers: bothMarkers,
		},
		{
			name:          "os_bound_systemd_is_silent",
			keyring:       func() SecretSource { return failingSource{err: unusable} },
			systemd:       func(string) (SecretSource, bool) { return exportedSource{newMemStore()}, true },
			machineSecret: healthyMachineSecret,
			wantKind:      KeySourceOSBound,
			forbidMarkers: bothMarkers,
		},
		{
			name:          "plaintext_emits_only_the_plaintext_marker",
			keyring:       func() SecretSource { return failingSource{err: unusable} },
			systemd:       func(string) (SecretSource, bool) { return nil, false },
			machineSecret: brokenMachineSecret,
			wantKind:      KeySourceNone,
			wantMarker:    PlaintextWarningMarker,
			forbidMarkers: []string{MachineBoundWarningMarker},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var warnings bytes.Buffer
			store, err := OpenSecretStoreWith(
				WithDataDir(t.TempDir()),
				WithKeyringSource(tc.keyring, nil),
				WithSystemdSource(tc.systemd),
				WithMachineSecretSource(tc.machineSecret),
				WithWarningWriter(&warnings),
			)
			if err != nil {
				t.Fatalf("OpenSecretStoreWith() error = %v", err)
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
			if tc.wantMarker != "" && !strings.Contains(warnings.String(), tc.wantMarker) {
				t.Fatalf("warnings = %q, want marker %q", warnings.String(), tc.wantMarker)
			}
			for _, forbidden := range tc.forbidMarkers {
				if strings.Contains(warnings.String(), forbidden) {
					t.Fatalf("warnings = %q, must not contain %q", warnings.String(), forbidden)
				}
			}
			t.Logf("backend=%q kind=%q warnings=%q", store.Backend(), tc.wantKind, strings.TrimSpace(warnings.String()))

			assertSecretRoundTrip(t, store)
		})
	}
}

// TestSecretStoreMachineBoundWarningIsNotFatal pins the non-fatal contract: a
// warning writer that fails must not fail store construction or selection.
func TestSecretStoreMachineBoundWarningIsNotFatal(t *testing.T) {
	t.Parallel()

	store, err := OpenSecretStoreWith(
		WithDataDir(t.TempDir()),
		WithKeyringSource(func() SecretSource {
			return failingSource{err: errors.New("no D-Bus secret service")}
		}, nil),
		WithSystemdSource(nil),
		WithMachineSecretSource(healthyMachineSecret),
		WithWarningWriter(failingSink{}),
	)
	if err != nil {
		t.Fatalf("OpenSecretStoreWith() with a failing warning sink error = %v, want a usable store", err)
	}
	if got := KeySourceKindOf(store); got != KeySourceMachineBound {
		t.Fatalf("KeySourceKindOf() = %q, want %q", got, KeySourceMachineBound)
	}
	if got := store.Backend(); got != BackendFileEncrypted {
		t.Fatalf("Backend() = %q, want %q", got, BackendFileEncrypted)
	}
}
