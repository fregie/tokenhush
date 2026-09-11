package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretStoreRejectsEmptyCredential covers malformed input: blank service
// or key names are typed errors for every backend, never panics.
func TestSecretStoreRejectsEmptyCredential(t *testing.T) {
	t.Parallel()

	stores := make(map[string]SecretStore)
	for name, scenario := range map[string]secretStoreScenario{
		"keyring": {
			keyring:       newFakeKeyring(),
			machineSecret: healthyMachineSecret,
		},
		"encrypted": {
			keyring:       unreachableKeyring(),
			machineSecret: healthyMachineSecret,
		},
		"plaintext": {
			keyring:       unreachableKeyring(),
			machineSecret: brokenMachineSecret,
		},
	} {
		store, err := openSecretStore(scenario.config(t, nil))
		if err != nil {
			t.Fatalf("openSecretStore(%s) error = %v", name, err)
		}
		stores[name] = store
	}

	inputs := []struct{ service, key string }{
		{"", "key"},
		{testService, ""},
		{"   ", "\t"},
	}
	for name, store := range stores {
		for _, input := range inputs {
			if _, err := store.Get(input.service, input.key); !errors.Is(err, errEmptyCredential) {
				t.Fatalf("%s.Get(%q, %q) error = %v, want errEmptyCredential", name, input.service, input.key, err)
			}
			if err := store.Set(input.service, input.key, "value"); !errors.Is(err, errEmptyCredential) {
				t.Fatalf("%s.Set(%q, %q) error = %v, want errEmptyCredential", name, input.service, input.key, err)
			}
			if err := store.Delete(input.service, input.key); !errors.Is(err, errEmptyCredential) {
				t.Fatalf("%s.Delete(%q, %q) error = %v, want errEmptyCredential", name, input.service, input.key, err)
			}
		}
	}
}

// TestSecretStoreOversizeNativeSetFailsWithoutDowngrade defines the size-limit
// behavior: an oversized native Set surfaces errSecretTooBig and the store
// keeps reporting its selected backend instead of silently switching layers.
func TestSecretStoreOversizeNativeSetFailsWithoutDowngrade(t *testing.T) {
	t.Parallel()

	keyring := newFakeKeyring()
	keyring.setErr = errSecretTooBig
	scenario := secretStoreScenario{
		keyring:       keyring,
		machineSecret: healthyMachineSecret,
	}
	cfg := scenario.config(t, nil)
	store, err := openSecretStore(cfg)
	if err != nil {
		t.Fatalf("openSecretStore() error = %v", err)
	}

	err = store.Set(testService, testAccount, strings.Repeat("x", maxSecurityCommandLen))
	if !errors.Is(err, errSecretTooBig) {
		t.Fatalf("Set(oversized) error = %v, want errSecretTooBig", err)
	}
	if got := store.Backend(); got != "keyring" {
		t.Fatalf("Backend() = %q after oversized Set, want %q (no mid-flight downgrade)", got, "keyring")
	}
	if _, statErr := os.Stat(filepath.Join(cfg.dataDir, secretsDirName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("file fallback was created after an oversized native Set (stat error = %v)", statErr)
	}
}
