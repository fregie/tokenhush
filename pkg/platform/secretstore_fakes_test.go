package platform

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// warningRecorder captures plaintext-fallback warnings so tests can assert the
// marker is emitted without depending on stderr. Each scenario owns its own
// recorder, which keeps the tests parallel-safe.
type warningRecorder struct {
	mu       sync.Mutex
	messages []string
}

func (r *warningRecorder) warnf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
}

func (r *warningRecorder) joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.messages, "\n")
}

// fakeKeyring is the in-memory keyringBackend fake behind the injectable
// factory. readErr simulates a box with no reachable native secret service;
// setErr simulates a native Set rejection such as errSecretTooBig.
type fakeKeyring struct {
	mu      sync.Mutex
	entries map[string]string
	readErr error
	setErr  error
}

func newFakeKeyring() *fakeKeyring {
	return &fakeKeyring{entries: make(map[string]string)}
}

func fakeKey(service, account string) string { return service + "\x00" + account }

func (f *fakeKeyring) get(service, account string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return "", f.readErr
	}
	value, ok := f.entries[fakeKey(service, account)]
	if !ok {
		return "", ErrSecretNotFound
	}
	return value, nil
}

func (f *fakeKeyring) set(service, account, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.entries[fakeKey(service, account)] = secret
	return nil
}

func (f *fakeKeyring) delete(service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return f.readErr
	}
	if _, ok := f.entries[fakeKey(service, account)]; !ok {
		return ErrSecretNotFound
	}
	delete(f.entries, fakeKey(service, account))
	return nil
}

func (f *fakeKeyring) name() string { return "in-memory fake keyring" }

// memStore is a minimal storeBackend used to simulate an available
// systemd-creds layer without the systemd-creds binary.
type memStore struct {
	mu      sync.Mutex
	entries map[string]string
}

func newMemStore() *memStore { return &memStore{entries: make(map[string]string)} }

func (m *memStore) get(service, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.entries[fakeKey(service, key)]
	if !ok {
		return "", ErrNotFound
	}
	return value, nil
}

func (m *memStore) set(service, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[fakeKey(service, key)] = value
	return nil
}

func (m *memStore) delete(service, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[fakeKey(service, key)]; !ok {
		return ErrNotFound
	}
	delete(m.entries, fakeKey(service, key))
	return nil
}

func healthyMachineSecret() ([]byte, error) {
	return []byte("unit-test-machine-bound-secret"), nil
}

func brokenMachineSecret() ([]byte, error) {
	return nil, errNoMachineSecret
}

func unreachableKeyring() keyringBackend {
	kr := newFakeKeyring()
	kr.readErr = errors.New("no Secret Service on this machine")
	return kr
}

// secretStoreScenario names one injected availability combination plus its
// expected selection outcome.
type secretStoreScenario struct {
	name          string
	keyring       keyringBackend
	systemd       storeBackend
	machineSecret func() ([]byte, error)
	wantBackend   string
	wantWarn      bool
}

// config wires the injectable selection seams with a fresh temp data dir.
func (sc secretStoreScenario) config(t *testing.T, rec *warningRecorder) secretStoreConfig {
	t.Helper()
	if rec == nil {
		rec = &warningRecorder{}
	}
	return secretStoreConfig{
		dataDir:      t.TempDir(),
		keyring:      func() keyringBackend { return sc.keyring },
		keyringWorks: nativeKeyringAvailable,
		systemd: func(string) (storeBackend, bool) {
			if sc.systemd == nil {
				return nil, false
			}
			return sc.systemd, true
		},
		machineSecret: sc.machineSecret,
		warnf:         rec.warnf,
	}
}

func assertSecretNotFound(t *testing.T, store SecretStore) {
	t.Helper()
	if _, err := store.Get(testService, "definitely-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing key) error = %v, want ErrNotFound", err)
	}
}

func assertSecretRoundTrip(t *testing.T, store SecretStore) {
	t.Helper()

	if err := store.Set(testService, testAccount, testSecret); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := store.Get(testService, testAccount)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != testSecret {
		t.Fatalf("Get() = %q, want %q (non-ASCII/multi-line must survive)", got, testSecret)
	}

	if err := store.Set(testService, testAccount, "second value"); err != nil {
		t.Fatalf("Set(overwrite) error = %v", err)
	}
	if got, err = store.Get(testService, testAccount); err != nil || got != "second value" {
		t.Fatalf("Get() after overwrite = (%q, %v), want (%q, nil)", got, err, "second value")
	}

	if err := store.Delete(testService, testAccount); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Get(testService, testAccount); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after Delete error = %v, want ErrNotFound", err)
	}
	if err := store.Delete(testService, testAccount); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete() on a missing entry error = %v, want ErrNotFound", err)
	}
}
