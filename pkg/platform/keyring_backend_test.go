package platform

import "testing"

// TestNewKeyringBackendReportsName pins the W2.2 seam: every supported OS
// resolves a low-level backend with a non-empty, human-readable label that
// tokenhush doctor will surface through SecretStore.Backend().
func TestNewKeyringBackendReportsName(t *testing.T) {
	t.Parallel()

	backend := newKeyringBackend()
	if backend == nil {
		t.Fatal("newKeyringBackend() returned nil")
	}
	if name := backend.name(); name == "" {
		t.Fatal("newKeyringBackend().name() is empty")
	}
}

// TestSecurityIndicatesNotFound pins the `security(1)` missing-entry detection
// used by the darwin Get/Delete paths.
func TestSecurityIndicatesNotFound(t *testing.T) {
	t.Parallel()

	if !securityIndicatesNotFound([]byte("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.")) {
		t.Fatal("securityIndicatesNotFound() missed a not-found message")
	}
	if securityIndicatesNotFound([]byte("security: invalid argument")) {
		t.Fatal("securityIndicatesNotFound() matched an unrelated error")
	}
}
