//go:build !windows

package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestControlTokenFileMode locks the POSIX permission contract of
// <dataDir>/control.token: only the owning user may read or write the token.
// On Windows POSIX mode bits do not apply; the file relies on the per-user
// %LOCALAPPDATA% ACL instead, so this test is excluded there.
func TestControlTokenFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ControlTokenFileName)

	// A pre-existing looser file must be replaced, not reopened in place.
	if err := os.WriteFile(path, []byte("stale-token"), 0o644); err != nil {
		t.Fatalf("seed stale token file: %v", err)
	}
	if _, err := WriteControlToken(dir, "fresh-mode-check-token"); err != nil {
		t.Fatalf("WriteControlToken: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token file mode = %o, want 600", perm)
	}
}
