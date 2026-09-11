//go:build linux

package platform

import (
	"strings"
	"testing"
)

// TestSystemdCredsArgvCarriesNoSecret pins the argv-safety contract of the
// systemd-creds layer: the secret travels on stdin (encrypt) or stdout
// (decrypt), never as a process argument.
func TestSystemdCredsArgvCarriesNoSecret(t *testing.T) {
	t.Parallel()

	for _, argv := range [][]string{
		systemdCredsEncryptArgv("tokenhush_abc123"),
		systemdCredsDecryptArgv("tokenhush_abc123", "/tmp/tokenhush-test.cred"),
	} {
		for i, arg := range argv {
			for _, fragment := range []string{testSecret, "s3cr3t", "newline"} {
				if strings.Contains(arg, fragment) {
					t.Fatalf("argv[%d] = %q leaks secret fragment %q", i, arg, fragment)
				}
			}
		}
	}

	argv := systemdCredsEncryptArgv("tokenhush_abc123")
	if argv[len(argv)-2] != "-" || argv[len(argv)-1] != "-" {
		t.Fatalf("encrypt argv = %q, want stdin/stdout '-' operands so the secret never enters argv", argv)
	}
}

// TestSystemdCredsUnavailableWhenBinaryMissing proves the layer reports itself
// unavailable (so the selector moves on) when the binary is absent.
func TestSystemdCredsUnavailableWhenBinaryMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	backend, ok := newSystemdCredsStore(t.TempDir())
	if ok || backend != nil {
		t.Fatalf("newSystemdCredsStore() = (%v, %v), want (nil, false)", backend, ok)
	}
}
