package platform

import (
	"bytes"
	"encoding/base64"
	"io"
	"reflect"
	"strings"
	"testing"
)

const (
	testService = "tokenhush/audit"
	testAccount = "hmac-key"
	// Includes spaces, non-ASCII and a newline: the worst case for leaking
	// through argv and the case the keychain would mangle if not encoded.
	testSecret = "s3cr3t π with\nnewline & $quote"
)

// TestSecuritySetSecretNeverInArgv pins the macOS invocation contract: the
// `security` argv carries only the interactive flag, while the secret is
// delivered on stdin. This test runs on every platform (it asserts command
// construction, not macOS runtime) and MUST fail if the secret ever becomes an
// argv element — which would expose it to `ps`.
func TestSecuritySetSecretNeverInArgv(t *testing.T) {
	t.Parallel()

	argv, stdin, err := securitySetInvocation(testService, testAccount, testSecret)
	if err != nil {
		t.Fatalf("securitySetInvocation() error = %v", err)
	}

	wantArgv := []string{securityBinary, "-i"}
	if !reflect.DeepEqual(argv, wantArgv) {
		t.Fatalf("argv = %q, want %q", argv, wantArgv)
	}

	// No argv element may contain the secret, its base64 form, or any
	// recognisable fragment of it.
	fragments := []string{
		testSecret,
		base64.StdEncoding.EncodeToString([]byte(testSecret)),
		"s3cr3t",
		securityB64Prefix,
	}
	for i, arg := range argv {
		for _, frag := range fragments {
			if strings.Contains(arg, frag) {
				t.Fatalf("argv[%d] = %q leaks secret fragment %q (seen in `ps`)", i, arg, frag)
			}
		}
	}

	// The secret must arrive on the stdin channel instead.
	if !strings.Contains(stdin, base64.StdEncoding.EncodeToString([]byte(testSecret))) {
		t.Fatalf("stdin payload does not carry the encoded secret: %q", stdin)
	}
	if !strings.HasPrefix(stdin, "add-generic-password") {
		t.Fatalf("stdin payload = %q, want an add-generic-password command", stdin)
	}
	if !strings.HasSuffix(stdin, "\n") {
		t.Fatalf("stdin payload = %q, want newline-terminated interactive command", stdin)
	}
}

// TestSecuritySetDeliversSecretOnWriter proves the production path delivers the
// secret through an io.Writer (the child's stdin pipe); a bytes.Buffer stands
// in for that pipe.
func TestSecuritySetDeliversSecretOnWriter(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := securityWriteSetCommand(&buf, testService, testAccount, testSecret); err != nil {
		t.Fatalf("securityWriteSetCommand() error = %v", err)
	}
	if !strings.Contains(buf.String(), base64.StdEncoding.EncodeToString([]byte(testSecret))) {
		t.Fatalf("writer payload = %q does not contain the encoded secret", buf.String())
	}
	var _ io.Writer = &buf // documents the stdin-pipe shape
}

// TestSecurityGetAndDeleteArgvHaveNoSecret confirms reads/deletes never pass a
// value in either.
func TestSecurityGetAndDeleteArgvHaveNoSecret(t *testing.T) {
	t.Parallel()

	for _, argv := range [][]string{
		securityGetArgv(testService, testAccount),
		securityDeleteArgv(testService, testAccount),
	} {
		for i, arg := range argv {
			if strings.Contains(arg, testSecret) {
				t.Fatalf("argv[%d] = %q leaks the secret", i, arg)
			}
		}
	}
	if got, want := securityGetArgv("s", "a"), []string{securityBinary, "find-generic-password", "-s", "s", "-wa", "a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("securityGetArgv() = %q, want %q", got, want)
	}
	if got, want := securityDeleteArgv("s", "a"), []string{securityBinary, "delete-generic-password", "-s", "s", "-a", "a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("securityDeleteArgv() = %q, want %q", got, want)
	}
}

// TestSecuritySetRejectsOversizeCommand covers the documented 4096-byte
// `security -i` line limit (which counts service + account + encoded secret).
func TestSecuritySetRejectsOversizeCommand(t *testing.T) {
	t.Parallel()

	if _, err := securitySetCommand("s", "a", strings.Repeat("x", maxSecurityCommandLen)); err == nil {
		t.Fatalf("securitySetCommand() accepted a value over the %d-byte limit", maxSecurityCommandLen)
	}
	// A small value must still be accepted.
	if _, err := securitySetCommand("s", "a", "ok"); err != nil {
		t.Fatalf("securitySetCommand() rejected a small value: %v", err)
	}
}

// TestSecurityValueRoundTrip proves the encode/decode pair is lossless for the
// non-ASCII / multi-line case the keychain would otherwise corrupt.
func TestSecurityValueRoundTrip(t *testing.T) {
	t.Parallel()

	line, err := securitySetCommand("s", "a", testSecret)
	if err != nil {
		t.Fatalf("securitySetCommand() error = %v", err)
	}
	// Extract the quoted encoded value from the command line.
	const marker = "-w "
	idx := strings.Index(line, marker)
	if idx < 0 {
		t.Fatalf("command %q has no %q argument", line, marker)
	}
	quoted := strings.TrimSuffix(line[idx+len(marker):], "\n")
	quoted = strings.Trim(quoted, "'")
	got, err := securityDecodeValue(quoted)
	if err != nil {
		t.Fatalf("securityDecodeValue() error = %v", err)
	}
	if got != testSecret {
		t.Fatalf("round trip = %q, want %q", got, testSecret)
	}
}
