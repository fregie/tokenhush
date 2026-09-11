// Package platform OS-specific secret-store primitives.
//
// This file intentionally carries NO build constraint: the macOS invocation
// contract (argv construction + stdin payload) is pure string handling and is
// exercised by unit tests on every platform. Only keyring_darwin.go actually
// executes /usr/bin/security.
package platform

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
)

// The macOS keychain is reached exclusively through the system
// /usr/bin/security tool. Mutations use interactive mode (`security -i`) and
// are written to the child's STDIN, so the secret is never an argv element and
// can never be observed through `ps`/`/proc/<pid>/cmdline`.
const (
	securityBinary = "/usr/bin/security"

	// maxSecurityCommandLen mirrors the historical `security -i` line limit:
	// the entire add-generic-password line (service + account + encoded secret)
	// must fit, not merely the secret.
	maxSecurityCommandLen = 4096

	// securityB64Prefix marks values this package base64-encoded before
	// storing. The keychain hex/base64-encodes multi-line or non-ASCII values
	// on read, so encoding every value up front keeps Get lossless.
	securityB64Prefix = "tokenhush-b64:"
)

// securitySetArgv is the argv used to store a secret. It contains ONLY the
// interactive flag, never the secret; the value travels on stdin.
func securitySetArgv() []string {
	return []string{securityBinary, "-i"}
}

// securitySetCommand builds the single interactive command line (newline
// terminated) that `security -i` interprets to add or update a generic
// password. The returned string contains the secret and MUST only ever be
// written to the child's stdin.
func securitySetCommand(service, account, secret string) (string, error) {
	encoded := securityB64Prefix + base64.StdEncoding.EncodeToString([]byte(secret))
	line := "add-generic-password -U -s " + securityQuote(service) +
		" -a " + securityQuote(account) +
		" -w " + securityQuote(encoded) + "\n"
	if len(line) > maxSecurityCommandLen {
		return "", errSecretTooBig
	}
	return line, nil
}

// securityWriteSetCommand writes the interactive add command (which contains
// the secret) to w. In production w is the child's stdin pipe; tests pass a
// bytes.Buffer to prove the secret travels on the stdin channel.
func securityWriteSetCommand(w io.Writer, service, account, secret string) error {
	line, err := securitySetCommand(service, account, secret)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, line)
	return err
}

// securitySetInvocation exposes the full Set shape as a testable contract:
// argv MUST NOT contain the secret; stdin MUST.
func securitySetInvocation(service, account, secret string) (argv []string, stdin string, err error) {
	line, err := securitySetCommand(service, account, secret)
	if err != nil {
		return nil, "", err
	}
	return securitySetArgv(), line, nil
}

// securityGetArgv returns the argv for a read. The value is returned on
// stdout, so it is never passed in.
func securityGetArgv(service, account string) []string {
	return []string{securityBinary, "find-generic-password", "-s", service, "-wa", account}
}

// securityDeleteArgv returns the argv for a delete. Deletion needs no secret.
func securityDeleteArgv(service, account string) []string {
	return []string{securityBinary, "delete-generic-password", "-s", service, "-a", account}
}

// securityQuote single-quotes s for `security -i`'s POSIX-style tokenizer.
// Values without special characters are returned verbatim.
func securityQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n\r'\"\\$`!;&|<>(){}[]*?~#") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\"'\"'`) + "'"
}

// securityDecodeValue reverses the Set-time base64 encoding. Values without
// the marker (e.g. written by another tool) are returned verbatim.
func securityDecodeValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, securityB64Prefix) {
		return raw, nil
	}
	dec, err := base64.StdEncoding.DecodeString(raw[len(securityB64Prefix):])
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

// securityIndicatesNotFound reports whether security(1) output means "missing".
func securityIndicatesNotFound(out []byte) bool {
	return bytes.Contains(out, []byte("could not be found"))
}
