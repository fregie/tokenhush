//go:build darwin

package platform

import (
	"fmt"
	"os/exec"
)

type darwinKeyring struct{}

func newKeyringBackend() keyringBackend { return darwinKeyring{} }

func (darwinKeyring) name() string { return "macOS Keychain (security(1), stdin)" }

func (darwinKeyring) get(service, account string) (string, error) {
	argv := securityGetArgv(service, account)
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		if securityIndicatesNotFound(out) {
			return "", ErrSecretNotFound
		}
		return "", fmt.Errorf("security find-generic-password: %w", err)
	}
	return securityDecodeValue(string(out))
}

func (darwinKeyring) set(service, account, secret string) error {
	argv := securitySetArgv()
	cmd := exec.Command(argv[0], argv[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := securityWriteSetCommand(stdin, service, account, secret); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("security add-generic-password: %w", err)
	}
	return nil
}

func (darwinKeyring) delete(service, account string) error {
	argv := securityDeleteArgv(service, account)
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if securityIndicatesNotFound(out) {
		return ErrSecretNotFound
	}
	if err != nil {
		return fmt.Errorf("security delete-generic-password: %w", err)
	}
	return nil
}
