//go:build windows

package platform

import (
	"errors"

	"github.com/zalando/go-keyring"
)

type windowsKeyring struct{}

func newKeyringBackend() keyringBackend { return windowsKeyring{} }

func (windowsKeyring) name() string { return "Windows Credential Manager (wincred)" }

func (windowsKeyring) get(service, account string) (string, error) {
	value, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrSecretNotFound
	}
	return value, err
}

func (windowsKeyring) set(service, account, secret string) error {
	err := keyring.Set(service, account, secret)
	if errors.Is(err, keyring.ErrSetDataTooBig) {
		return errSecretTooBig
	}
	return err
}

func (windowsKeyring) delete(service, account string) error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrSecretNotFound
	}
	return err
}
