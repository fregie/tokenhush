//go:build linux

package platform

import (
	"errors"

	"github.com/zalando/go-keyring"
)

type linuxKeyring struct{}

func newKeyringBackend() keyringBackend { return linuxKeyring{} }

func (linuxKeyring) name() string { return "Linux Secret Service (D-Bus, login collection)" }

func (linuxKeyring) get(service, account string) (string, error) {
	value, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrSecretNotFound
	}
	return value, err
}

func (linuxKeyring) set(service, account, secret string) error {
	err := keyring.Set(service, account, secret)
	if errors.Is(err, keyring.ErrSetDataTooBig) {
		return errSecretTooBig
	}
	return err
}

func (linuxKeyring) delete(service, account string) error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrSecretNotFound
	}
	return err
}
