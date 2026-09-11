//go:build !darwin && !windows && !linux

package platform

import "errors"

// errKeyringUnsupported is returned on platforms without a native secret
// store; W2.2's fallback chain turns it into the next layer.
var errKeyringUnsupported = errors.New("no native OS keyring backend on this platform")

type unsupportedKeyring struct{}

func newKeyringBackend() keyringBackend { return unsupportedKeyring{} }

func (unsupportedKeyring) name() string { return "unsupported" }

func (unsupportedKeyring) get(_, _ string) (string, error) { return "", errKeyringUnsupported }

func (unsupportedKeyring) set(_, _, _ string) error { return errKeyringUnsupported }

func (unsupportedKeyring) delete(_, _ string) error { return errKeyringUnsupported }
