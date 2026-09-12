package platform

import "errors"

// ErrSecretNotFound is the W2.0 low-level name, kept as an alias of ErrNotFound
// (docs/security.md) so existing keyring code and errors.Is(err, ErrNotFound)
// callers share a single sentinel.
var ErrSecretNotFound = ErrNotFound

// errSecretTooBig is returned when the value (plus service/account metadata)
// exceeds a native backend's hard limit: the macOS `security -i` line is
// capped at 4096 bytes and the Windows credential blob at 2560 bytes.
var errSecretTooBig = errors.New("secret exceeds OS keyring size limit")

// keyringBackend is the low-level, single-target primitive that talks to one
// native secret store. W2.2 wraps it with the fallback chain (systemd-creds,
// encrypted file, plaintext) to build the exported SecretStore interface.
type keyringBackend interface {
	get(service, account string) (string, error)
	set(service, account, secret string) error
	delete(service, account string) error
	name() string
}
