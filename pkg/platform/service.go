package platform

import (
	"errors"
	"fmt"
)

// ErrNotImplemented reports a capability that is documented as deferred past
// V1, so callers can distinguish deliberate deferral from a failure. Classify
// it with errors.Is; the wrapping message names the capability and points at
// the roadmap.
var ErrNotImplemented = errors.New("not implemented in V1; see roadmap")

// InstallService is the V1 stub for `tokenhush service install`.
//
// Background service installation — a launchd agent on macOS, a systemd user
// unit on Linux, a Service Control Manager entry on Windows — is deliberately
// out of scope for V1 (docs/deployment.md §4). A per-user, loopback-only proxy does not
// need it, and each platform's installer is a self-contained time sink that
// would also drag in admin rights on Windows. V1 ships the foreground
// `tokenhush run` process only.
//
// This stub never touches the host. It always returns an error wrapping
// ErrNotImplemented so the CLI can surface roadmap guidance.
func InstallService() error {
	// Deliberately no launchd/systemd/SCM code path, not even behind build
	// tags: a dead branch would still be platform service code to maintain.
	return fmt.Errorf("platform: service install: %w", ErrNotImplemented)
}

// UninstallService is the V1 stub for `tokenhush service uninstall`.
//
// Because InstallService never installs anything (docs/deployment.md §4), there is
// nothing to remove; the stub exists so the command surface is stable and
// fails honestly instead of pretending a service might exist. It never
// touches the host and always returns an error wrapping ErrNotImplemented.
func UninstallService() error {
	return fmt.Errorf("platform: service uninstall: %w", ErrNotImplemented)
}
