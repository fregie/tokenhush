//go:build !linux

package platform

// newSystemdCredsStore is the non-Linux stub: systemd-creds exists only on
// Linux and is never part of the fallback chain elsewhere.
func newSystemdCredsStore(string) (storeBackend, bool) { return nil, false }
