//go:build !windows

package update

// scheduleRebootReplace is a no-op off Windows; the journal-based Recover path
// completes the swap at the next start.
func scheduleRebootReplace(string, string) bool { return false }
