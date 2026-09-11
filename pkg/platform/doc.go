// Package platform isolates every OS-specific concern: config and data paths,
// the secret-store fallback chain, and the service-lifecycle stub. It is
// exported because the closed-source build imports it; nothing else in the
// core should branch on runtime.GOOS.
package platform
