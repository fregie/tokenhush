// Package redact implements deterministic secret and PII detection, the
// placeholder mapping, and the client-bound-only restore path.
//
// Hard invariant: placeholders are restored only toward the client, never
// toward the upstream.
package redact
