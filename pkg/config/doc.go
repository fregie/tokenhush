// Package config loads the user configuration (tokenhush.yaml) from the
// platform config directory, applies the opinionated V1 defaults from
// docs/configuration.md, and validates the result: loopback-only listen address, detector
// toggles, log level, the upstreams override map, allowlist entries, and the
// self_protection modes. The static allowlist is a seed for, never replaced
// by, the runtime allowlist store: the effective set is their union.
package config
