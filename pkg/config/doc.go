// Package config loads the user configuration (tokenhush.yaml) from the
// platform config directory, applies the opinionated V1 defaults from
// docs/configuration.md, and validates the result: loopback-only listen address, detector
// toggles, log level, and the upstreams override map.
package config
