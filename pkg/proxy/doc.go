// Package proxy implements the local reverse proxy: dual-stack loopback
// listeners, Host allowlist validation, upstream forwarding, and SSE
// passthrough that keeps placeholder restoration safe across chunk
// boundaries.
//
// Only the package contract is fixed here; behavior lands in later work items.
package proxy
