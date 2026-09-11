// Package proxy implements the local reverse proxy: dual-stack loopback
// listeners, Host allowlist validation, upstream forwarding, and SSE
// passthrough that keeps placeholder restoration safe across chunk
// boundaries.
//
// The dual-stack loopback listener layer lives in listen.go; Host allowlist
// validation, forwarding and SSE land in later work items.
package proxy
