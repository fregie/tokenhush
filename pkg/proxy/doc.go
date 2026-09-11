// Package proxy implements the local reverse proxy: dual-stack loopback
// listeners, Host allowlist and control-plane guards, upstream forwarding, and
// SSE passthrough that keeps placeholder restoration safe across chunk
// boundaries.
//
// The dual-stack loopback listener layer lives in listen.go; the Host
// allowlist, control-API bearer auth and Origin policy live in guard.go; the
// per-session control token and browser handshake URL live in token.go; the
// upstream forwarder and its redaction seam live in forward.go. The SSE
// sliding-window parser lands in a later work item.
package proxy
