// Package audit defines the metadata-only audit record seam and the no-op
// defaults that stand in until the SQLite + HMAC hash-chain store is wired
// into the daemon.
//
// Records carry metadata only (provider, path, timestamps, byte counts,
// redaction counts, detector ids), never request or response content.
package audit

import (
	"context"
	"time"
)

// Record is one metadata-only audit row. ID, PrevHash, and Hash are assigned
// by the store; callers writing through an AuditSink leave them zero.
type Record struct {
	ID         int64    `json:"id"`
	TS         int64    `json:"ts"` // unix milliseconds
	Provider   string   `json:"provider"`
	Path       string   `json:"path"`
	Method     string   `json:"method"`
	Status     int      `json:"status,omitempty"`
	ReqBytes   int64    `json:"req_bytes"`
	RespBytes  int64    `json:"resp_bytes"`
	Redactions int      `json:"redactions"`
	Detectors  []string `json:"detectors,omitempty"`
	Client     string   `json:"client,omitempty"`
	PrevHash   []byte   `json:"prev_hash,omitempty"`
	Hash       []byte   `json:"hash,omitempty"`
}

// Query filters the records returned by an AuditQuerier. Zero values mean
// "no constraint"; Limit <= 0 leaves the limit to the implementation.
type Query struct {
	Since    time.Time
	Until    time.Time
	Provider string
	Limit    int
}

// AuditSink appends metadata-only audit records. The daemon injects this
// seam until the real store replaces the no-op default.
type AuditSink interface {
	Record(rec Record) error
}

// AuditQuerier reads audit records for the control API and the audit CLI.
type AuditQuerier interface {
	Query(ctx context.Context, q Query) ([]Record, error)
}
