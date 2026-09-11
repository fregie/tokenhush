package config

import (
	"errors"
	"strings"
)

// Sentinel errors. Every failure returned by this package wraps exactly one of
// these, so callers classify failures with errors.Is instead of string
// matching.
var (
	// ErrRead means the configuration file exists but could not be read.
	ErrRead = errors.New("cannot read config file")
	// ErrTooLarge means the configuration file exceeds maxConfigBytes.
	ErrTooLarge = errors.New("config file too large")
	// ErrParse means the document is not valid YAML for the V1 schema:
	// syntax error, duplicate key, or a value of the wrong type.
	ErrParse = errors.New("invalid config")
	// ErrUnknownField means the document contains a key outside the V1
	// schema, including unknown detector keys.
	ErrUnknownField = errors.New("unknown config field")
	// ErrInvalidListenHost means listen.host is not a loopback address.
	ErrInvalidListenHost = errors.New("invalid listen.host")
	// ErrInvalidListenPort means listen.port is not an integer in 1..65535.
	ErrInvalidListenPort = errors.New("invalid listen.port")
	// ErrInvalidUpstream means an upstreams entry is malformed.
	ErrInvalidUpstream = errors.New("invalid upstreams entry")
	// ErrInvalidLogLevel means log.level is not one of debug|info|warn|error.
	ErrInvalidLogLevel = errors.New("invalid log.level")
	// ErrInvalidRetention means audit.retention_days is not positive.
	ErrInvalidRetention = errors.New("invalid audit.retention_days")
)

// Error is the single typed error returned by this package. It carries the
// config file path, the dotted config field (when applicable), a human reason,
// a sentinel target for errors.Is, and the underlying cause (when any).
type Error struct {
	Path   string
	Field  string
	Reason string
	Err    error
	Cause  error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("config")
	if e.Path != "" {
		b.WriteString(" ")
		b.WriteString(e.Path)
	}
	if e.Field != "" {
		b.WriteString(": ")
		b.WriteString(e.Field)
	}
	if e.Reason != "" {
		b.WriteString(": ")
		b.WriteString(e.Reason)
	}
	return b.String()
}

// Unwrap exposes both the sentinel and the underlying cause, so errors.Is and
// errors.As see the whole chain.
func (e *Error) Unwrap() []error {
	if e.Cause == nil {
		return []error{e.Err}
	}
	return []error{e.Err, e.Cause}
}

// firstLine collapses a multi-line YAML parser message (position marker plus
// source excerpt) to its first line for human-facing error text; the full
// message stays reachable through Cause.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
