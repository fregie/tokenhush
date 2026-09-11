package config

import (
	"fmt"
	"math"

	"github.com/goccy/go-yaml"
)

// Port is a TCP port in 1..65535. The custom decoder rejects fractional,
// quoted, null and out-of-range values instead of letting the YAML library
// silently truncate them.
type Port int

func (p *Port) UnmarshalYAML(b []byte) error {
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return &Error{Field: "listen.port", Reason: "must be an integer", Err: ErrInvalidListenPort, Cause: err}
	}
	var n int64
	switch v := raw.(type) {
	case uint64:
		if v > math.MaxInt64 {
			return portError("must be in 1..65535")
		}
		n = int64(v)
	case int64:
		n = v
	default:
		return portError("must be an integer, got " + yamlValueKind(raw))
	}
	if n < 1 || n > 65535 {
		return portError(fmt.Sprintf("must be in 1..65535, got %d", n))
	}
	*p = Port(n)
	return nil
}

func portError(reason string) error {
	return &Error{Field: "listen.port", Reason: reason, Err: ErrInvalidListenPort}
}

func yamlValueKind(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case float64:
		return "a fractional number"
	case bool:
		return "a boolean"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", v)
	}
}
