package config

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// Upstreams maps a request host or path prefix to the base URL requests should
// be forwarded to. It is the config-side override consumed by the W3.8
// resolver for custom / OpenAI-compatible endpoints.
type Upstreams map[string]string

// UnmarshalYAML parses and validates the whole `upstreams:` block, so shape
// errors surface as ErrInvalidUpstream instead of a bare decode failure.
func (u *Upstreams) UnmarshalYAML(b []byte) error {
	var raw map[string]string
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return &Error{
			Field:  "upstreams",
			Reason: "must be a mapping of host/path to base URL: " + firstLine(err.Error()),
			Err:    ErrInvalidUpstream,
			Cause:  err,
		}
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic first-error reporting
	for _, k := range keys {
		if err := validateUpstream(k, raw[k]); err != nil {
			return err
		}
	}
	if len(raw) == 0 {
		*u = nil // explicit `{}` means "no overrides", same as omitting the block
		return nil
	}
	*u = raw
	return nil
}

func validateUpstream(key, base string) error {
	switch {
	case strings.TrimSpace(key) == "":
		return upstreamError("", "key must not be empty")
	case strings.TrimSpace(key) != key || strings.ContainsAny(key, " \t\r\n"):
		return upstreamError("", fmt.Sprintf("key %q must not contain whitespace", key))
	case strings.Contains(key, "://"):
		return upstreamError(key, "key must be a host or path, not a URL")
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return upstreamError(key, "base URL is not parseable: "+firstLine(err.Error()))
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return upstreamError(key, "base URL scheme must be http or https")
	}
	if parsed.Host == "" {
		return upstreamError(key, "base URL must include a host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return upstreamError(key, "base URL must not contain a query or fragment")
	}
	return nil
}

func upstreamError(key, reason string) error {
	field := "upstreams"
	if key != "" {
		field += "." + key
	}
	return &Error{Field: field, Reason: reason, Err: ErrInvalidUpstream}
}
