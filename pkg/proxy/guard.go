package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ErrForeignHost is returned when a request's Host is outside the loopback
// allowlist, which is the shape of a DNS-rebinding attempt against the local
// gateway.
var ErrForeignHost = errors.New("proxy: request host is not the loopback gateway")

// ErrCrossOrigin is returned when a request carries an Origin that is not
// same-origin with the loopback gateway.
var ErrCrossOrigin = errors.New("proxy: request origin is not same-origin with the gateway")

// loopbackHostNames is the default Host allowlist. The bound port is checked
// separately, so a page served by this gateway keeps working while a page on
// any other origin does not.
var loopbackHostNames = []string{"127.0.0.1", "localhost", "::1"}

// Allowed is the closed set of request hosts the gateway answers to. The zero
// value uses the loopback defaults and does not check the port.
type Allowed struct {
	Hosts []string
	Port  int
}

// CheckHostOrigin validates the Host and Origin header values of an incoming
// request against allowed. It is pure, so the DNS-rebinding policy is testable
// without a server.
//
// The Host must name a loopback allowlist entry and, when allowed.Port is set,
// must carry exactly that port: a request for 127.0.0.1:8787 is what the
// gateway answers, so a Host that omits the port or names another one is a
// request for a different origin. An empty Origin is fine for non-browser
// clients; a present Origin must be plain http, carry no userinfo, path,
// query or fragment, and match the Host name, port and scheme exactly.
func CheckHostOrigin(host, origin string, allowed Allowed) error {
	name, port, err := parseHostAuthority(host)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrForeignHost, err)
	}
	if !hostAllowed(name, allowed) {
		return fmt.Errorf("%w: %q", ErrForeignHost, host)
	}
	if allowed.Port != 0 && port != allowed.Port {
		return fmt.Errorf("%w: %q does not carry the bound port %d", ErrForeignHost, host, allowed.Port)
	}
	if origin == "" {
		return nil
	}
	return checkOrigin(origin, name, port, allowed)
}

// checkOrigin enforces the same-origin rule against the checked Host.
func checkOrigin(origin, hostName string, hostPort int, allowed Allowed) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("%w: %q is not a URL", ErrCrossOrigin, origin)
	}
	if parsed.Scheme != "http" || parsed.User != nil || parsed.Opaque != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: %q is not a bare http origin", ErrCrossOrigin, origin)
	}
	name, port, err := parseHostAuthority(parsed.Host)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCrossOrigin, err)
	}
	if !hostAllowed(name, allowed) || name != hostName || port != hostPort {
		return fmt.Errorf("%w: %q does not match host %q", ErrCrossOrigin, origin, net.JoinHostPort(hostName, strconv.Itoa(hostPort)))
	}
	return nil
}

// parseHostAuthority splits a Host header value or a URL authority into a
// lowercased host name and a port (0 when absent). Bracketed IPv6 literals
// lose their brackets. Anything with a path, query, fragment, userinfo or
// whitespace in it is malformed and refused.
func parseHostAuthority(value string) (string, int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", 0, errors.New("empty host")
	}
	if strings.ContainsAny(raw, "/?#@ \t") {
		return "", 0, fmt.Errorf("malformed host %q", raw)
	}
	name, portText := raw, ""
	if host, port, err := net.SplitHostPort(raw); err == nil {
		name, portText = host, port
	} else if strings.HasPrefix(raw, "[") {
		if !strings.HasSuffix(raw, "]") || len(raw) < 3 {
			return "", 0, fmt.Errorf("malformed host %q", raw)
		}
		name = raw[1 : len(raw)-1]
	}
	if name == "" {
		return "", 0, errors.New("empty host name")
	}
	port := 0
	if portText != "" {
		parsed, err := strconv.Atoi(portText)
		if err != nil || parsed < 1 || parsed > 65535 {
			return "", 0, fmt.Errorf("invalid port %q", portText)
		}
		port = parsed
	}
	return strings.ToLower(name), port, nil
}

// hostAllowed reports whether name is one of the allowlist entries. Bracket
// decorations are ignored so [::1] and ::1 are the same entry.
func hostAllowed(name string, allowed Allowed) bool {
	hosts := allowed.Hosts
	if len(hosts) == 0 {
		hosts = loopbackHostNames
	}
	for _, candidate := range hosts {
		trimmed := strings.Trim(strings.TrimSpace(candidate), "[]")
		if strings.EqualFold(trimmed, name) {
			return true
		}
	}
	return false
}
