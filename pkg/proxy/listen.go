package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// Loopback addresses. The IPv4 loopback is mandatory; the IPv6 loopback is
// best-effort, so a host with no usable ::1 degrades to v4-only instead of
// refusing to start. Wildcard addresses are rejected before any bind is
// attempted (docs/security.md).
const (
	loopbackV4 = "127.0.0.1"
	loopbackV6 = "::1"
)

// wsaEADDRINUSE is Windows' WSAEADDRINUSE (10048). syscall.EADDRINUSE on
// Windows is a synthesized POSIX value that does not compare equal to the real
// winsock error, so both are consulted.
const wsaEADDRINUSE = syscall.Errno(10048)

// Winsock codes for "the address is not assigned" and "the address family is
// unsupported". As with wsaEADDRINUSE, the synthesized POSIX values do not
// compare equal to the real winsock errnos on Windows, so both are consulted.
const (
	wsaEADDRNOTAVAIL = syscall.Errno(10049)
	wsaEAFNOSUPPORT  = syscall.Errno(10047)
)

// Typed listener errors, all errors.Is-testable. Bind failures additionally
// wrap the underlying net error so callers can inspect the platform cause.
var (
	// ErrInvalidHost means the requested host is not one of the loopback
	// spellings 127.0.0.1, ::1 or localhost. Wildcard and empty hosts land
	// here, before any socket exists.
	ErrInvalidHost = errors.New("proxy: listen host must be loopback (127.0.0.1, ::1 or localhost)")
	// ErrInvalidPort means the requested port is outside 0..65535. Port 0 is
	// legal: it asks the kernel for an ephemeral port (used by tests).
	ErrInvalidPort = errors.New("proxy: listen port must be in 0..65535")
	// ErrAddrInUse means one family's loopback port is already bound. V1 fails
	// fast: the sibling listener is closed and no Listeners is returned.
	ErrAddrInUse = errors.New("proxy: loopback port already in use")
	// ErrListenFailed means a loopback bind failed for any reason other than a
	// busy port or a host with no usable IPv6 loopback (the degrade path). It
	// covers a v4 bind failure and every unexpected v6 bind failure.
	ErrListenFailed = errors.New("proxy: loopback listen failed")
)

// listenerFunc matches net.Listen. Listen uses net.Listen directly; listenWith
// accepts an injected constructor so tests can prove the dual-stack and
// degrade logic on runners without a usable ::1.
type listenerFunc func(network, address string) (net.Listener, error)

// Listeners is the loopback listener pair. Both listeners share the same TCP
// port, so a client resolving "localhost" to either address family reaches the
// same proxy. The IPv6 leg is absent (and v6Err is set) when the host has no
// usable IPv6 loopback; see Degraded.
type Listeners struct {
	ipv4  net.Listener
	ipv6  net.Listener // nil when the host has no usable IPv6 loopback
	v6Err error        // non-nil exactly when ipv6 == nil
}

// Listen binds 127.0.0.1:port (tcp4) and, best-effort, [::1]:port (tcp6). host
// is validated against the loopback allowlist and never used to relax the bind:
// wildcard and empty hosts are rejected here, as defence in depth on top of
// pkg/config validation.
//
// port 0 asks the kernel for an ephemeral port on the v4 listener, which is
// then reused for the v6 listener, so tests never collide with a fixed port.
//
// The IPv4 bind is mandatory: any failure returns a typed error and leaves
// nothing listening. The IPv6 bind is best-effort and degrades to a v4-only
// Listeners ONLY when the host has no usable IPv6 loopback (EADDRNOTAVAIL or
// EAFNOSUPPORT). Every other v6 failure, including EADDRINUSE, still fails
// fast: v4 is closed and a typed error is returned. Observe the degrade via
// Degraded and V6Err.
func Listen(host string, port int) (*Listeners, error) {
	return listenWith(host, port, net.Listen)
}

func listenWith(host string, port int, listen listenerFunc) (*Listeners, error) {
	if !isLoopbackHost(host) {
		return nil, fmt.Errorf("%w: got %q", ErrInvalidHost, host)
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidPort, port)
	}

	v4Addr := net.JoinHostPort(loopbackV4, strconv.Itoa(port))
	v4, err := listen("tcp4", v4Addr)
	if err != nil {
		return nil, bindError(v4Addr, err)
	}

	actualPort := port
	if actualPort == 0 {
		actualPort = addrPort(v4.Addr())
		if actualPort == 0 {
			_ = v4.Close()
			return nil, fmt.Errorf("%w: %s reported no port in %v", ErrListenFailed, v4Addr, v4.Addr())
		}
	}

	v6Addr := net.JoinHostPort(loopbackV6, strconv.Itoa(actualPort))
	v6, err := listen("tcp6", v6Addr)
	switch {
	case err == nil:
		return &Listeners{ipv4: v4, ipv6: v6}, nil
	case isAddrInUse(err):
		_ = v4.Close()
		return nil, bindError(v6Addr, err)
	case isNoIPv6(err):
		// Degrade deliberately: a host with no IPv6 loopback has no client
		// that could reach [::1], so serving IPv4-only is not a weaker
		// posture. Loopback-only binding, Host validation and the per-run
		// control token are the anti-local-attacker mitigations, not the
		// presence of a second address family. The failure is kept for
		// reporting through V6Err instead of being dropped.
		return &Listeners{ipv4: v4, v6Err: err}, nil
	default:
		_ = v4.Close()
		return nil, bindError(v6Addr, err)
	}
}

// V4 returns the 127.0.0.1 listener, which is always non-nil.
func (l *Listeners) V4() net.Listener { return l.ipv4 }

// V6 returns the [::1] listener, or nil when the host has no usable IPv6
// loopback (see Degraded).
func (l *Listeners) V6() net.Listener { return l.ipv6 }

// Degraded reports whether the [::1] leg is absent because the host has no
// usable IPv6 loopback. A degraded listener serves 127.0.0.1 only.
func (l *Listeners) Degraded() bool { return l.ipv6 == nil }

// V6Err returns the [::1] bind failure behind a degraded listener, and nil when
// both families are bound.
func (l *Listeners) V6Err() error { return l.v6Err }

// Addrs returns the bound addresses in IPv4-first order. The IPv6 entry is
// omitted when degraded, so the slice holds one or two addresses and is never
// nil.
func (l *Listeners) Addrs() []net.Addr {
	addrs := make([]net.Addr, 0, 2)
	addrs = append(addrs, l.ipv4.Addr())
	if l.ipv6 != nil {
		addrs = append(addrs, l.ipv6.Addr())
	}
	return addrs
}

// Port returns the TCP port the IPv4 listener is bound to.
func (l *Listeners) Port() int { return addrPort(l.ipv4.Addr()) }

// Close closes whichever listeners exist and reports the joined errors. It is
// nil-safe for the absent IPv6 leg.
func (l *Listeners) Close() error {
	var err error
	if l.ipv4 != nil {
		err = l.ipv4.Close()
	}
	if l.ipv6 != nil {
		err = errors.Join(err, l.ipv6.Close())
	}
	return err
}

// bindError classifies a failed bind: a busy port becomes ErrAddrInUse,
// anything else ErrListenFailed. Both wrap the original error.
func bindError(addr string, err error) error {
	if isAddrInUse(err) {
		return fmt.Errorf("%w: %s: %w", ErrAddrInUse, addr, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrListenFailed, addr, err)
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, wsaEADDRINUSE)
}

// isNoIPv6 reports the two errnos that mean "this host has no usable IPv6
// loopback": the address is not assigned (cannot assign requested address) or
// the address family is unsupported. Both the POSIX and winsock values are
// consulted, mirroring isAddrInUse.
func isNoIPv6(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, wsaEADDRNOTAVAIL) ||
		errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, wsaEAFNOSUPPORT)
}

// isLoopbackHost mirrors pkg/config's allowlist for defence in depth: a config
// that somehow reaches Listen with a wildcard host still cannot bind it.
func isLoopbackHost(host string) bool {
	switch host {
	case loopbackV4, loopbackV6:
		return true
	default:
		return strings.EqualFold(host, "localhost")
	}
}

// addrPort extracts the TCP port from a listener address; 0 means unknown.
func addrPort(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}
