package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// Loopback addresses. The listener layer binds exactly these two families;
// wildcard addresses are rejected before any bind is attempted (docs/13 §3.4).
const (
	loopbackV4 = "127.0.0.1"
	loopbackV6 = "::1"
)

// wsaEADDRINUSE is Windows' WSAEADDRINUSE (10048). syscall.EADDRINUSE on
// Windows is a synthesized POSIX value that does not compare equal to the real
// winsock error, so both are consulted.
const wsaEADDRINUSE = syscall.Errno(10048)

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
	// ErrListenFailed means a loopback family could not be bound for any
	// reason other than the port being busy (for example no IPv6 stack).
	ErrListenFailed = errors.New("proxy: loopback listen failed")
)

// listenerFunc matches net.Listen. Listen uses net.Listen directly; listenWith
// accepts an injected constructor so tests can prove the dual-stack logic on
// runners without a usable ::1.
type listenerFunc func(network, address string) (net.Listener, error)

// Listeners is the dual-stack loopback pair. Both listeners always share the
// same TCP port, so a client resolving "localhost" to either address family
// reaches the same proxy.
type Listeners struct {
	ipv4 net.Listener
	ipv6 net.Listener
}

// Listen binds 127.0.0.1:port (tcp4) and [::1]:port (tcp6) explicitly. host is
// validated against the loopback allowlist and never used to relax the bind:
// wildcard and empty hosts are rejected here, as defence in depth on top of
// pkg/config validation.
//
// port 0 asks the kernel for an ephemeral port on the v4 listener, which is
// then reused for the v6 listener, so tests never collide with a fixed port.
// If either family cannot be bound, the other listener is closed and a typed
// error is returned; nothing is left listening.
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
	if err != nil {
		_ = v4.Close()
		return nil, bindError(v6Addr, err)
	}

	return &Listeners{ipv4: v4, ipv6: v6}, nil
}

// V4 returns the 127.0.0.1 listener.
func (l *Listeners) V4() net.Listener { return l.ipv4 }

// V6 returns the [::1] listener.
func (l *Listeners) V6() net.Listener { return l.ipv6 }

// Addrs returns the actual bound addresses in IPv4, IPv6 order.
func (l *Listeners) Addrs() []net.Addr {
	return []net.Addr{l.ipv4.Addr(), l.ipv6.Addr()}
}

// Port returns the TCP port both listeners are bound to.
func (l *Listeners) Port() int { return addrPort(l.ipv4.Addr()) }

// Close closes both listeners and reports the joined errors.
func (l *Listeners) Close() error {
	return errors.Join(l.ipv4.Close(), l.ipv6.Close())
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
