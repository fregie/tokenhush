// Package proxy implements the loopback-only local HTTP gateway together
// with its host, origin, and control-token guards.
package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// ErrNonLoopbackBind is returned when a caller asks to bind an address that
// is not a loopback IP literal. No listener is created when it is returned.
var ErrNonLoopbackBind = errors.New("proxy: refusing to bind a non-loopback address")

// ErrAddrInUse is returned when the requested address is already bound by
// another process. It wraps the underlying syscall.EADDRINUSE.
var ErrAddrInUse = errors.New("proxy: address already in use")

// NoticeWriter receives non-fatal notices such as the IPv6 fallback. It
// defaults to os.Stderr and may be swapped out in tests.
var NoticeWriter io.Writer = os.Stderr

// Listen binds a loopback-only TCP listener on host:port.
//
// host must be a loopback IP literal or the exact loopback name
// "localhost": "127.0.0.1" always binds, "localhost" is pinned to
// 127.0.0.1 without a name lookup, and "[::1]" (or "::1") first tries the
// IPv6 loopback and falls back to 127.0.0.1 when the host has no IPv6
// stack, writing a notice to NoticeWriter. Every other hostname,
// "0.0.0.0", "::", and LAN IPs are refused with ErrNonLoopbackBind and no
// listener is created.
//
// The returned string is the actual bound address; with port 0 it is the
// ephemeral port chosen by the kernel.
func Listen(host string, port int) (net.Listener, string, error) {
	if port < 0 || port > 65535 {
		return nil, "", fmt.Errorf("proxy: invalid port %d", port)
	}
	ip, err := loopbackBindIP(host)
	if err != nil {
		return nil, "", err
	}
	if ip.Equal(net.IPv6loopback) {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			return &loopbackListener{Listener: ln}, ln.Addr().String(), nil
		}
		if !ipv6Unavailable(err) {
			return nil, "", wrapListenError(err)
		}
		fmt.Fprintf(NoticeWriter, "proxy: IPv6 loopback unavailable (%v); falling back to 127.0.0.1\n", err)
		ip = net.IPv4(127, 0, 0, 1)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		return nil, "", wrapListenError(err)
	}
	if !isLoopbackListenAddr(ln.Addr()) {
		_ = ln.Close()
		return nil, "", fmt.Errorf("%w: %s", ErrNonLoopbackBind, ln.Addr())
	}
	return &loopbackListener{Listener: ln}, ln.Addr().String(), nil
}

// loopbackBindIP validates host as a loopback IP literal. An empty host
// defaults to 127.0.0.1 and "localhost" is pinned to 127.0.0.1 without
// resolving it. Any other hostname is refused outright: a name lookup
// could leave the trust boundary of the machine's loopback interface.
func loopbackBindIP(host string) (net.IP, error) {
	h := strings.TrimSpace(host)
	if h == "" || strings.EqualFold(h, "localhost") {
		return net.IPv4(127, 0, 0, 1), nil
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	ip := net.ParseIP(h)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %q", ErrNonLoopbackBind, host)
	}
	return ip, nil
}

// ipv6Unavailable reports whether err means the platform has no IPv6
// loopback rather than a real bind conflict such as EADDRINUSE.
func ipv6Unavailable(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.EPROTONOSUPPORT)
}

// wrapListenError adds ErrAddrInUse to address-in-use failures while
// keeping the original error (and syscall.EADDRINUSE) in the chain.
func wrapListenError(err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("%w: %w", ErrAddrInUse, err)
	}
	return err
}

// isLoopbackListenAddr reports whether a listener ended up on loopback.
func isLoopbackListenAddr(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// loopbackListener makes Close idempotent so callers can shut the gateway
// down more than once without an error.
type loopbackListener struct {
	net.Listener
	once sync.Once
	err  error
}

// Close stops the listener. Repeated calls return the first result.
func (l *loopbackListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}
