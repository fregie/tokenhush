package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// seamEphemeralPort is the port the injected v4 listener pretends the kernel
// assigned when the caller asked for port 0.
const seamEphemeralPort = 45001

// bindCall records one listener-constructor invocation.
type bindCall struct {
	network string
	address string
}

// fakeListener is an inert net.Listener backed by an explicit address. The
// injected seam uses it to prove dual-stack wiring without a usable ::1.
type fakeListener struct {
	addr   net.Addr
	closed bool
}

func (f *fakeListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }

func (f *fakeListener) Close() error {
	if f.closed {
		return net.ErrClosed
	}
	f.closed = true
	return nil
}

func (f *fakeListener) Addr() net.Addr { return f.addr }

// recordingSeam records every bind and serves loopback-addressed fakes. A
// port-0 request is answered with seamEphemeralPort so the test can prove the
// v6 leg reuses the port the v4 leg actually got.
func recordingSeam(t *testing.T, calls *[]bindCall) listenerFunc {
	t.Helper()
	return func(network, address string) (net.Listener, error) {
		*calls = append(*calls, bindCall{network: network, address: address})
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatalf("seam received malformed address %q: %v", address, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			t.Fatalf("seam received non-numeric port %q: %v", portText, err)
		}
		if port == 0 {
			port = seamEphemeralPort
		}
		switch network {
		case "tcp4":
			if host != loopbackV4 {
				t.Fatalf("tcp4 bind host = %q, want %q", host, loopbackV4)
			}
			return &fakeListener{addr: &net.TCPAddr{IP: net.ParseIP(loopbackV4), Port: port}}, nil
		case "tcp6":
			if host != loopbackV6 {
				t.Fatalf("tcp6 bind host = %q, want %q", host, loopbackV6)
			}
			return &fakeListener{addr: &net.TCPAddr{IP: net.ParseIP(loopbackV6), Port: port}}, nil
		default:
			t.Fatalf("unexpected network %q", network)
			return nil, nil
		}
	}
}

// TestListenDualStack is the docs/13 §10.3 case-1 acceptance test. The
// injected-seam subtest proves both families are attempted with the same port
// on any runner; the real-loopback subtest dials both families for real and
// skips only when the runner genuinely lacks a usable ::1.
func TestListenDualStack(t *testing.T) {
	t.Run("injected_seam_binds_both_families", func(t *testing.T) {
		var calls []bindCall
		ls, err := listenWith("127.0.0.1", 0, recordingSeam(t, &calls))
		if err != nil {
			t.Fatalf("listenWith: %v", err)
		}
		t.Cleanup(func() { _ = ls.Close() })

		want := []bindCall{
			{network: "tcp4", address: "127.0.0.1:0"},
			{network: "tcp6", address: "[::1]:" + strconv.Itoa(seamEphemeralPort)},
		}
		if len(calls) != len(want) {
			t.Fatalf("listen calls = %+v, want exactly %d calls (no wildcard attempt)", calls, len(want))
		}
		for i := range want {
			if calls[i] != want[i] {
				t.Errorf("listen call %d = %+v, want %+v", i, calls[i], want[i])
			}
		}
		for _, c := range calls {
			host, _, err := net.SplitHostPort(c.address)
			if err != nil {
				t.Fatalf("bind address %q is malformed: %v", c.address, err)
			}
			if host != loopbackV4 && host != loopbackV6 {
				t.Fatalf("non-loopback host bound: %q", c.address)
			}
		}

		if got := ls.Port(); got != seamEphemeralPort {
			t.Errorf("Port() = %d, want %d", got, seamEphemeralPort)
		}
		addrs := ls.Addrs()
		if len(addrs) != 2 {
			t.Fatalf("Addrs() = %v, want 2 addresses", addrs)
		}
		if got, want := addrs[0].String(), "127.0.0.1:"+strconv.Itoa(seamEphemeralPort); got != want {
			t.Errorf("Addrs()[0] = %q, want %q", got, want)
		}
		if got, want := addrs[1].String(), "[::1]:"+strconv.Itoa(seamEphemeralPort); got != want {
			t.Errorf("Addrs()[1] = %q, want %q", got, want)
		}

		if err := ls.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if f4, ok := ls.V4().(*fakeListener); !ok || !f4.closed {
			t.Fatalf("V4 listener not closed: %#v", ls.V4())
		}
		if f6, ok := ls.V6().(*fakeListener); !ok || !f6.closed {
			t.Fatalf("V6 listener not closed: %#v", ls.V6())
		}
	})

	t.Run("real_loopback_accepts_both_families", func(t *testing.T) {
		probe, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("runner has no usable IPv6 loopback: %v", err)
		}
		_ = probe.Close()

		ls, err := Listen("127.0.0.1", 0)
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		t.Cleanup(func() { _ = ls.Close() })

		port := ls.Port()
		if port <= 0 {
			t.Fatalf("Port() = %d, want a positive ephemeral port", port)
		}
		addrs := ls.Addrs()
		if len(addrs) != 2 {
			t.Fatalf("Addrs() = %v, want 2 addresses", addrs)
		}
		suffix := ":" + strconv.Itoa(port)
		if got := addrs[0].String(); got != "127.0.0.1"+suffix {
			t.Errorf("Addrs()[0] = %q, want %q", got, "127.0.0.1"+suffix)
		}
		if got := addrs[1].String(); got != "[::1]"+suffix {
			t.Errorf("Addrs()[1] = %q, want %q", got, "[::1]"+suffix)
		}

		for _, tc := range []struct {
			name    string
			network string
			ln      net.Listener
		}{
			{name: "ipv4", network: "tcp4", ln: ls.V4()},
			{name: "ipv6", network: "tcp6", ln: ls.V6()},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tcpLn, ok := tc.ln.(*net.TCPListener)
				if !ok {
					t.Fatalf("listener is %T, want *net.TCPListener", tc.ln)
				}
				if err := tcpLn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatalf("SetDeadline: %v", err)
				}
				accepted := make(chan net.Conn, 1)
				go func() {
					conn, _ := tcpLn.Accept()
					accepted <- conn
				}()
				conn, err := net.DialTimeout(tc.network, tc.ln.Addr().String(), 5*time.Second)
				if err != nil {
					t.Fatalf("dial %s %s: %v", tc.network, tc.ln.Addr(), err)
				}
				_ = conn.Close()
				select {
				case got := <-accepted:
					if got == nil {
						t.Fatalf("Accept on %s returned nil conn", tc.network)
					}
					_ = got.Close()
				case <-time.After(5 * time.Second):
					t.Fatalf("no connection accepted on %s", tc.network)
				}
			})
		}

		// Cleanup receipt: Close must release both ports so a later bind on
		// the same port succeeds (no leaked listeners).
		if err := ls.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		rebound, err := net.Listen("tcp4", "127.0.0.1"+suffix)
		if err != nil {
			t.Fatalf("port %d not released after Close: %v", port, err)
		}
		_ = rebound.Close()
	})
}

// TestListenAcceptsLoopbackSpellings locks the host allowlist to the same
// three spellings pkg/config validates (docs/13 §3.4).
func TestListenAcceptsLoopbackSpellings(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "LocalHost", "LOCALHOST"} {
		t.Run(host, func(t *testing.T) {
			var calls []bindCall
			ls, err := listenWith(host, 0, recordingSeam(t, &calls))
			if err != nil {
				t.Fatalf("listenWith(%q): %v", host, err)
			}
			if len(calls) != 2 {
				t.Fatalf("listen calls = %+v, want 2", calls)
			}
			if err := ls.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

// TestListenRejectsWildcard proves the listener layer itself (not config
// validation) refuses wildcard, empty and out-of-loopback hosts, and never
// reaches the bind seam for them.
func TestListenRejectsWildcard(t *testing.T) {
	for _, host := range []string{
		"",
		" ",
		"0.0.0.0",
		"::",
		"[::]",
		"0:0:0:0:0:0:0:0",
		"*",
		"192.168.1.10",
		"example.com",
		"localhost:8787",
		"[::1]",
		"127.0.0.1 ",
	} {
		t.Run(fmt.Sprintf("host=%q", host), func(t *testing.T) {
			called := false
			ls, err := listenWith(host, 0, func(network, address string) (net.Listener, error) {
				called = true
				return nil, errors.New("bind seam must not run for a rejected host")
			})
			if !errors.Is(err, ErrInvalidHost) {
				t.Fatalf("listenWith(%q) error = %v, want ErrInvalidHost", host, err)
			}
			t.Logf("rejected %q -> %v", host, err)
			if ls != nil {
				t.Fatalf("listenWith(%q) returned non-nil Listeners", host)
			}
			if called {
				t.Fatalf("bind seam ran for rejected host %q", host)
			}
		})
	}
}

// TestListenRejectsBadPort covers negative and out-of-range ports; port 0
// stays legal as the ephemeral test port.
func TestListenRejectsBadPort(t *testing.T) {
	for _, port := range []int{-1, -8787, 65536, 1 << 20} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			called := false
			ls, err := listenWith("127.0.0.1", port, func(network, address string) (net.Listener, error) {
				called = true
				return nil, errors.New("bind seam must not run for a rejected port")
			})
			if !errors.Is(err, ErrInvalidPort) {
				t.Fatalf("listenWith(port=%d) error = %v, want ErrInvalidPort", port, err)
			}
			t.Logf("rejected port %d -> %v", port, err)
			if ls != nil {
				t.Fatalf("listenWith(port=%d) returned non-nil Listeners", port)
			}
			if called {
				t.Fatalf("bind seam ran for rejected port %d", port)
			}
		})
	}
}

// TestListenPortCollision locks the V1 fail-fast collision policy: the second
// family never silently replaces a busy port, and a failed second bind closes
// the first listener instead of leaking it.
func TestListenPortCollision(t *testing.T) {
	t.Run("ipv4_real_port_in_use", func(t *testing.T) {
		occupied, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("occupy port: %v", err)
		}
		t.Cleanup(func() { _ = occupied.Close() })
		port := occupied.Addr().(*net.TCPAddr).Port

		ls, err := Listen("127.0.0.1", port)
		if ls != nil {
			t.Fatalf("Listen on occupied port %d returned listeners", port)
		}
		if !errors.Is(err, ErrAddrInUse) {
			t.Fatalf("Listen on occupied port %d error = %v, want ErrAddrInUse", port, err)
		}
	})

	t.Run("ipv6_addr_in_use_closes_ipv4", func(t *testing.T) {
		v4 := &fakeListener{addr: &net.TCPAddr{IP: net.ParseIP(loopbackV4), Port: 41234}}
		var calls []bindCall
		ls, err := listenWith("localhost", 41234, func(network, address string) (net.Listener, error) {
			calls = append(calls, bindCall{network: network, address: address})
			if network == "tcp4" {
				return v4, nil
			}
			return nil, &net.OpError{Op: "listen", Net: "tcp6", Err: syscall.EADDRINUSE}
		})
		if ls != nil {
			t.Fatalf("listenWith returned listeners despite v6 collision")
		}
		if !errors.Is(err, ErrAddrInUse) {
			t.Fatalf("error = %v, want ErrAddrInUse", err)
		}
		if len(calls) != 2 {
			t.Fatalf("listen calls = %+v, want both families attempted", calls)
		}
		if !v4.closed {
			t.Fatalf("v4 listener leaked after v6 bind failure")
		}
	})

	t.Run("ipv6_generic_failure_closes_ipv4", func(t *testing.T) {
		v4 := &fakeListener{addr: &net.TCPAddr{IP: net.ParseIP(loopbackV4), Port: 41235}}
		ls, err := listenWith("localhost", 41235, func(network, address string) (net.Listener, error) {
			if network == "tcp4" {
				return v4, nil
			}
			return nil, errors.New("ipv6 stack unavailable")
		})
		if ls != nil {
			t.Fatalf("listenWith returned listeners despite v6 failure")
		}
		if !errors.Is(err, ErrListenFailed) {
			t.Fatalf("error = %v, want ErrListenFailed", err)
		}
		if !v4.closed {
			t.Fatalf("v4 listener leaked after v6 bind failure")
		}
	})
}
