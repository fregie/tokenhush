package proxy

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// requireLoopbackAddr fails the test when addr does not name a loopback
// endpoint, and returns its host and port components otherwise.
func requireLoopbackAddr(t *testing.T, addr string) (host, port string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			t.Fatalf("bound address %q escaped loopback", addr)
		}
		return host, port
	}
	if !strings.EqualFold(host, "localhost") {
		t.Fatalf("bound address %q is neither a loopback IP nor localhost", addr)
	}
	return host, port
}

func TestListenBindsLoopbackIPv4(t *testing.T) {
	ln, addr, err := Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Listen(127.0.0.1, 0): %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	if addr != ln.Addr().String() {
		t.Errorf("returned address %q, want the bound address %q", addr, ln.Addr())
	}
	requireLoopbackAddr(t, addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial bound address %q: %v", addr, err)
	}
	if remote, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || !remote.IP.IsLoopback() {
		t.Errorf("connection remote address %v is not loopback", conn.RemoteAddr())
	}
	if err := conn.Close(); err != nil {
		t.Errorf("close dialed connection: %v", err)
	}
}

func TestListenPinsLocalhostWithoutLookup(t *testing.T) {
	ln, addr, err := Listen("localhost", 0)
	if err != nil {
		t.Fatalf("Listen(localhost, 0): %v", err)
	}
	defer func() { _ = ln.Close() }()

	host, _ := requireLoopbackAddr(t, addr)
	if host != "127.0.0.1" {
		t.Errorf("localhost bound to %q, want the pinned 127.0.0.1", host)
	}
}

func TestListenAcceptsEmptyHost(t *testing.T) {
	ln, addr, err := Listen("", 0)
	if err != nil {
		t.Fatalf("Listen(\"\", 0): %v", err)
	}
	defer func() { _ = ln.Close() }()
	if host, _ := requireLoopbackAddr(t, addr); host != "127.0.0.1" {
		t.Errorf("empty host bound to %q, want 127.0.0.1", host)
	}
}

func TestListenIPv6LoopbackOrSingleStackFallback(t *testing.T) {
	notice := &bytes.Buffer{}
	previous := NoticeWriter
	NoticeWriter = notice
	defer func() { NoticeWriter = previous }()

	for _, host := range []string{"[::1]", "::1"} {
		t.Run(host, func(t *testing.T) {
			ln, addr, err := Listen(host, 0)
			if err != nil {
				t.Skipf("host has no usable IPv6 loopback: %v", err)
			}
			defer func() { _ = ln.Close() }()
			requireLoopbackAddr(t, addr)

			if strings.Contains(notice.String(), "falling back") {
				if !strings.HasPrefix(addr, "127.0.0.1:") {
					t.Errorf("fallback notice issued but bound %q", addr)
				}
				return
			}
			if !strings.HasPrefix(addr, "[::1]:") {
				t.Errorf("bound %q, want the IPv6 loopback or a 127.0.0.1 fallback", addr)
			}
		})
	}
}

func TestListenNeverEscapesLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", ""} {
		ln, addr, err := Listen(host, 0)
		if err != nil {
			t.Fatalf("Listen(%q, 0): %v", host, err)
		}
		requireLoopbackAddr(t, addr)
		if !isLoopbackListenAddr(ln.Addr()) {
			t.Errorf("listener address %v is not loopback", ln.Addr())
		}
		if err := ln.Close(); err != nil {
			t.Errorf("Close(%q): %v", host, err)
		}
	}
}

func TestListenRefusesNonLoopbackHosts(t *testing.T) {
	hosts := []string{
		"0.0.0.0",
		"::",
		"192.168.1.10",
		"10.0.0.1",
		"172.16.0.9",
		"example.com",
		"evil.example",
		"localhost.example.com",
		"127.0.0.1.nip.io",
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			ln, addr, err := Listen(host, 0)
			if ln != nil {
				_ = ln.Close()
				t.Errorf("Listen(%q, 0) created a listener", host)
			}
			if addr != "" {
				t.Errorf("Listen(%q, 0) returned address %q, want none", host, addr)
			}
			if !errors.Is(err, ErrNonLoopbackBind) {
				t.Errorf("Listen(%q, 0) error = %v, want ErrNonLoopbackBind", host, err)
			}
		})
	}
}

func TestListenRejectsInvalidPort(t *testing.T) {
	for _, port := range []int{-1, 65536, 1 << 20} {
		ln, _, err := Listen("127.0.0.1", port)
		if ln != nil {
			_ = ln.Close()
			t.Errorf("Listen(127.0.0.1, %d) created a listener", port)
		}
		if err == nil {
			t.Errorf("Listen(127.0.0.1, %d) succeeded, want an error", port)
		}
	}
}

func TestListenAddrInUseIsTyped(t *testing.T) {
	first, addr, err := Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer func() { _ = first.Close() }()

	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portText, err)
	}

	second, secondAddr, err := Listen("127.0.0.1", port)
	if second != nil {
		_ = second.Close()
		t.Errorf("second Listen on in-use port %d created a listener", port)
	}
	if secondAddr != "" {
		t.Errorf("second Listen returned address %q, want none", secondAddr)
	}
	if !errors.Is(err, ErrAddrInUse) {
		t.Errorf("second Listen error = %v, want ErrAddrInUse", err)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("second Listen error = %v, want it to wrap syscall.EADDRINUSE", err)
	}
}

func TestListenCloseIsIdempotent(t *testing.T) {
	ln, addr, err := Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Errorf("second Close: %v, want nil", err)
	}
	conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Errorf("address %q still accepts connections after Close", addr)
	}
}
