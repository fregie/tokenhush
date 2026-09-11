package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestBindLoopbackOnly is the W5.4 named invariant (docs/13 §3.4,
// docs/security.md §2.4): the listener layer binds exactly the two loopback
// families (127.0.0.1 + ::1) and rejects every wildcard, off-host or malformed
// spelling before any socket exists. It uses the same injected bind seam as
// TestListenDualStack, so it proves the invariant on runners without a usable
// ::1 and never touches the real default port.
func TestBindLoopbackOnly(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "LocalHost", "LOCALHOST"} {
		t.Run("allowed_"+strconv.Quote(host), func(t *testing.T) {
			var calls []bindCall
			ls, err := listenWith(host, 0, recordingSeam(t, &calls))
			if err != nil {
				t.Fatalf("listenWith(%q): %v", host, err)
			}
			t.Cleanup(func() { _ = ls.Close() })

			if len(calls) != 2 {
				t.Fatalf("bind calls = %+v, want exactly 2 loopback families", calls)
			}
			for _, c := range calls {
				bindHost, _, err := net.SplitHostPort(c.address)
				if err != nil {
					t.Fatalf("bind address %q is malformed: %v", c.address, err)
				}
				if bindHost != loopbackV4 && bindHost != loopbackV6 {
					t.Fatalf("non-loopback bind host %q (address %q)", bindHost, c.address)
				}
			}
			for _, addr := range ls.Addrs() {
				bindHost, _, err := net.SplitHostPort(addr.String())
				if err != nil {
					t.Fatalf("bound address %q is malformed: %v", addr, err)
				}
				ip := net.ParseIP(bindHost)
				if ip == nil || !ip.IsLoopback() {
					t.Fatalf("bound address %q is not loopback", addr)
				}
			}
		})
	}

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
		"127.0.0.1 ",
	} {
		t.Run("forbidden_"+strconv.Quote(host), func(t *testing.T) {
			called := false
			ls, err := listenWith(host, 0, func(network, address string) (net.Listener, error) {
				called = true
				return nil, errors.New("bind seam must not run for a non-loopback host")
			})
			if !errors.Is(err, ErrInvalidHost) {
				t.Fatalf("listenWith(%q) error = %v, want ErrInvalidHost", host, err)
			}
			if ls != nil {
				t.Fatalf("listenWith(%q) returned listeners for a rejected host", host)
			}
			if called {
				t.Fatalf("bind seam ran for non-loopback host %q", host)
			}
		})
	}
}

// telemetryGuardDialer records every outbound destination and refuses any
// non-loopback host. It is the W5.4 no-telemetry probe: if the proxy ever
// tried to phone home, the extra dial would be recorded (and refused) instead
// of silently leaving the machine. The guard is itself proven non-vacuous by
// the "non_loopback_egress_is_refused" subtest below.
type telemetryGuardDialer struct {
	mu    sync.Mutex
	dials []string
	base  net.Dialer
}

// errNonLoopbackDial marks a dial the telemetry guard refused.
var errNonLoopbackDial = errors.New("telemetry guard: refused non-loopback egress")

// DialContext implements the http.Transport dial seam.
func (d *telemetryGuardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, address)
	d.mu.Unlock()

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %s", errNonLoopbackDial, address)
	}
	return d.base.DialContext(ctx, network, address)
}

// destinations returns a copy of every address the guard observed.
func (d *telemetryGuardDialer) destinations() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dials...)
}

// guardedHTTPClient builds an HTTP client whose only dialer is the guard. The
// environment proxy is disabled so an HTTP_PROXY in CI cannot turn a loopback
// upstream into a non-loopback dial (which would be refused and hide the real
// invariant).
func guardedHTTPClient(guard *telemetryGuardDialer) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           guard.DialContext,
			Proxy:                 nil,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// TestNoTelemetry is the W5.4 named invariant (docs/security.md §1,
// docs/13 §9.2): a proxied request egresses only to the configured upstream.
// The forwarder is given a dialer that records and refuses non-loopback
// destinations, so any hidden telemetry call would show up as an extra or
// non-loopback dial.
func TestNoTelemetry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)

	t.Run("only_the_configured_upstream_is_dialed", func(t *testing.T) {
		guard := &telemetryGuardDialer{}
		fwd, err := NewForwarder(upstream.URL, nil, WithHTTPClient(guardedHTTPClient(guard)))
		if err != nil {
			t.Fatalf("NewForwarder: %v", err)
		}
		rec := httptest.NewRecorder()
		fwd.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/v1/messages", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (body %q), want 200", rec.Code, rec.Body.String())
		}

		dials := guard.destinations()
		if len(dials) != 1 {
			t.Fatalf("egress dials = %v, want exactly 1 (the configured upstream)", dials)
		}
		if want := upstream.Listener.Addr().String(); dials[0] != want {
			t.Fatalf("dialed %q, want the configured upstream %q", dials[0], want)
		}
		t.Logf("single egress dial: %s", dials[0])
	})

	t.Run("non_loopback_egress_is_refused", func(t *testing.T) {
		guard := &telemetryGuardDialer{}
		fwd, err := NewForwarder("http://203.0.113.7:9", nil, WithHTTPClient(guardedHTTPClient(guard)))
		if err != nil {
			t.Fatalf("NewForwarder: %v", err)
		}
		rec := httptest.NewRecorder()
		fwd.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/telemetry", nil))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 for a refused non-loopback egress", rec.Code)
		}
		dials := guard.destinations()
		if len(dials) != 1 || !strings.HasPrefix(dials[0], "203.0.113.7:") {
			t.Fatalf("guard dials = %v, want the refused non-loopback attempt recorded", dials)
		}
	})
}
