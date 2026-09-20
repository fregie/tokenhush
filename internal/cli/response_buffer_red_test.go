package cli

// response_buffer_red_test.go holds the Wave-1 red regressions for the
// whole-response buffering rewrite (work plan todos 3, 4 and 6). Every test
// here compiles today and fails on an assertion: the writer still streams SSE,
// there is no buffer cap and no response deadline. Todos 16 and 19 make them
// green. Helpers are prefixed "red" so they cannot collide with the other
// Wave-1 test files.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
)

// redResponseSpy is a client-bound writer that records when the responseWriter
// actually commits: the first WriteHeader flips wrote, so "nothing is
// committed before finish()" is directly observable.
type redResponseSpy struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
}

func newRedResponseSpy() *redResponseSpy { return &redResponseSpy{header: http.Header{}} }

func (s *redResponseSpy) Header() http.Header { return s.header }

func (s *redResponseSpy) WriteHeader(status int) {
	if !s.wrote {
		s.wrote, s.status = true, status
	}
}

func (s *redResponseSpy) Write(p []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.body.Write(p)
}

func (s *redResponseSpy) Flush() {}

// redGateway builds a real pipeline over cfg with a throwaway data dir.
func redGateway(t *testing.T, cfg config.Config) *gateway {
	t.Helper()
	gw, err := buildGateway(cfg, t.TempDir(), io.Discard, false)
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}
	return gw
}

// redBlockingGateway builds a pipeline whose response phase blocks on the
// keyword BLOCKME, so a response-scoped Block can be driven through the writer.
func redBlockingGateway(t *testing.T) *gateway {
	t.Helper()
	gw := redGateway(t, config.Default())
	doc := &filter.Document{Rules: []filter.RuleDoc{{
		ID: "resp-block", Type: filter.TypeKeyword, Category: filter.CategoryCustom,
		Scope: filter.ScopeResponse, Action: filter.ActionBlock, Keywords: []string{"BLOCKME"},
	}}}
	compiled, err := filter.Compile(doc)
	if err != nil {
		t.Fatalf("compile blocking rule: %v", err)
	}
	registry := filter.NewRegistry()
	if err := registry.RegisterCompiled(compiled); err != nil {
		t.Fatalf("register blocking rule: %v", err)
	}
	gw.policy = filter.NewPolicy(registry, filter.PolicyConfig{})
	return gw
}

// redConfig points /v1/chat/completions at target.
func redConfig(target string) config.Config {
	cfg := config.Default()
	cfg.Listen.Port = 0
	cfg.Upstreams = []config.Upstream{{Match: "/v1/chat/completions", Target: target}}
	return cfg
}

// redUpstream starts a fake upstream and closes it at test cleanup.
func redUpstream(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// redRoute drives one request through the real route/finish path and returns
// the recorder the writer committed into.
func redRoute(t *testing.T, gw *gateway, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	gw.route(rec, req)
	return rec
}

// redClosedPort reserves and immediately releases a loopback port, so a dial to
// it is refused fast and deterministically.
func redClosedPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

// TestResponseWriterCommitsOnlyInFinish pins B-FD1's single commit point: the
// client sees neither a status nor a byte until finish(), for a buffered body
// and for an event stream alike.
func TestResponseWriterCommitsOnlyInFinish(t *testing.T) {
	gw := redGateway(t, config.Default())
	cases := []struct {
		name        string
		contentType string
		body        string
	}{
		{"non-sse", "application/json", `{"a":"b"}`},
		{"sse", "text/event-stream", "data: {\"a\":\"b\"}\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := newRedResponseSpy()
			w := &responseWriter{dst: spy, gate: gw, req: httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)}
			w.Header().Set("Content-Type", tc.contentType)
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(tc.body)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if spy.wrote {
				t.Errorf("the response committed status %d before finish()", spy.status)
			}
			w.finish()
			if !spy.wrote {
				t.Fatalf("finish() did not commit the response")
			}
			if spy.status != http.StatusOK {
				t.Errorf("committed status = %d, want 200", spy.status)
			}
			if spy.body.Len() == 0 {
				t.Errorf("finish() committed an empty body")
			}
		})
	}
}

// TestResponseWriterBuffersNonSSE pins that the non-SSE body accumulates in the
// writer's buffer and is capped there: a sub-cap write is accepted without a
// commit, and a write past response_buffer_bytes is refused (B-FD1's sentinel),
// finishing as 502.
func TestResponseWriterBuffersNonSSE(t *testing.T) {
	cfg := config.Default()
	cfg.ResponseBufferBytes = 16
	gw := redGateway(t, cfg)
	spy := newRedResponseSpy()
	w := &responseWriter{dst: spy, gate: gw, req: httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	first := []byte(`{"a":"b"}`)
	n, err := w.Write(first)
	if err != nil {
		t.Fatalf("buffering a sub-cap body returned an error: %v", err)
	}
	if n != len(first) {
		t.Errorf("Write accepted %d bytes, want %d", n, len(first))
	}
	if spy.wrote {
		t.Errorf("a buffered non-SSE body committed before finish()")
	}
	if _, err := w.Write([]byte(strings.Repeat("x", 32))); err == nil {
		t.Errorf("a non-SSE body past response_buffer_bytes was accepted without error")
	}
	w.finish()
	if spy.status != http.StatusBadGateway {
		t.Errorf("finish() committed %d, want 502 after the buffer cap was exceeded", spy.status)
	}
}

// TestSSEBlockYields502NotErrorRecord pins B-FD3: a response-scoped Block on a
// stream is a clean 502 with nothing committed, never the old in-stream error
// record delivered after a committed 200.
func TestSSEBlockYields502NotErrorRecord(t *testing.T) {
	gw := redBlockingGateway(t)
	spy := newRedResponseSpy()
	w := &responseWriter{dst: spy, gate: gw, req: httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("data: {\"text\":\"BLOCKME\"}\n\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if spy.wrote {
		t.Errorf("the SSE stream committed status %d before finish()", spy.status)
	}
	w.finish()
	if spy.status != http.StatusBadGateway {
		t.Errorf("committed status = %d, want 502", spy.status)
	}
	body := spy.body.Bytes()
	if bytes.Contains(body, []byte("event: error")) {
		t.Errorf("the client received an in-stream SSE error record: %s", body)
	}
	if !bytes.Contains(body, []byte("rule_blocked")) {
		t.Errorf("the 502 body does not name the block: %s", body)
	}
}

// TestLocalErrorBodyNotEvaluated pins that a locally generated error body is
// excluded from response evaluation: a refused dial is a 502 whose "Bad
// Gateway" text must not move walk_skips.
func TestLocalErrorBodyNotEvaluated(t *testing.T) {
	port := redClosedPort(t)
	gw := redGateway(t, redConfig(fmt.Sprintf("http://127.0.0.1:%d", port)))
	rec := redRoute(t, gw, "/v1/chat/completions")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if got := gw.counters.WalkSkips(); got != 0 {
		t.Errorf("a locally generated error body moved %d walk_skips, want 0", got)
	}
}

// TestResponseBufferCapExceededIs502BeforeCommit pins todo 4: a stream past
// response_buffer_bytes is a 502 with zero upstream bytes committed, and the
// upstream read is aborted rather than drained.
func TestResponseBufferCapExceededIs502BeforeCommit(t *testing.T) {
	const planned = 8 << 20
	var written atomic.Int64
	done := make(chan struct{})
	srv := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, `{"data":"`); err != nil {
			return
		}
		chunk := bytes.Repeat([]byte("a"), 4096)
		total := 0
		for total < planned {
			n, err := w.Write(chunk)
			total += n
			written.Store(int64(total))
			if err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, `"}`)
	})
	cfg := redConfig(srv.URL)
	cfg.ResponseBufferBytes = 64
	gw := redGateway(t, cfg)

	rec := redRoute(t, gw, "/v1/chat/completions")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the fake upstream never stopped writing")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 when the response exceeds response_buffer_bytes", rec.Code)
	}
	if got := written.Load(); got >= planned {
		t.Errorf("the upstream wrote %d bytes, want the read aborted below %d", got, planned)
	}
	if got := gw.counters.WalkSkips(); got != 0 {
		t.Errorf("the over-cap refusal moved %d walk_skips, want 0", got)
	}
	if bytes.Contains(rec.Body.Bytes(), bytes.Repeat([]byte("a"), 256)) {
		t.Errorf("upstream bytes were committed despite the over-cap refusal")
	}
}

// TestResponseBufferAtCapForwarded pins the exact cap boundary: exactly
// response_buffer_bytes is forwarded unchanged, one byte more is refused.
func TestResponseBufferAtCapForwarded(t *testing.T) {
	const capBytes = 64
	srv := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		width := 53
		if r.URL.Query().Get("n") == "65" {
			width = 54
		}
		body := []byte(`{"data":"` + strings.Repeat("a", width) + `"}`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	cfg := redConfig(srv.URL)
	cfg.ResponseBufferBytes = capBytes
	gw := redGateway(t, cfg)

	atCap := redRoute(t, gw, "/v1/chat/completions?n=64")
	if atCap.Code != http.StatusOK {
		t.Errorf("exactly-at-cap status = %d, want 200", atCap.Code)
	}
	want := []byte(`{"data":"` + strings.Repeat("a", 53) + `"}`)
	if len(want) != capBytes {
		t.Fatalf("test fixture is %d bytes, want %d", len(want), capBytes)
	}
	if !bytes.Equal(atCap.Body.Bytes(), want) {
		t.Errorf("exactly-at-cap body = %q, want %q", atCap.Body.Bytes(), want)
	}

	overCap := redRoute(t, gw, "/v1/chat/completions?n=65")
	if overCap.Code != http.StatusBadGateway {
		t.Errorf("one-byte-over-cap status = %d, want 502", overCap.Code)
	}
}

// TestResponseBufferOverallDeadline pins that response_timeout bounds the whole
// response read: an upstream that stalls after its headers yields 504 well
// inside the stall.
func TestResponseBufferOverallDeadline(t *testing.T) {
	srv := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
		_, _ = io.WriteString(w, `{"late":true}`)
	})
	cfg := redConfig(srv.URL)
	cfg.ResponseTimeout = 100 * time.Millisecond
	gw := redGateway(t, cfg)

	start := time.Now()
	rec := redRoute(t, gw, "/v1/chat/completions")
	elapsed := time.Since(start)
	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504 when the response stalls past response_timeout", rec.Code)
	}
	if elapsed >= 600*time.Millisecond {
		t.Errorf("the response took %s, want the overall deadline to bound it well under 600ms", elapsed)
	}
}

// TestResponseBufferTimeoutIs504BeforeCommit pins that a timeout discards every
// buffered upstream byte: no partial body reaches the client, only the 504.
func TestResponseBufferTimeoutIs504BeforeCommit(t *testing.T) {
	srv := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"partial":`)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
		_, _ = io.WriteString(w, `"late"}`)
	})
	cfg := redConfig(srv.URL)
	cfg.ResponseTimeout = 100 * time.Millisecond
	gw := redGateway(t, cfg)

	rec := redRoute(t, gw, "/v1/chat/completions")
	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504 before any commit", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("partial")) {
		t.Errorf("a partial upstream body was committed: %q", rec.Body.Bytes())
	}
}

// TestResponseBufferUnderDeadlineSucceeds pins that a response finishing inside
// response_timeout is forwarded whole, while one past it is refused.
func TestResponseBufferUnderDeadlineSucceeds(t *testing.T) {
	fast := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	cfg := redConfig(fast.URL)
	cfg.ResponseTimeout = 5 * time.Second
	gw := redGateway(t, cfg)
	rec := redRoute(t, gw, "/v1/chat/completions")
	if rec.Code != http.StatusOK {
		t.Errorf("a fast response under response_timeout = %d, want 200", rec.Code)
	}
	if got, want := rec.Body.String(), `{"ok":true}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	slow := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
		_, _ = io.WriteString(w, `{"late":true}`)
	})
	slowCfg := redConfig(slow.URL)
	slowCfg.ResponseTimeout = 100 * time.Millisecond
	if rec := redRoute(t, redGateway(t, slowCfg), "/v1/chat/completions"); rec.Code != http.StatusGatewayTimeout {
		t.Errorf("a response past response_timeout = %d, want 504", rec.Code)
	}
}

// TestResponseBufferCapBeatsTimeout pins the frozen precedence: an over-cap
// stream is 502 even when a response deadline is also configured.
func TestResponseBufferCapBeatsTimeout(t *testing.T) {
	srv := redUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("a", 4096) + `"}`))
	})
	cfg := redConfig(srv.URL)
	cfg.ResponseBufferBytes = 64
	cfg.ResponseTimeout = 200 * time.Millisecond
	gw := redGateway(t, cfg)

	rec := redRoute(t, gw, "/v1/chat/completions")
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502: the buffer cap wins over the response deadline", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(strings.Repeat("a", 256))) {
		t.Errorf("upstream bytes were committed despite the cap")
	}
}
