package proxy

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/extension"
)

// resolveLoopbackHost is the Host a V1 client presents to the local gateway
// (the only spelling that survives HostAllowlist), so host-key overrides are
// exercised with provider-shaped hosts in their own cases.
const resolveLoopbackHost = "127.0.0.1:8787"

// resolveRecordingSink is a fake audit.AuditSink that captures rejection rows
// and can be forced to fail, so the resolver's audit seam is testable without
// the W5.3 store.
type resolveRecordingSink struct {
	mu      sync.Mutex
	records []audit.Record
	err     error
}

func (s *resolveRecordingSink) Record(rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return s.err
}

func (s *resolveRecordingSink) snapshot() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...)
}

func resolveReq(method, host, path string) *extension.Request {
	return &extension.Request{Method: method, Host: host, Path: path}
}

// TestUpstreamResolve is the W3.8 acceptance table: real-shaped tool routes
// must resolve to the exact provider (never merely "some upstream"), config
// upstreams: overrides must win with a documented precedence, and every
// unrecognised path must yield ErrUnknownUpstream with a zero Upstream.
func TestUpstreamResolve(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		method    string
		host      string
		path      string
		wantName  string
		wantBase  string
		wantErr   error
	}{
		// Built-in provider table (docs/13 §4.1 + docs/12 §6.1 shapes).
		{name: "anthropic messages", method: "POST", host: resolveLoopbackHost, path: "/v1/messages", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "anthropic messages oauth query", method: "POST", host: resolveLoopbackHost, path: "/v1/messages?beta=true", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "anthropic messages fragment", method: "POST", host: resolveLoopbackHost, path: "/v1/messages#beta", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "anthropic count tokens", method: "POST", host: resolveLoopbackHost, path: "/v1/messages/count_tokens", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "anthropic count tokens oauth query", method: "POST", host: resolveLoopbackHost, path: "/v1/messages/count_tokens?beta=true", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "anthropic messages trailing slash", method: "POST", host: resolveLoopbackHost, path: "/v1/messages/", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "anthropic messages trailing slash query", method: "POST", host: resolveLoopbackHost, path: "/v1/messages/?beta=true", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "anthropic count tokens on GET", method: "GET", host: resolveLoopbackHost, path: "/v1/messages/count_tokens", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "openai chat completions", method: "POST", host: resolveLoopbackHost, path: "/v1/chat/completions", wantName: ProviderOpenAI, wantBase: OpenAIBaseURL},
		{name: "openai responses", method: "POST", host: resolveLoopbackHost, path: "/v1/responses", wantName: ProviderOpenAI, wantBase: OpenAIBaseURL},
		{name: "openai responses trailing slash", method: "POST", host: resolveLoopbackHost, path: "/v1/responses/", wantName: ProviderOpenAI, wantBase: OpenAIBaseURL},
		{name: "built-in route ignores request host", method: "POST", host: "api.anthropic.com", path: "/v1/messages", wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},

		// Unknown paths: typed error, zero Upstream, never a guessed provider.
		{name: "unknown ambiguous models path", method: "GET", host: resolveLoopbackHost, path: "/v1/models", wantErr: ErrUnknownUpstream},
		{name: "unknown root path", method: "GET", host: resolveLoopbackHost, path: "/", wantErr: ErrUnknownUpstream},
		{name: "unknown empty path", method: "GET", host: resolveLoopbackHost, path: "", wantErr: ErrUnknownUpstream},
		{name: "unknown query-only path", method: "GET", host: resolveLoopbackHost, path: "?beta=true", wantErr: ErrUnknownUpstream},
		{name: "unknown api version", method: "POST", host: resolveLoopbackHost, path: "/v2/messages", wantErr: ErrUnknownUpstream},
		{name: "unknown sibling segment", method: "POST", host: resolveLoopbackHost, path: "/v1/messagesX", wantErr: ErrUnknownUpstream},
		{name: "unknown uppercase path", method: "POST", host: resolveLoopbackHost, path: "/V1/MESSAGES", wantErr: ErrUnknownUpstream},
		{name: "unknown dot-dot traversal", method: "POST", host: resolveLoopbackHost, path: "/v1/messages/../chat/completions", wantErr: ErrUnknownUpstream},
		{name: "unknown escaped traversal", method: "POST", host: resolveLoopbackHost, path: "/v1/messages/%2e%2e/chat/completions", wantErr: ErrUnknownUpstream},
		{name: "unknown double leading slash", method: "POST", host: resolveLoopbackHost, path: "//v1/messages", wantErr: ErrUnknownUpstream},
		{name: "unknown double inner slash", method: "POST", host: resolveLoopbackHost, path: "/v1//messages", wantErr: ErrUnknownUpstream},
		{name: "unknown backslash traversal", method: "POST", host: resolveLoopbackHost, path: `/v1/messages\..\chat\completions`, wantErr: ErrUnknownUpstream},
		{name: "unknown path without leading slash", method: "POST", host: resolveLoopbackHost, path: "v1/messages", wantErr: ErrUnknownUpstream},
		{name: "unknown absolute URL as path", method: "POST", host: resolveLoopbackHost, path: "http://api.anthropic.com/v1/messages", wantErr: ErrUnknownUpstream},
		{name: "unknown trailing space path", method: "POST", host: resolveLoopbackHost, path: "/v1/messages ", wantErr: ErrUnknownUpstream},
		{name: "unknown NUL byte path", method: "POST", host: resolveLoopbackHost, path: "/v1/messages\x00", wantErr: ErrUnknownUpstream},
		{name: "unknown cyrillic homoglyph path", method: "POST", host: resolveLoopbackHost, path: "/v1/мessages", wantErr: ErrUnknownUpstream},
		{name: "unknown near version path", method: "POST", host: resolveLoopbackHost, path: "/v1.1/responses", wantErr: ErrUnknownUpstream},

		// Config upstreams: overrides (docs/13 §7, W2.5 shape).
		{name: "exact path override of built-in route", method: "POST", host: resolveLoopbackHost, path: "/v1/messages",
			overrides: map[string]string{"/v1/messages": "https://gw.example/anthropic"}, wantName: ProviderAnthropic, wantBase: "https://gw.example/anthropic"},
		{name: "exact path override of unknown route", method: "POST", host: resolveLoopbackHost, path: "/v1/unknown",
			overrides: map[string]string{"/v1/unknown": "https://gw.example/custom"}, wantName: ProviderCustom, wantBase: "https://gw.example/custom"},
		{name: "exact override key trailing slash normalized", method: "POST", host: resolveLoopbackHost, path: "/v1/messages",
			overrides: map[string]string{"/v1/messages/": "https://gw.example/anthropic"}, wantName: ProviderAnthropic, wantBase: "https://gw.example/anthropic"},
		{name: "path prefix override wins over built-in", method: "POST", host: resolveLoopbackHost, path: "/v1/chat/completions",
			overrides: map[string]string{"/v1": "https://gw.example/v1"}, wantName: ProviderOpenAI, wantBase: "https://gw.example/v1"},
		{name: "longest path prefix wins", method: "POST", host: resolveLoopbackHost, path: "/v1/messages/count_tokens",
			overrides: map[string]string{"/v1": "https://gw.example/v1", "/v1/messages": "https://gw.example/anthropic/messages"},
			wantName:  ProviderAnthropic, wantBase: "https://gw.example/anthropic/messages"},
		{name: "path prefix needs segment boundary", method: "POST", host: resolveLoopbackHost, path: "/v1/messages",
			overrides: map[string]string{"/v1/message": "https://gw.example/partial"}, wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "path prefix segment boundary matches", method: "POST", host: resolveLoopbackHost, path: "/v1/chat/completions",
			overrides: map[string]string{"/v1/chat": "https://gw.example/chat"}, wantName: ProviderOpenAI, wantBase: "https://gw.example/chat"},
		{name: "root prefix is catch-all for unknown paths", method: "POST", host: resolveLoopbackHost, path: "/v1/unknown",
			overrides: map[string]string{"/": "https://gw.example/all"}, wantName: ProviderCustom, wantBase: "https://gw.example/all"},
		{name: "host override on known path", method: "POST", host: "api.anthropic.com", path: "/v1/messages",
			overrides: map[string]string{"api.anthropic.com": "https://gw.example/anthropic"}, wantName: ProviderAnthropic, wantBase: "https://gw.example/anthropic"},
		{name: "host override exact port", method: "POST", host: "api.example.com:8443", path: "/v1/chat/completions",
			overrides: map[string]string{"api.example.com:8443": "https://gw.example/8443"}, wantName: ProviderOpenAI, wantBase: "https://gw.example/8443"},
		{name: "host override port mismatch falls through", method: "POST", host: "api.example.com:9443", path: "/v1/chat/completions",
			overrides: map[string]string{"api.example.com:8443": "https://gw.example/8443"}, wantName: ProviderOpenAI, wantBase: OpenAIBaseURL},
		{name: "host override without port matches any port", method: "POST", host: "api.example.com:9443", path: "/v1/responses",
			overrides: map[string]string{"api.example.com": "https://gw.example/any"}, wantName: ProviderOpenAI, wantBase: "https://gw.example/any"},
		{name: "host override is case-insensitive", method: "POST", host: "api.example.com:443", path: "/v1/responses",
			overrides: map[string]string{"API.Example.COM": "https://gw.example/upper"}, wantName: ProviderOpenAI, wantBase: "https://gw.example/upper"},
		{name: "host override explicit port beats portless", method: "POST", host: "api.example.com:8443", path: "/v1/responses",
			overrides: map[string]string{"api.example.com": "https://gw.example/any", "api.example.com:8443": "https://gw.example/8443"},
			wantName:  ProviderOpenAI, wantBase: "https://gw.example/8443"},
		{name: "host override bracketed IPv6 literal", method: "POST", host: "[::1]:9000", path: "/v1/messages",
			overrides: map[string]string{"[::1]:9000": "https://gw.example/v6"}, wantName: ProviderAnthropic, wantBase: "https://gw.example/v6"},
		{name: "exact path override beats host override", method: "POST", host: "api.anthropic.com", path: "/v1/messages",
			overrides: map[string]string{"/v1/messages": "https://gw.example/path", "api.anthropic.com": "https://gw.example/host"},
			wantName:  ProviderAnthropic, wantBase: "https://gw.example/path"},
		{name: "exact host override beats path prefix", method: "POST", host: "api.anthropic.com", path: "/v1/messages",
			overrides: map[string]string{"/v1": "https://gw.example/prefix", "api.anthropic.com": "https://gw.example/host"},
			wantName:  ProviderAnthropic, wantBase: "https://gw.example/host"},
		{name: "host override does not rescue unknown path", method: "POST", host: resolveLoopbackHost, path: "/v1/unknown",
			overrides: map[string]string{"api.anthropic.com": "https://gw.example/host"}, wantErr: ErrUnknownUpstream},
		{name: "blank override key and value ignored", method: "POST", host: resolveLoopbackHost, path: "/v1/messages",
			overrides: map[string]string{"": "https://gw.example/blank", "/v1/messages": " "}, wantName: ProviderAnthropic, wantBase: AnthropicBaseURL},
		{name: "nil overrides use built-in table", method: "POST", host: resolveLoopbackHost, path: "/v1/responses",
			overrides: nil, wantName: ProviderOpenAI, wantBase: OpenAIBaseURL},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewResolver(tc.overrides, nil)
			got, err := r.Resolve(resolveReq(tc.method, tc.host, tc.path))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Resolve(%q) error = %v, want error wrapping %v", tc.path, err, tc.wantErr)
				}
				if got != (extension.Upstream{}) {
					t.Fatalf("Resolve(%q) = %+v on error, want the zero Upstream (never a guessed provider)", tc.path, got)
				}
				t.Logf("path %q -> typed error: %v", tc.path, err)
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) unexpected error: %v", tc.path, err)
			}
			if got.Name != tc.wantName || got.BaseURL != tc.wantBase {
				t.Fatalf("Resolve(%q) = %+v, want {Name:%q BaseURL:%q}", tc.path, got, tc.wantName, tc.wantBase)
			}
			t.Logf("path %q -> upstream %s %s", tc.path, got.Name, got.BaseURL)
		})
	}
}

// TestUpstreamResolveUnknownPathAuditRow locks the audit seam for unknown-path
// rejections: a sink gets exactly one metadata-only row, a nil sink is still a
// typed error (the caller records it), and a failing sink never masks the
// rejection.
func TestUpstreamResolveUnknownPathAuditRow(t *testing.T) {
	sink := &resolveRecordingSink{}
	r := NewResolver(nil, sink)

	// A served request must not write a rejection row here: the handler
	// records served traffic (bytes, status, redactions), not the resolver.
	if _, err := r.Resolve(resolveReq("POST", resolveLoopbackHost, "/v1/messages")); err != nil {
		t.Fatalf("known path resolved with error: %v", err)
	}
	if rows := sink.snapshot(); len(rows) != 0 {
		t.Fatalf("known path wrote %d audit rows, want 0", len(rows))
	}

	// Unknown path: typed error plus exactly one metadata-only row. The query
	// string is not stored (it can carry sensitive parameters).
	_, err := r.Resolve(resolveReq("POST", resolveLoopbackHost, "/v1/secret?token=abc"))
	if !errors.Is(err, ErrUnknownUpstream) {
		t.Fatalf("unknown path error = %v, want ErrUnknownUpstream", err)
	}
	rows := sink.snapshot()
	if len(rows) != 1 {
		t.Fatalf("unknown path wrote %d audit rows, want 1", len(rows))
	}
	rec := rows[0]
	t.Logf("unknown-path audit row: %+v (error: %v)", rec, err)
	switch {
	case rec.Path != "/v1/secret":
		t.Errorf("audit Path = %q, want %q (query stripped)", rec.Path, "/v1/secret")
	case rec.Method != "POST":
		t.Errorf("audit Method = %q, want %q", rec.Method, "POST")
	case rec.Status != http.StatusBadGateway:
		t.Errorf("audit Status = %d, want %d", rec.Status, http.StatusBadGateway)
	case rec.Provider != "":
		t.Errorf("audit Provider = %q, want empty (no provider was chosen)", rec.Provider)
	case rec.ReqBytes != 0 || rec.RespBytes != 0 || rec.Redactions != 0 || rec.Detectors != nil:
		t.Errorf("audit row carries request data: %+v", rec)
	case rec.ID != 0 || rec.PrevHash != nil || rec.Hash != nil:
		t.Errorf("audit row must leave store-assigned fields zero: %+v", rec)
	case rec.TS <= 0:
		t.Errorf("audit TS = %d, want unix milliseconds > 0", rec.TS)
	}

	// A failing sink must not replace the typed rejection.
	broken := &resolveRecordingSink{err: errors.New("audit store down")}
	if _, err := NewResolver(nil, broken).Resolve(resolveReq("GET", resolveLoopbackHost, "/v1/nope")); !errors.Is(err, ErrUnknownUpstream) {
		t.Fatalf("with failing sink error = %v, want ErrUnknownUpstream", err)
	}

	// No sink: typed error remains; recording is the caller's job.
	if _, err := NewResolver(nil, nil).Resolve(resolveReq("GET", resolveLoopbackHost, "/v1/nope")); !errors.Is(err, ErrUnknownUpstream) {
		t.Fatalf("with nil sink error = %v, want ErrUnknownUpstream", err)
	}
}

// TestUpstreamResolveNilRequest guards the seam against a nil request instead
// of panicking.
func TestUpstreamResolveNilRequest(t *testing.T) {
	r := NewResolver(nil, &resolveRecordingSink{})
	if _, err := r.Resolve(nil); !errors.Is(err, ErrUnknownUpstream) {
		t.Fatalf("Resolve(nil) error = %v, want ErrUnknownUpstream", err)
	}
	if _, err := r.Pick(nil); !errors.Is(err, ErrUnknownUpstream) {
		t.Fatalf("Pick(nil) error = %v, want ErrUnknownUpstream", err)
	}
}

// TestUpstreamResolveLongPathErrorBounded locks that attacker-controlled path
// text cannot inflate the typed error without bound.
func TestUpstreamResolveLongPathErrorBounded(t *testing.T) {
	r := NewResolver(nil, nil)
	long := "/v1/" + strings.Repeat("a", 1<<20)
	_, err := r.Resolve(resolveReq("POST", resolveLoopbackHost, long))
	if !errors.Is(err, ErrUnknownUpstream) {
		t.Fatalf("long path error = %v, want ErrUnknownUpstream", err)
	}
	if len(err.Error()) > 256 {
		t.Fatalf("error message is %d bytes, want <= 256", len(err.Error()))
	}
	t.Logf("long path (%d bytes) -> error (%d bytes): %v", len(long), len(err.Error()), err)
}

// TestUpstreamResolvePickMatchesRouterContract proves the Resolver satisfies
// extension.Router and that Pick is exactly the Resolve result, for both a
// routed path and a rejection.
func TestUpstreamResolvePickMatchesRouterContract(t *testing.T) {
	r := NewResolver(nil, nil)
	var router extension.Router = r
	if got := router.Name(); got != "default" {
		t.Fatalf("Name() = %q, want %q", got, "default")
	}

	for _, path := range []string{"/v1/messages", "/v1/unknown"} {
		req := resolveReq("POST", resolveLoopbackHost, path)
		picked, pickErr := router.Pick(req)
		resolved, resolveErr := r.Resolve(req)
		if picked != resolved {
			t.Errorf("Pick(%q) = %+v, Resolve = %+v, want identical", path, picked, resolved)
		}
		switch {
		case resolveErr == nil && pickErr != nil:
			t.Errorf("Pick(%q) error = %v, Resolve error = nil", path, pickErr)
		case resolveErr != nil && (!errors.Is(pickErr, ErrUnknownUpstream) || !errors.Is(resolveErr, ErrUnknownUpstream)):
			t.Errorf("Pick(%q) error = %v, Resolve error = %v, want both wrapping ErrUnknownUpstream", path, pickErr, resolveErr)
		}
		t.Logf("path %q: Pick=%+v err=%v", path, picked, pickErr)
	}
}
