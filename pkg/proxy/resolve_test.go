package proxy

import (
	"errors"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
)

// builtinTableWant mirrors the built-in routing table one-to-one. The test
// spells every entry out instead of ranging over builtinRoutes so a silent
// table edit -- a dropped route, a wrong vendor, an extra local route -- fails
// here rather than drifting.
var builtinTableWant = map[string]Upstream{
	"/v1/audio/speech":          {BaseURL: OpenAIBaseURL},
	"/v1/audio/transcriptions":  {BaseURL: OpenAIBaseURL},
	"/v1/audio/translations":    {BaseURL: OpenAIBaseURL},
	"/v1/chat/completions":      {BaseURL: OpenAIBaseURL},
	"/v1/completions":           {BaseURL: OpenAIBaseURL},
	"/v1/embeddings":            {BaseURL: OpenAIBaseURL},
	"/v1/images/edits":          {BaseURL: OpenAIBaseURL},
	"/v1/images/generations":    {BaseURL: OpenAIBaseURL},
	"/v1/moderations":           {BaseURL: OpenAIBaseURL},
	"/v1/responses":             {BaseURL: OpenAIBaseURL},
	"/v1/messages":              {BaseURL: AnthropicBaseURL},
	"/v1/messages/batches":      {BaseURL: AnthropicBaseURL},
	"/v1/messages/count_tokens": {BaseURL: AnthropicBaseURL},
	"/v1/models":                {Local: true},
}

// TestResolveBuiltinPaths pins every built-in route to its audited vendor and
// proves the production table carries no undocumented entry.
func TestResolveBuiltinPaths(t *testing.T) {
	if len(builtinRoutes) != len(builtinTableWant) {
		t.Fatalf("builtinRoutes has %d entries, the audited table has %d", len(builtinRoutes), len(builtinTableWant))
	}
	for path, want := range builtinTableWant {
		got, err := Resolve(path, config.Default())
		if err != nil {
			t.Errorf("Resolve(%q) error = %v, want nil", path, err)
			continue
		}
		if got != want {
			t.Errorf("Resolve(%q) = %+v, want %+v", path, got, want)
		}
	}
	for path := range builtinRoutes {
		if _, documented := builtinTableWant[path]; !documented {
			t.Errorf("builtinRoutes contains undocumented route %q", path)
		}
	}
}

// TestResolveModelsIsTheLocalException pins the one named exception: it is
// proxy-local, carries no upstream URL, and is the only such entry.
func TestResolveModelsIsTheLocalException(t *testing.T) {
	got, err := Resolve("/v1/models", config.Default())
	if err != nil {
		t.Fatalf("Resolve(/v1/models) error = %v, want nil", err)
	}
	if !got.Local || got.BaseURL != "" {
		t.Errorf("Resolve(/v1/models) = %+v, want the proxy-local exception with no upstream", got)
	}
	for path, upstream := range builtinRoutes {
		if path != "/v1/models" && upstream.Local {
			t.Errorf("builtinRoutes[%q] is local, want it to be an upstream route", path)
		}
	}
}

// TestResolveConfiguredWinsOverBuiltins proves the configured upstreams:
// precedence: a configured match beats both a vendor route and the local
// exception, while unmatched paths keep their built-in route.
func TestResolveConfiguredWinsOverBuiltins(t *testing.T) {
	cfg := config.Config{Upstreams: []config.Upstream{
		{Match: "/v1/chat/completions", Target: "https://gateway.example/openai/"},
		{Match: "/v1/models", Target: "https://models.example"},
	}}

	got, err := Resolve("/v1/chat/completions", cfg)
	if err != nil {
		t.Fatalf("Resolve(/v1/chat/completions) error = %v, want nil", err)
	}
	if want := (Upstream{BaseURL: "https://gateway.example/openai"}); got != want {
		t.Errorf("Resolve(/v1/chat/completions) = %+v, want %+v", got, want)
	}

	got, err = Resolve("/v1/models", cfg)
	if err != nil {
		t.Fatalf("Resolve(/v1/models) error = %v, want nil", err)
	}
	if want := (Upstream{BaseURL: "https://models.example"}); got != want {
		t.Errorf("Resolve(/v1/models) = %+v, want the configured target %+v", got, want)
	}

	got, err = Resolve("/v1/messages", cfg)
	if err != nil {
		t.Fatalf("Resolve(/v1/messages) error = %v, want nil", err)
	}
	if want := (Upstream{BaseURL: AnthropicBaseURL}); got != want {
		t.Errorf("Resolve(/v1/messages) = %+v, want the untouched built-in %+v", got, want)
	}
}

// TestResolveConfiguredLongestMatchWins pins the configured matching rules:
// segment-boundary prefixes, longest key first, and no accidental catch-all.
// A near-miss never reaches the LONGER key, but a broader configured prefix
// (an operator's explicit choice) still covers it -- /v1/chat/completionsX is
// below /v1, so it goes to /v1's target and not to the built-in vendor.
func TestResolveConfiguredLongestMatchWins(t *testing.T) {
	cfg := config.Config{Upstreams: []config.Upstream{
		{Match: "/v1", Target: "https://aggregator.example"},
		{Match: "/v1/messages", Target: "https://anthropic-proxy.example/"},
		{Match: "/v1/chat/completions", Target: "https://chat-proxy.example"},
	}}

	cases := []struct {
		path string
		want Upstream
	}{
		{"/v1/messages", Upstream{BaseURL: "https://anthropic-proxy.example"}},
		{"/v1/messages/count_tokens", Upstream{BaseURL: "https://anthropic-proxy.example"}},
		{"/v1/chat/completions", Upstream{BaseURL: "https://chat-proxy.example"}},
		{"/v1/messagesX", Upstream{BaseURL: "https://aggregator.example"}},
		{"/v1/chat/completionsX", Upstream{BaseURL: "https://aggregator.example"}},
		{"/v1/unknown", Upstream{BaseURL: "https://aggregator.example"}},
		{"/healthz", Upstream{}},
		{"/v1", Upstream{BaseURL: "https://aggregator.example"}},
	}
	for _, tc := range cases {
		got, err := Resolve(tc.path, cfg)
		if tc.want == (Upstream{}) {
			if !errors.Is(err, ErrUnknownUpstream) {
				t.Errorf("Resolve(%q) error = %v, want ErrUnknownUpstream", tc.path, err)
			}
			if got != (Upstream{}) {
				t.Errorf("Resolve(%q) = %+v, want the zero Upstream", tc.path, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Resolve(%q) error = %v, want nil", tc.path, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Resolve(%q) = %+v, want %+v", tc.path, got, tc.want)
		}
	}
}

// TestResolveQueryTrailingSlashAndFragment pins the tolerated decorations: a
// query, a fragment and one or more trailing slashes never change the route.
func TestResolveQueryTrailingSlashAndFragment(t *testing.T) {
	cases := []struct {
		path string
		want Upstream
	}{
		{"/v1/chat/completions/", Upstream{BaseURL: OpenAIBaseURL}},
		{"/v1/chat/completions?stream=true", Upstream{BaseURL: OpenAIBaseURL}},
		{"/v1/chat/completions/?stream=true", Upstream{BaseURL: OpenAIBaseURL}},
		{"/v1/messages////", Upstream{BaseURL: AnthropicBaseURL}},
		{"/v1/messages#stream", Upstream{BaseURL: AnthropicBaseURL}},
		{"/v1/models/", Upstream{Local: true}},
	}
	for _, tc := range cases {
		got, err := Resolve(tc.path, config.Default())
		if err != nil {
			t.Errorf("Resolve(%q) error = %v, want nil", tc.path, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Resolve(%q) = %+v, want %+v", tc.path, got, tc.want)
		}
	}
}

// TestResolveNearMissesStayTypedErrors pins the three near-misses the plan
// names: each is a typed ErrUnknownUpstream, never the neighbouring route.
func TestResolveNearMissesStayTypedErrors(t *testing.T) {
	for _, path := range []string{"/v1/model", "/v1/models/foo", "/v1/chat/completionsX"} {
		got, err := Resolve(path, config.Default())
		if !errors.Is(err, ErrUnknownUpstream) {
			t.Errorf("Resolve(%q) error = %v, want ErrUnknownUpstream", path, err)
		}
		if got != (Upstream{}) {
			t.Errorf("Resolve(%q) = %+v, want the zero Upstream", path, got)
		}
		if err != nil && !strings.Contains(err.Error(), path) {
			t.Errorf("Resolve(%q) error %q does not name the rejected path", path, err)
		}
	}
}

// TestResolveUnknownPathsNeverDefault sweeps non-mapped paths -- empty,
// malformed, case-changed, percent-escaped, traversal-flavoured and every
// partial-segment variant -- and asserts the resolver errors instead of
// defaulting, both with and without configured upstreams.
func TestResolveUnknownPathsNeverDefault(t *testing.T) {
	paths := []string{
		"",
		"/",
		"///",
		"v1/messages",
		"/v1",
		"/v1/",
		"/v1/chat",
		"/v1/chat/",
		"/v1/messagesX",
		"/v1/messages/extra",
		"/v1/messages/count_tokens/extra",
		"/v1/model",
		"/v1/modelsX",
		"/v1/models/foo",
		"/v1/models/foo/bar",
		"/v1/chat/completionsX",
		"/api/v1/messages",
		"/healthz",
		"/status",
		"/v1/Models",
		"/V1/MESSAGES",
		"//v1/messages",
		"/v1/../v1/messages",
		"/v1/messages/../chat/completions",
		"/v1/%6dessages",
	}
	configs := map[string]config.Config{
		"default":  config.Default(),
		"override": {Upstreams: []config.Upstream{{Match: "/v1/chat/completions", Target: "https://gateway.example"}}},
	}
	for name, cfg := range configs {
		t.Run(name, func(t *testing.T) {
			for _, path := range paths {
				got, err := Resolve(path, cfg)
				if !errors.Is(err, ErrUnknownUpstream) {
					t.Errorf("Resolve(%q) error = %v, want ErrUnknownUpstream", path, err)
					continue
				}
				if got != (Upstream{}) {
					t.Errorf("Resolve(%q) = %+v, want the zero Upstream", path, got)
				}
			}
		})
	}
}
