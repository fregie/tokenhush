package proxy

import (
	"reflect"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// TestBuiltinRoutes pins the exported view of the built-in routing table: the
// exact five entries in a stable order, that only the named exception
// (/v1/models) is flagged, that the table cannot drift from the resolver, and
// that each call returns an independent copy.
func TestBuiltinRoutes(t *testing.T) {
	want := []Route{
		{Path: "/v1/chat/completions", Upstream: extension.Upstream{Name: ProviderOpenAI, BaseURL: OpenAIBaseURL}},
		{Path: "/v1/messages", Upstream: extension.Upstream{Name: ProviderAnthropic, BaseURL: AnthropicBaseURL}},
		{Path: "/v1/messages/count_tokens", Upstream: extension.Upstream{Name: ProviderAnthropic, BaseURL: AnthropicBaseURL}},
		{Path: "/v1/responses", Upstream: extension.Upstream{Name: ProviderOpenAI, BaseURL: OpenAIBaseURL}},
		{Path: "/v1/models", Upstream: extension.Upstream{Name: ProviderOpenAI, BaseURL: OpenAIBaseURL}, Exception: true},
	}

	got := BuiltinRoutes()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuiltinRoutes() = %+v, want %+v", got, want)
	}

	// Only the named exception is flagged; every other entry is data-bearing.
	for _, r := range got {
		wantException := r.Path == "/v1/models"
		if r.Exception != wantException {
			t.Errorf("BuiltinRoutes entry %q Exception = %v, want %v", r.Path, r.Exception, wantException)
		}
	}

	// The table must not drift from the resolver: each entry resolves to the
	// upstream it advertises.
	resolver := NewResolver(nil, nil)
	for _, r := range got {
		up, err := resolver.Resolve(&extension.Request{Method: "POST", Path: r.Path})
		if err != nil {
			t.Fatalf("Resolve(%q) error = %v, want nil", r.Path, err)
		}
		if up != r.Upstream {
			t.Errorf("Resolve(%q) = %+v, BuiltinRoutes entry = %+v", r.Path, up, r.Upstream)
		}
	}

	// Order is stable across calls.
	if second := BuiltinRoutes(); !reflect.DeepEqual(got, second) {
		t.Errorf("BuiltinRoutes() order not stable: %+v vs %+v", got, second)
	}

	// The returned slice is a fresh copy: mutating it cannot corrupt the
	// package tables for the next caller.
	got[0].Upstream = extension.Upstream{Name: "mutated", BaseURL: "https://mutated.invalid"}
	if third := BuiltinRoutes(); !reflect.DeepEqual(third, want) {
		t.Errorf("BuiltinRoutes() after caller mutation = %+v, want %+v", third, want)
	}
}
