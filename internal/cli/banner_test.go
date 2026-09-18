package cli

import (
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// TestStartupBannerNamesTheEndpointRoutingAndToolHint pins the three things an
// operator needs at startup and that the banner carries no value.
func TestStartupBannerNamesTheEndpointRoutingAndToolHint(t *testing.T) {
	cfg := config.Default()
	cfg.Upstreams = []config.Upstream{{Match: "/v1/chat/completions", Target: "https://relay.example"}}
	var out strings.Builder

	printStartupBanner(&out, cfg, []string{"127.0.0.1:8787"}, 8787)
	got := out.String()

	for _, want := range []string{
		"listening on http://127.0.0.1:8787",
		"/v1/chat/completions -> https://relay.example",
		proxy.OpenAIBaseURL,
		proxy.AnthropicBaseURL,
		"GET /v1/models",
		"http://127.0.0.1:8787/v1",
		"tokenhush env <tool>",
		"claude",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("banner missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "__PII_") {
		t.Errorf("banner leaked a placeholder:\n%s", got)
	}
}

// TestStartupBannerDefaultsWhenNoUpstreamsConfigured pins the no-config line.
func TestStartupBannerDefaultsWhenNoUpstreamsConfigured(t *testing.T) {
	var out strings.Builder
	printStartupBanner(&out, config.Default(), []string{"127.0.0.1:8787"}, 8787)
	if got := out.String(); !strings.Contains(got, "none configured; built-in routes apply") {
		t.Errorf("banner = %q, want the no-config upstream line", got)
	}
}
