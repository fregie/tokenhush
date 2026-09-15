package cli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// TestWriteStartupSummary pins the local startup banner: the built-in routing
// table, the config override block and the tool-onboarding hint. The renderer
// makes no network request; these assertions cover only the rendered bytes.
func TestWriteStartupSummary(t *testing.T) {
	builtinPaths := []string{
		"/v1/chat/completions",
		"/v1/messages",
		"/v1/messages/count_tokens",
		"/v1/responses",
		"/v1/models",
	}

	t.Run("default config", func(t *testing.T) {
		cfg := config.Default()
		var buf bytes.Buffer
		writeStartupSummary(&buf, &cfg)
		out := buf.String()

		for _, path := range builtinPaths {
			if !strings.Contains(out, path) {
				t.Errorf("output missing built-in path %q:\n%s", path, out)
			}
		}
		for _, base := range []string{proxy.OpenAIBaseURL, proxy.AnthropicBaseURL} {
			if !strings.Contains(out, base) {
				t.Errorf("output missing base URL %q:\n%s", base, out)
			}
		}
		if !strings.Contains(out, "any other path is rejected, never misrouted") {
			t.Errorf("output missing the unknown-path rejection line:\n%s", out)
		}

		var exceptionLines []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "(named exception: model discovery)") {
				exceptionLines = append(exceptionLines, line)
			}
		}
		if len(exceptionLines) != 1 {
			t.Fatalf("named-exception marker appears on %d lines, want 1:\n%s", len(exceptionLines), out)
		}
		if !strings.Contains(exceptionLines[0], "/v1/models") {
			t.Errorf("named-exception marker is on the wrong line %q, want /v1/models", exceptionLines[0])
		}

		port := int(cfg.Listen.Port)
		root := fmt.Sprintf("http://127.0.0.1:%d", port)
		for _, want := range []string{
			"tokenhush env claude",
			"tokenhush env codex",
			"tokenhush env <tool>",
			"# ANTHROPIC_BASE_URL=" + root,
			"# base_url=" + root + "/v1",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing onboarding hint %q:\n%s", want, out)
			}
		}

		if len(envTools) != 14 {
			t.Fatalf("envTools has %d entries, want 14", len(envTools))
		}
		if wantTools := strings.Join(envTools, ", "); !strings.Contains(out, "# "+wantTools) {
			t.Errorf("output missing the %d-tool list %q:\n%s", len(envTools), wantTools, out)
		}

		if strings.Contains(out, "\t") {
			t.Errorf("output contains a tab, want plain ASCII columns:\n%q", out)
		}
		for _, r := range out {
			if r > 127 {
				t.Fatalf("output contains a non-ASCII rune %q:\n%s", r, out)
			}
		}
		t.Logf("rendered startup summary:\n%s", out)
	})

	t.Run("upstreams overrides", func(t *testing.T) {
		cfg := config.Default()
		cfg.Upstreams = config.Upstreams{
			"/v1":               "https://relay.example.com",
			"relay.example.com": "https://relay.example.com",
		}
		var buf bytes.Buffer
		writeStartupSummary(&buf, &cfg)
		out := buf.String()

		if !strings.Contains(out, "your upstreams: overrides:") {
			t.Fatalf("output missing the override block header:\n%s", out)
		}
		var pathLine, hostLine string
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "-> https://relay.example.com") {
				continue
			}
			if strings.Contains(line, "(path prefix)") {
				pathLine = line
			}
			if strings.Contains(line, "(host)") {
				hostLine = line
			}
		}
		if !strings.Contains(pathLine, "/v1") {
			t.Errorf("path override line = %q, want the /v1 key with a (path prefix) label", pathLine)
		}
		if !strings.Contains(hostLine, "relay.example.com") {
			t.Errorf("host override line = %q, want the relay.example.com key with a (host) label", hostLine)
		}

		if !strings.Contains(out, "/v1/chat/completions") {
			t.Errorf("override output dropped the built-in table:\n%s", out)
		}

		empty := config.Default()
		empty.Upstreams = config.Upstreams{}
		var emptyBuf bytes.Buffer
		writeStartupSummary(&emptyBuf, &empty)
		if strings.Contains(emptyBuf.String(), "your upstreams: overrides:") {
			t.Errorf("empty upstreams map still rendered the override block:\n%s", emptyBuf.String())
		}
	})

	t.Run("no port skips onboarding", func(t *testing.T) {
		cfg := config.Default()
		cfg.Listen.Port = 0
		var buf bytes.Buffer
		writeStartupSummary(&buf, &cfg)
		out := buf.String()

		for _, absent := range []string{"point a tool at the gateway", "tokenhush env", "http://127.0.0.1"} {
			if strings.Contains(out, absent) {
				t.Errorf("port 0 output unexpectedly contains %q:\n%s", absent, out)
			}
		}
		if !strings.Contains(out, "upstream routes") {
			t.Errorf("port 0 output dropped the route table:\n%s", out)
		}
		for _, path := range builtinPaths {
			if !strings.Contains(out, path) {
				t.Errorf("port 0 output missing built-in path %q:\n%s", path, out)
			}
		}
	})

	t.Run("nil writer and nil config do not panic", func(t *testing.T) {
		cfg := config.Default()
		writeStartupSummary(nil, &cfg)
		writeStartupSummary(nil, nil)
		var buf bytes.Buffer
		writeStartupSummary(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("nil config wrote %d bytes, want none", buf.Len())
		}
	})
}
