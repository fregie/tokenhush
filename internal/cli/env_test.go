package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// resolveMatrixHost is the Host a local tool presents to the gateway; the route
// matrix exercises path routing, so a loopback Host keeps it realistic.
const resolveMatrixHost = "127.0.0.1:8787"

// envTestTools mirrors the tools `tokenhush env <tool>` advertises. W6.1's
// acceptance is per tool/OS pair: every pair must render a snippet that
// contains the configured port. The nine A-group tools added by WA.5 are
// covered here and by TestToolRouteMatrix (route reachability).
var envTestTools = []string{
	"claude", "codex", "aider", "cline", "roo",
	"opencode", "qwen", "crush", "zed", "continue", "openwebui", "goose", "openhands", "kilo",
}

// envTestModes pins both shell dialects deterministically, independent of the
// host the tests run on.
var envTestModes = []struct {
	name string
	mode platform.ShellMode
}{
	{"posix", platform.ShellPOSIX},
	{"powershell", platform.ShellPowerShell},
}

func envTestPOSIX() platform.ShellMode { return platform.ShellPOSIX }

func envTestPowerShell() platform.ShellMode { return platform.ShellPowerShell }

// envTestConfig returns the V1 defaults, so command-level tests never read the
// host's real tokenhush.yaml.
func envTestConfig(string) (*config.Config, error) {
	cfg := config.Default()
	return &cfg, nil
}

func mustContain(t *testing.T, snippet, want string) {
	t.Helper()
	if !strings.Contains(snippet, want) {
		t.Errorf("snippet does not contain %q:\n%s", want, snippet)
	}
}

func mustNotContain(t *testing.T, snippet, banned string) {
	t.Helper()
	if strings.Contains(snippet, banned) {
		t.Errorf("snippet unexpectedly contains %q:\n%s", banned, snippet)
	}
}

// TestEnvSnippets covers all five tools x both shell dialects (the task's
// "each tool/OS pair" matrix). Snippets are logged so `go test -v` output is
// the evidence that both dialects render correctly on any host.
func TestEnvSnippets(t *testing.T) {
	const port = config.Port(8787)

	for _, tool := range envTestTools {
		for _, m := range envTestModes {
			t.Run(tool+"/"+m.name, func(t *testing.T) {
				snippet, err := envSnippet(tool, m.mode, port)
				if err != nil {
					t.Fatalf("envSnippet(%q, %q, %d) error: %v", tool, m.mode, port, err)
				}
				t.Logf("snippet for %s (%s):\n%s", tool, m.name, snippet)

				mustContain(t, snippet, "127.0.0.1:8787")

				switch tool {
				case "claude":
					mustContain(t, snippet, "ANTHROPIC_BASE_URL")
					if m.mode == platform.ShellPOSIX {
						mustContain(t, snippet, `export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"`)
					} else {
						mustContain(t, snippet, `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"`)
						mustContain(t, snippet, `setx ANTHROPIC_BASE_URL "http://127.0.0.1:8787"`)
					}
				case "codex":
					mustContain(t, snippet, `model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }`)
					if m.mode == platform.ShellPOSIX {
						mustContain(t, snippet, "~/.codex/config.toml")
					} else {
						mustContain(t, snippet, `%USERPROFILE%\.codex\config.toml`)
					}
				case "aider":
					if m.mode == platform.ShellPOSIX {
						mustContain(t, snippet, `export OPENAI_API_BASE="http://127.0.0.1:8787/v1"`)
						mustContain(t, snippet, `export ANTHROPIC_API_BASE="http://127.0.0.1:8787"`)
					} else {
						mustContain(t, snippet, `$env:OPENAI_API_BASE = "http://127.0.0.1:8787/v1"`)
						mustContain(t, snippet, `$env:ANTHROPIC_API_BASE = "http://127.0.0.1:8787"`)
						mustContain(t, snippet, `setx OPENAI_API_BASE "http://127.0.0.1:8787/v1"`)
						mustContain(t, snippet, `setx ANTHROPIC_API_BASE "http://127.0.0.1:8787"`)
					}
				case "cline", "roo":
					// Roo Code reuses Cline's OpenAI-compatible configuration.
					mustContain(t, snippet, "Base URL: http://127.0.0.1:8787/v1")
					if tool == "roo" {
						mustContain(t, snippet, "Roo Code")
					} else {
						mustContain(t, snippet, "Cline")
					}
				case "opencode":
					mustContain(t, snippet, `"baseURL": "http://127.0.0.1:8787/v1"`)
					mustContain(t, snippet, "opencode.json")
				case "qwen":
					mustContain(t, snippet, "OPENAI_BASE_URL")
					mustContain(t, snippet, "ANTHROPIC_BASE_URL")
					if m.mode == platform.ShellPOSIX {
						mustContain(t, snippet, `export OPENAI_BASE_URL="http://127.0.0.1:8787/v1"`)
						mustContain(t, snippet, `export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"`)
					} else {
						mustContain(t, snippet, `$env:OPENAI_BASE_URL = "http://127.0.0.1:8787/v1"`)
						mustContain(t, snippet, `setx OPENAI_BASE_URL "http://127.0.0.1:8787/v1"`)
					}
				case "crush":
					mustContain(t, snippet, `"base_url": "http://127.0.0.1:8787/v1"`)
					mustContain(t, snippet, "crush.json")
				case "zed":
					mustContain(t, snippet, `"api_url": "http://127.0.0.1:8787/v1"`)
				case "continue":
					mustContain(t, snippet, `apiBase: "http://127.0.0.1:8787/v1"`)
					mustContain(t, snippet, "config.yaml")
				case "openwebui":
					mustContain(t, snippet, "OPENAI_API_BASE_URL")
					if m.mode == platform.ShellPOSIX {
						mustContain(t, snippet, `export OPENAI_API_BASE_URL="http://127.0.0.1:8787/v1"`)
					} else {
						mustContain(t, snippet, `$env:OPENAI_API_BASE_URL = "http://127.0.0.1:8787/v1"`)
					}
				case "goose":
					mustContain(t, snippet, "OPENAI_HOST")
					mustContain(t, snippet, "OPENAI_BASE_PATH")
					if m.mode == platform.ShellPOSIX {
						mustContain(t, snippet, `export OPENAI_HOST="http://127.0.0.1:8787"`)
						mustContain(t, snippet, `export OPENAI_BASE_PATH="v1"`)
					} else {
						mustContain(t, snippet, `$env:OPENAI_HOST = "http://127.0.0.1:8787"`)
						mustContain(t, snippet, `$env:OPENAI_BASE_PATH = "v1"`)
					}
				case "openhands":
					mustContain(t, snippet, "LLM_BASE_URL")
					if m.mode == platform.ShellPOSIX {
						mustContain(t, snippet, `export LLM_BASE_URL="http://127.0.0.1:8787/v1"`)
					} else {
						mustContain(t, snippet, `$env:LLM_BASE_URL = "http://127.0.0.1:8787/v1"`)
					}
				case "kilo":
					mustContain(t, snippet, "Base URL: http://127.0.0.1:8787/v1")
					mustContain(t, snippet, "Kilo Code")
				}

				// Dialect hygiene: shell syntax only where the tool consumes
				// environment variables; config-file/UI tools must stay plain.
				if m.mode == platform.ShellPOSIX {
					mustNotContain(t, snippet, "$env:")
					mustNotContain(t, snippet, "setx ")
				} else {
					mustNotContain(t, snippet, "export ")
				}
				switch tool {
				case "codex", "cline", "roo", "opencode", "crush", "zed", "continue", "kilo":
					// Config-file / UI tools consume no environment variables, so
					// no shell dialect may leak into their snippet.
					mustNotContain(t, snippet, "export ")
					mustNotContain(t, snippet, "$env:")
					mustNotContain(t, snippet, "setx ")
				}
			})
		}
	}
}

// TestEnvSnippetsUnknownTool is the unit-level guard for the CLI's supported
// list; TestEnvSnippetsBadTool drives the same path through the command.
func TestEnvSnippetsUnknownTool(t *testing.T) {
	if _, err := envSnippet("cursor", platform.ShellPOSIX, 8787); err == nil {
		t.Fatal("envSnippet(\"cursor\", ...) error = nil, want an unknown-tool error")
	}
}

// TestEnvSnippetsCommand drives envCommandWith with a pinned dialect and
// config, asserting exit codes and the port actually rendered.
func TestEnvSnippetsCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStdout []string
		wantCode   int
	}{
		{"claude default port", []string{"claude"}, []string{"ANTHROPIC_BASE_URL", "127.0.0.1:8787"}, ExitOK},
		{"codex port override", []string{"--port", "9123", "codex"}, []string{"base_url", "127.0.0.1:9123/v1"}, ExitOK},
		{"aider both variables", []string{"aider"}, []string{"OPENAI_API_BASE", "ANTHROPIC_API_BASE"}, ExitOK},
		{"cline", []string{"cline"}, []string{"Base URL: http://127.0.0.1:8787/v1"}, ExitOK},
		{"roo maps to cline config", []string{"roo"}, []string{"Roo Code", "Base URL: http://127.0.0.1:8787/v1"}, ExitOK},
		{"opencode baseURL", []string{"opencode"}, []string{"opencode.json", `"baseURL": "http://127.0.0.1:8787/v1"`}, ExitOK},
		{"qwen both variables", []string{"qwen"}, []string{"OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"}, ExitOK},
		{"crush base_url", []string{"crush"}, []string{"crush.json", `"base_url": "http://127.0.0.1:8787/v1"`}, ExitOK},
		{"zed api_url", []string{"zed"}, []string{`"api_url": "http://127.0.0.1:8787/v1"`}, ExitOK},
		{"continue config.yaml", []string{"continue"}, []string{"config.yaml", `apiBase: "http://127.0.0.1:8787/v1"`}, ExitOK},
		{"openwebui base url", []string{"openwebui"}, []string{"OPENAI_API_BASE_URL", "127.0.0.1:8787/v1"}, ExitOK},
		{"goose host and path", []string{"goose"}, []string{"OPENAI_HOST", "OPENAI_BASE_PATH", `OPENAI_BASE_PATH="v1"`}, ExitOK},
		{"openhands llm base", []string{"openhands"}, []string{"LLM_BASE_URL", "127.0.0.1:8787/v1"}, ExitOK},
		{"kilo custom provider", []string{"kilo"}, []string{"Kilo Code", "Base URL: http://127.0.0.1:8787/v1"}, ExitOK},
		{"opencode port override", []string{"--port", "9123", "opencode"}, []string{`"baseURL": "http://127.0.0.1:9123/v1"`}, ExitOK},
		{"port lower bound", []string{"--port", "1", "claude"}, []string{"127.0.0.1:1"}, ExitOK},
		{"port upper bound", []string{"--port", "65535", "claude"}, []string{"127.0.0.1:65535"}, ExitOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := envCommandWith(tt.args, &stdout, &stderr, envTestPOSIX, envTestConfig)
			if code != tt.wantCode {
				t.Fatalf("envCommandWith(%q) = %d, want %d (stderr: %s)", tt.args, code, tt.wantCode, stderr.String())
			}
			for _, want := range tt.wantStdout {
				mustContain(t, stdout.String(), want)
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

// TestEnvSnippetsPowerShellCommand proves the command path (not just the pure
// renderer) switches dialect through the injected platform seam.
func TestEnvSnippetsPowerShellCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := envCommandWith([]string{"aider"}, &stdout, &stderr, envTestPowerShell, envTestConfig)
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, ExitOK, stderr.String())
	}
	mustContain(t, stdout.String(), `$env:OPENAI_API_BASE = "http://127.0.0.1:8787/v1"`)
	mustContain(t, stdout.String(), `setx OPENAI_API_BASE "http://127.0.0.1:8787/v1"`)
	mustNotContain(t, stdout.String(), "export ")
}

// TestEnvSnippetsConfigPort proves the "configured port" comes from the
// tokenhush.yaml config when no --port override is given.
func TestEnvSnippetsConfigPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokenhush.yaml")
	if err := os.WriteFile(path, []byte("listen:\n  port: 9317\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := envCommandWith([]string{"--config", path, "claude"}, &stdout, &stderr, envTestPOSIX, config.LoadFile)
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, ExitOK, stderr.String())
	}
	mustContain(t, stdout.String(), `export ANTHROPIC_BASE_URL="http://127.0.0.1:9317"`)

	// An explicit --port wins over the config file.
	stdout.Reset()
	stderr.Reset()
	code = envCommandWith([]string{"--config", path, "--port", "9999", "claude"}, &stdout, &stderr, envTestPOSIX, config.LoadFile)
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, ExitOK, stderr.String())
	}
	mustContain(t, stdout.String(), `export ANTHROPIC_BASE_URL="http://127.0.0.1:9999"`)
	mustNotContain(t, stdout.String(), "9317")
}

// TestEnvSnippetsNativeMode exercises the production wiring end to end through
// Run: the dialect is platform.ShellSnippetMode() and the port defaults to
// 8787 because TOKENHUSH_HOME points at an empty directory.
func TestEnvSnippetsNativeMode(t *testing.T) {
	t.Setenv("TOKENHUSH_HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"env", "claude"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("Run(env claude) = %d, want %d (stderr: %s)", code, ExitOK, stderr.String())
	}
	mustContain(t, stdout.String(), "127.0.0.1:8787")
	if platform.ShellSnippetMode() == platform.ShellPowerShell {
		mustContain(t, stdout.String(), "$env:ANTHROPIC_BASE_URL")
	} else {
		mustContain(t, stdout.String(), "export ANTHROPIC_BASE_URL")
	}
}

// TestEnvSnippetsBadTool asserts the adversarial contract: an unknown tool
// exits non-zero, prints nothing on stdout and lists the supported tools.
func TestEnvSnippetsBadTool(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := envCommandWith([]string{"cursor"}, &stdout, &stderr, envTestPOSIX, envTestConfig)
	if code == ExitOK {
		t.Fatal("unknown tool exited 0, want non-zero")
	}
	if code != ExitUsage {
		t.Errorf("unknown tool exit = %d, want %d", code, ExitUsage)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	mustContain(t, stderr.String(), `unknown tool "cursor"`)
	mustContain(t, stderr.String(), "supported tools: claude, codex, aider, cline, roo, opencode, qwen, crush, zed, continue, openwebui, goose, openhands, kilo")
}

// TestEnvSnippetsUsage covers missing and extra arguments plus an invalid
// --port; all are usage errors that must not print a snippet.
func TestEnvSnippetsUsage(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantError []string
	}{
		{"missing tool", nil, []string{"usage: tokenhush env", "supported tools:"}},
		{"extra argument", []string{"claude", "codex"}, []string{`unexpected argument "codex"`, "usage: tokenhush env"}},
		{"flags after tool", []string{"claude", "--port", "9123"}, []string{`unexpected argument "--port"`, "usage: tokenhush env"}},
		{"port too large", []string{"--port", "70000", "claude"}, []string{"--port must be in 1..65535"}},
		{"port negative", []string{"--port", "-5", "claude"}, []string{"--port must be in 1..65535"}},
		{"unknown flag", []string{"--bogus", "claude"}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := envCommandWith(tt.args, &stdout, &stderr, envTestPOSIX, envTestConfig)
			if code != ExitUsage {
				t.Fatalf("envCommandWith(%q) = %d, want %d (stderr: %s)", tt.args, code, ExitUsage, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			for _, want := range tt.wantError {
				mustContain(t, stderr.String(), want)
			}
		})
	}
}

// TestEnvSnippetsConfigError asserts a broken config fails with ExitFailure
// (not a usage error) and never prints a snippet.
func TestEnvSnippetsConfigError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokenhush.yaml")
	if err := os.WriteFile(path, []byte("listen: [oops\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := envCommandWith([]string{"--config", path, "claude"}, &stdout, &stderr, envTestPOSIX, config.LoadFile)
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, ExitFailure, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	mustContain(t, stderr.String(), "tokenhush: env:")
}

// envToolRoute is one actual request path an onboarded agent tool sends once
// its snippet points the tool at the gateway, plus the provider the gateway
// must resolve it to.
type envToolRoute struct {
	path     string
	provider string
	base     string
}

// envToolRoutes is the route-reachability matrix for every tool `tokenhush env`
// onboards. The paths are the concrete requests each integration issues once
// the snippet's base URL is applied, and each must resolve via proxy.Resolve.
// The A-group tools added by WA.5 all speak a protocol the gateway already
// routes, so none are unreachable today. A tool that needs a protocol outside
// the built-in table (for example Google GenAI generateContent) must instead be
// listed in envUnverifiedTools with a reason and documented as "未验证" in
// docs/configuration.md, until the gateway routes it.
var envToolRoutes = map[string][]envToolRoute{
	"claude": {{path: "/v1/messages", provider: proxy.ProviderAnthropic, base: proxy.AnthropicBaseURL}},
	"codex":  {{path: "/v1/responses", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL}},
	"aider":  {{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL}},
	"cline":  {{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL}},
	"roo":    {{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL}},
	"opencode": {
		{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
		{path: "/v1/models", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
	},
	"qwen": {
		{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
		{path: "/v1/messages", provider: proxy.ProviderAnthropic, base: proxy.AnthropicBaseURL},
	},
	"crush": {{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL}},
	"zed": {
		{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
		{path: "/v1/models", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
	},
	"continue": {
		{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
		{path: "/v1/models", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
	},
	"openwebui": {
		// Model picker hits /v1/models, reachable only because of the WA.4
		// named exception; chat then goes to /v1/chat/completions.
		{path: "/v1/models", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
		{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
	},
	"goose":     {{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL}},
	"openhands": {{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL}},
	"kilo": {
		{path: "/v1/chat/completions", provider: proxy.ProviderOpenAI, base: proxy.OpenAIBaseURL},
		{path: "/v1/messages", provider: proxy.ProviderAnthropic, base: proxy.AnthropicBaseURL},
	},
}

// envUnverifiedTools maps a tool whose request path cannot be network-verified
// against the current routing table to the reason it is marked "未验证". Empty
// today: every A-group tool speaks Chat Completions, Messages, Responses, or
// model discovery, all reachable (the last via the WA.4 named exception).
var envUnverifiedTools = map[string]string{}

// TestToolRouteMatrix asserts the route-reachability matrix: for every tool the
// `env` command onboards, each concrete request path its integration sends must
// resolve through proxy.Resolve to the expected provider and base URL. Tools
// that cannot be reached must be listed in envUnverifiedTools with a reason, so
// an untestable integration is explicit instead of silently missing.
func TestToolRouteMatrix(t *testing.T) {
	resolver := proxy.NewResolver(nil, nil)

	for _, tool := range envTools {
		routes, verified := envToolRoutes[tool]
		reason, unverified := envUnverifiedTools[tool]
		switch {
		case verified && unverified:
			t.Errorf("tool %q is in both envToolRoutes and envUnverifiedTools", tool)
		case !verified && !unverified:
			t.Errorf("tool %q is in neither envToolRoutes nor envUnverifiedTools", tool)
		case unverified && strings.TrimSpace(reason) == "":
			t.Errorf("tool %q is marked 未验证 without a reason", tool)
		}
		if !verified {
			t.Logf("tool %q: 未验证 (%s)", tool, reason)
			continue
		}
		for _, route := range routes {
			got, err := resolver.Resolve(&extension.Request{Method: "POST", Host: resolveMatrixHost, Path: route.path})
			if err != nil {
				t.Errorf("tool %q path %q did not resolve: %v", tool, route.path, err)
				continue
			}
			if got.Name != route.provider || got.BaseURL != route.base {
				t.Errorf("tool %q path %q = %+v, want {Name:%q BaseURL:%q}", tool, route.path, got, route.provider, route.base)
				continue
			}
			t.Logf("tool %q path %q -> %s %s", tool, route.path, got.Name, got.BaseURL)
		}
	}

	for tool := range envToolRoutes {
		if !slices.Contains(envTools, tool) {
			t.Errorf("envToolRoutes has tool %q not advertised by envTools", tool)
		}
	}
	for tool := range envUnverifiedTools {
		if !slices.Contains(envTools, tool) {
			t.Errorf("envUnverifiedTools has tool %q not advertised by envTools", tool)
		}
	}
}
