package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
)

// errConfigBoom stands in for an unreadable config file.
var errConfigBoom = errors.New("boom")

// envTestLoader returns a config with the given port and no error.
func envTestLoader(port int) func(string) (config.Config, error) {
	return func(string) (config.Config, error) {
		cfg := config.Default()
		cfg.Listen.Port = port
		return cfg, nil
	}
}

// TestEnvToolsAreExactlyFourteen pins the frozen tool count and list.
func TestEnvToolsAreExactlyFourteen(t *testing.T) {
	if len(envTools) != 14 {
		t.Fatalf("envTools has %d entries, want exactly 14: %v", len(envTools), envTools)
	}
}

// TestEnvSnippetsUseTheRightBaseURL walks all fourteen tools: each must emit
// its tool name, and the loopback endpoint semantics must hold -- a bare
// origin for Anthropic-style clients, the /v1 prefix for OpenAI-compatible
// ones.
func TestEnvSnippetsUseTheRightBaseURL(t *testing.T) {
	cases := []struct {
		tool    string
		want    []string
		notWant []string
	}{
		{"claude", []string{`export ANTHROPIC_BASE_URL="http://127.0.0.1:9999"`}, []string{"127.0.0.1:9999/v1"}},
		{"codex", []string{`base_url = "http://127.0.0.1:9999/v1"`, "config.toml"}, nil},
		{"aider", []string{`export OPENAI_API_BASE="http://127.0.0.1:9999/v1"`, `export ANTHROPIC_API_BASE="http://127.0.0.1:9999"`}, nil},
		{"cline", []string{"Base URL: http://127.0.0.1:9999/v1"}, nil},
		{"roo", []string{"Roo Code", "Base URL: http://127.0.0.1:9999/v1"}, nil},
		{"opencode", []string{`"baseURL": "http://127.0.0.1:9999/v1"`}, nil},
		{"qwen", []string{`export OPENAI_BASE_URL="http://127.0.0.1:9999/v1"`, `export ANTHROPIC_BASE_URL="http://127.0.0.1:9999"`}, nil},
		{"crush", []string{`"base_url": "http://127.0.0.1:9999/v1"`}, nil},
		{"zed", []string{`"api_url": "http://127.0.0.1:9999/v1"`}, nil},
		{"continue", []string{`apiBase: "http://127.0.0.1:9999/v1"`}, nil},
		{"openwebui", []string{`export OPENAI_API_BASE_URL="http://127.0.0.1:9999/v1"`}, nil},
		{"goose", []string{`export OPENAI_HOST="http://127.0.0.1:9999"`, `export OPENAI_BASE_PATH="v1"`}, nil},
		{"openhands", []string{`export LLM_BASE_URL="http://127.0.0.1:9999/v1"`}, nil},
		{"kilo", []string{"Base URL: http://127.0.0.1:9999/v1"}, nil},
	}
	if len(cases) != len(envTools) {
		t.Fatalf("the matrix covers %d tools, envTools has %d", len(cases), len(envTools))
	}
	posix := func() shellMode { return shellPOSIX }
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := envCommandWith([]string{tc.tool}, &stdout, &stderr, posix, envTestLoader(9999)); code != exitOK {
				t.Fatalf("env %s = %d, want %d (stderr %q)", tc.tool, code, exitOK, stderr.String())
			}
			snippet := stdout.String()
			for _, want := range tc.want {
				if !strings.Contains(snippet, want) {
					t.Errorf("env %s snippet %q is missing %q", tc.tool, snippet, want)
				}
			}
			for _, unwanted := range tc.notWant {
				if strings.Contains(snippet, unwanted) {
					t.Errorf("env %s snippet %q unexpectedly carries %q", tc.tool, snippet, unwanted)
				}
			}
		})
	}
}

// TestEnvShellDialect pins the two dialects: POSIX exports, PowerShell sets
// the session variable and the persistent value.
func TestEnvShellDialect(t *testing.T) {
	posix := func() shellMode { return shellPOSIX }
	var stdout, stderr bytes.Buffer
	if code := envCommandWith([]string{"claude"}, &stdout, &stderr, posix, envTestLoader(8787)); code != exitOK {
		t.Fatalf("posix env = %d, want %d", code, exitOK)
	}
	if got := stdout.String(); !strings.Contains(got, `export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"`) {
		t.Errorf("posix snippet = %q, want an export line", got)
	}

	powerShell := func() shellMode { return shellPowerShell }
	stdout.Reset()
	stderr.Reset()
	if code := envCommandWith([]string{"claude"}, &stdout, &stderr, powerShell, envTestLoader(8787)); code != exitOK {
		t.Fatalf("powershell env = %d, want %d", code, exitOK)
	}
	got := stdout.String()
	for _, want := range []string{`$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"`, "setx ANTHROPIC_BASE_URL"} {
		if !strings.Contains(got, want) {
			t.Errorf("powershell snippet = %q, want %q", got, want)
		}
	}
	if strings.Contains(got, "export ") {
		t.Errorf("powershell snippet = %q, want no POSIX export", got)
	}
}

// TestEnvUnknownToolExitsTwo pins the usage error and the supported list.
func TestEnvUnknownToolExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := envCommandWith([]string{"nosuchtool"}, &stdout, &stderr, defaultShellMode, envTestLoader(8787))
	if code != exitUsage {
		t.Fatalf("env nosuchtool = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "supported tools:") {
		t.Errorf("stderr = %q, want the supported list", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
}

// TestEnvPortFlagOverridesConfig pins the port precedence and the bad-value
// usage error.
func TestEnvPortFlagOverridesConfig(t *testing.T) {
	posix := func() shellMode { return shellPOSIX }
	var stdout, stderr bytes.Buffer
	code := envCommandWith([]string{"--port", "4321", "claude"}, &stdout, &stderr, posix, envTestLoader(8787))
	if code != exitOK {
		t.Fatalf("env --port = %d, want %d (stderr %q)", code, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "http://127.0.0.1:4321") {
		t.Errorf("snippet = %q, want the flag port", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := envCommandWith([]string{"--port", "70000", "claude"}, &stdout, &stderr, posix, envTestLoader(8787)); code != exitUsage {
		t.Fatalf("env --port 70000 = %d, want %d", code, exitUsage)
	}
}

// TestEnvMissingToolIsUsage pins the argument-count check.
func TestEnvMissingToolIsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := envCommandWith(nil, &stdout, &stderr, defaultShellMode, envTestLoader(8787)); code != exitUsage {
		t.Fatalf("env (no tool) = %d, want %d", code, exitUsage)
	}
}

// TestEnvConfigFailureExitsOne pins that a broken config is a failure, not a
// usage error.
func TestEnvConfigFailureExitsOne(t *testing.T) {
	loader := func(string) (config.Config, error) { return config.Config{}, errConfigBoom }
	var stdout, stderr bytes.Buffer
	if code := envCommandWith([]string{"claude"}, &stdout, &stderr, defaultShellMode, loader); code != exitFailure {
		t.Fatalf("env with a broken config = %d, want %d", code, exitFailure)
	}
}
