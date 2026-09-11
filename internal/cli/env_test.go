package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/platform"
)

// envTestTools mirrors the tools `tokenhush env <tool>` advertises. W6.1's
// acceptance is per tool/OS pair: every pair must render a snippet that
// contains the configured port.
var envTestTools = []string{"claude", "codex", "aider", "cline", "roo"}

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
				}

				// Dialect hygiene: shell syntax only where the tool consumes
				// environment variables; config-file/UI tools must stay plain.
				if m.mode == platform.ShellPOSIX {
					mustNotContain(t, snippet, "$env:")
					mustNotContain(t, snippet, "setx ")
				} else {
					mustNotContain(t, snippet, "export ")
				}
				if tool == "codex" || tool == "cline" || tool == "roo" {
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
	mustContain(t, stderr.String(), "supported tools: claude, codex, aider, cline, roo")
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
