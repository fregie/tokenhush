package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/platform"
)

func init() { register("env", envCommand) }

// envTools lists the client tools `tokenhush env <tool>` can onboard, in the
// frozen order. Exactly these fourteen are supported. Roo Code shares Cline's
// OpenAI-compatible configuration (Roo is a Cline fork), so both render the
// same snippet body.
var envTools = []string{
	"claude", "codex", "aider", "cline", "roo",
	"opencode", "qwen", "crush", "zed", "continue", "openwebui", "goose", "openhands", "kilo",
}

// shellMode selects the shell dialect of the environment-variable snippets.
type shellMode int

const (
	shellPOSIX shellMode = iota
	shellPowerShell
)

// defaultShellMode detects the dialect: Windows means PowerShell, and a
// PowerShell host on any OS is detected from its environment.
func defaultShellMode() shellMode {
	if runtime.GOOS == "windows" {
		return shellPowerShell
	}
	shell := strings.ToLower(os.Getenv("SHELL") + os.Getenv("PSModulePath"))
	if strings.Contains(shell, "powershell") || strings.Contains(shell, "pwsh") {
		return shellPowerShell
	}
	return shellPOSIX
}

// envCommand is the CLI entry for `tokenhush env <tool>`.
func envCommand(args []string, stdout, stderr io.Writer) int {
	return envCommandWith(args, stdout, stderr, defaultShellMode, loadToolConfig)
}

// envCommandWith carries the injectable seams: the shell-mode accessor and the
// config loader. Tests pin both.
func envCommandWith(args []string, stdout, stderr io.Writer, mode func() shellMode, load func(string) (config.Config, error)) int {
	flags := flag.NewFlagSet("env", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		configPath string
		port       int
	)
	flags.StringVar(&configPath, "config", "", "path to tokenhush.yaml (default: the platform config dir)")
	flags.IntVar(&port, "port", 0, "override the listen port (1..65535)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: tokenhush env [--port N] [--config PATH] <tool>")
		envSupportedTools(stderr)
		return exitUsage
	}
	tool := flags.Arg(0)
	if !slices.Contains(envTools, tool) {
		fmt.Fprintf(stderr, "tokenhush: env: unknown tool %q\n", tool)
		envSupportedTools(stderr)
		return exitUsage
	}
	if port < 0 || port > 65535 {
		fmt.Fprintf(stderr, "tokenhush: env: --port %d is outside 1..65535\n", port)
		return exitUsage
	}
	cfg, err := load(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: env: %v\n", err)
		return exitFailure
	}
	effective := cfg.Listen.Port
	if port != 0 {
		effective = port
	}
	snippet, ok := envSnippet(tool, mode(), effective)
	if !ok {
		fmt.Fprintf(stderr, "tokenhush: env: unknown tool %q\n", tool)
		envSupportedTools(stderr)
		return exitUsage
	}
	fmt.Fprint(stdout, snippet)
	return exitOK
}

// loadToolConfig resolves the config the same way run does: an explicit path
// wins, otherwise the platform config file (a missing file means defaults).
func loadToolConfig(path string) (config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	dir, err := platform.ConfigDir()
	if err != nil {
		return config.Config{}, err
	}
	return config.Load(filepath.Join(dir, "tokenhush.yaml"))
}

// envSupportedTools prints the supported list after a usage error.
func envSupportedTools(stderr io.Writer) {
	fmt.Fprintf(stderr, "supported tools: %s\n", strings.Join(envTools, ", "))
}

// envSnippet renders the onboarding snippet for tool in the given shell
// dialect, pointing every base URL at the loopback gateway on port.
//
// All snippets are plain text (shell commands, a TOML line, JSON or UI steps)
// so they can be pasted directly. The base URL split is the frozen loopback
// endpoint semantics: Anthropic-style clients take the bare origin, and
// OpenAI-compatible clients take the /v1 prefix.
func envSnippet(tool string, mode shellMode, port int) (string, bool) {
	root := fmt.Sprintf("http://127.0.0.1:%d", port)
	openAI := root + "/v1"
	switch tool {
	case "claude":
		return "# Claude Code: run this before launching `claude`.\n" +
			envVars(mode, [][2]string{{"ANTHROPIC_BASE_URL", root}}), true
	case "codex":
		path := "~/.codex/config.toml"
		if mode == shellPowerShell {
			path = `%USERPROFILE%\.codex\config.toml`
		}
		return fmt.Sprintf("# Codex CLI: add this to %s (API key mode; the ChatGPT subscription login cannot pass through the gateway).\n"+
			"model_providers.tokenhush = { name = \"Tokenhush\", base_url = %q }\n", path, openAI), true
	case "aider":
		return "# Aider: run this before launching `aider`.\n" +
			envVars(mode, [][2]string{{"OPENAI_API_BASE", openAI}, {"ANTHROPIC_API_BASE", root}}), true
	case "cline", "roo":
		name := "Cline"
		if tool == "roo" {
			name = "Roo Code"
		}
		return fmt.Sprintf("%s (VS Code): Settings -> API Provider -> \"OpenAI Compatible\"\nBase URL: %s\n", name, openAI), true
	case "opencode":
		return fmt.Sprintf("# opencode: add this provider to opencode.json (OpenAI-compatible).\n"+
			"{\n"+
			"  \"$schema\": \"https://opencode.ai/config.json\",\n"+
			"  \"provider\": {\n"+
			"    \"tokenhush\": {\n"+
			"      \"npm\": \"@ai-sdk/openai-compatible\",\n"+
			"      \"name\": \"Tokenhush\",\n"+
			"      \"options\": { \"baseURL\": %q }\n"+
			"    }\n"+
			"  }\n"+
			"}\n", openAI), true
	case "qwen":
		return "# Qwen Code: run this before launching `qwen`.\n" +
			envVars(mode, [][2]string{{"OPENAI_BASE_URL", openAI}, {"ANTHROPIC_BASE_URL", root}}), true
	case "crush":
		return fmt.Sprintf("# Charm Crush: add this provider to crush.json.\n"+
			"{\n"+
			"  \"$schema\": \"https://charm.land/crush.json\",\n"+
			"  \"providers\": {\n"+
			"    \"tokenhush\": {\n"+
			"      \"type\": \"openai\",\n"+
			"      \"base_url\": %q\n"+
			"    }\n"+
			"  }\n"+
			"}\n", openAI), true
	case "zed":
		return fmt.Sprintf("# Zed: add this provider to settings.json (openai_compatible).\n"+
			"{\n"+
			"  \"language_models\": {\n"+
			"    \"openai_compatible\": {\n"+
			"      \"tokenhush\": { \"api_url\": %q }\n"+
			"    }\n"+
			"  }\n"+
			"}\n", openAI), true
	case "continue":
		return fmt.Sprintf("# Continue.dev: add this model to ~/.continue/config.yaml.\n"+
			"# Older Continue builds use config.json with the same apiBase key.\n"+
			"models:\n"+
			"  - name: tokenhush\n"+
			"    provider: openai\n"+
			"    apiBase: %q\n", openAI), true
	case "openwebui":
		return "# Open WebUI: set this before starting the server (Connections pick it up).\n" +
			envVars(mode, [][2]string{{"OPENAI_API_BASE_URL", openAI}}), true
	case "goose":
		return "# Goose: run this before launching `goose` (host and /v1 path are separate).\n" +
			envVars(mode, [][2]string{{"OPENAI_HOST", root}, {"OPENAI_BASE_PATH", "v1"}}), true
	case "openhands":
		return "# OpenHands: run this before launching OpenHands, or set [llm].base_url.\n" +
			envVars(mode, [][2]string{{"LLM_BASE_URL", openAI}}), true
	case "kilo":
		return fmt.Sprintf("Kilo Code (VS Code): Settings -> API Provider -> \"OpenAI Compatible\"\nBase URL: %s\n", openAI), true
	default:
		return "", false
	}
}

// envVars renders environment assignments in the dialect of mode. POSIX uses
// `export` for the current shell; PowerShell sets the current session with
// `$env:` and also prints the persistent `setx` form.
func envVars(mode shellMode, vars [][2]string) string {
	var builder strings.Builder
	powerShell := mode == shellPowerShell
	for _, pair := range vars {
		if powerShell {
			fmt.Fprintf(&builder, "$env:%s = %q\n", pair[0], pair[1])
		} else {
			fmt.Fprintf(&builder, "export %s=%q\n", pair[0], pair[1])
		}
	}
	if powerShell {
		builder.WriteString("# persist for new terminals:\n")
		for _, pair := range vars {
			fmt.Fprintf(&builder, "setx %s %q\n", pair[0], pair[1])
		}
	}
	return builder.String()
}
