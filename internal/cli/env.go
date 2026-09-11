package cli

import (
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/platform"
)

// envTools lists the client tools `tokenhush env <tool>` can onboard, in the
// order usage and error messages advertise them. Roo Code shares Cline's
// OpenAI-compatible configuration (Roo is a Cline fork), so both render the
// same snippet body.
var envTools = []string{"claude", "codex", "aider", "cline", "roo"}

// envCommand is the CLI entry for `tokenhush env <tool>` (docs/12 §6). It
// resolves the configured port (tokenhush.yaml or --port), then prints a
// copy-pasteable snippet for the host's shell dialect.
func envCommand(args []string, stdout, stderr io.Writer) int {
	return envCommandWith(args, stdout, stderr, platform.ShellSnippetMode, envLoadConfig)
}

// envLoadConfig mirrors the run command's config resolution: an explicit path
// wins, otherwise the platform config file (a missing file means defaults).
func envLoadConfig(path string) (*config.Config, error) {
	if path != "" {
		return config.LoadFile(path)
	}
	return config.Load()
}

// envCommandWith carries the injectable seams of envCommand: the shell-mode
// accessor (production: platform.ShellSnippetMode) and the config loader
// (production: config.Load/LoadFile). Tests pin both exhaustively.
func envCommandWith(
	args []string,
	stdout, stderr io.Writer,
	shellMode func() platform.ShellMode,
	loadConfig func(string) (*config.Config, error),
) int {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath string
		port       int
	)
	fs.StringVar(&configPath, "config", "", "path to tokenhush.yaml (default: platform config dir)")
	fs.IntVar(&port, "port", 0, "override listen port (1..65535)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		envUsage(stderr, fs.Args())
		return ExitUsage
	}

	tool := fs.Arg(0)
	if !slices.Contains(envTools, tool) {
		envUnknownTool(stderr, tool)
		return ExitUsage
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: env: %v\n", err)
		return ExitFailure
	}
	effective := cfg.Listen.Port
	if port != 0 {
		if port < 1 || port > 65535 {
			fmt.Fprintln(stderr, "tokenhush: env: --port must be in 1..65535")
			return ExitUsage
		}
		effective = config.Port(port)
	}

	snippet, err := envSnippet(tool, shellMode(), effective)
	if err != nil {
		// Defense in depth: envSnippet validates the same list as
		// envTools, so this is unreachable in production.
		envUnknownTool(stderr, tool)
		return ExitUsage
	}
	fmt.Fprint(stdout, snippet)
	return ExitOK
}

// envUsage prints the usage line and supported list for malformed invocations.
func envUsage(stderr io.Writer, args []string) {
	if len(args) > 1 {
		fmt.Fprintf(stderr, "tokenhush: env: unexpected argument %q\n", args[1])
	}
	fmt.Fprintln(stderr, "usage: tokenhush env [--port N] [--config PATH] <tool>")
	envSupportedTools(stderr)
}

// envUnknownTool reports an unsupported tool together with the supported list.
func envUnknownTool(stderr io.Writer, tool string) {
	fmt.Fprintf(stderr, "tokenhush: env: unknown tool %q\n", tool)
	envSupportedTools(stderr)
}

func envSupportedTools(stderr io.Writer) {
	fmt.Fprintf(stderr, "supported tools: %s\n", strings.Join(envTools, ", "))
}

// envSnippet renders the onboarding snippet for tool in the given shell
// dialect, pointing every base URL at the loopback gateway on port.
//
// All snippets are plain text (shell commands, a TOML line, or UI steps) so
// they can be pasted directly. The base URL split follows the client's
// expectations: Anthropic clients take the bare origin, OpenAI-compatible
// clients take /v1 (docs/configuration.md).
func envSnippet(tool string, mode platform.ShellMode, port config.Port) (string, error) {
	root := fmt.Sprintf("http://127.0.0.1:%d", port)
	openAI := root + "/v1"

	switch tool {
	case "claude":
		return "# Claude Code: run this before launching `claude`.\n" +
			envVars(mode, [][2]string{{"ANTHROPIC_BASE_URL", root}}), nil
	case "codex":
		path := "~/.codex/config.toml"
		if mode == platform.ShellPowerShell {
			path = `%USERPROFILE%\.codex\config.toml`
		}
		return fmt.Sprintf("# Codex CLI: add this to %s (API key mode; the ChatGPT subscription login cannot pass through the gateway).\n"+
			"model_providers.tokenhush = { name = \"Tokenhush\", base_url = %q }\n", path, openAI), nil
	case "aider":
		return "# Aider: run this before launching `aider`.\n" +
			envVars(mode, [][2]string{
				{"OPENAI_API_BASE", openAI},
				{"ANTHROPIC_API_BASE", root},
			}), nil
	case "cline", "roo":
		name := "Cline"
		if tool == "roo" {
			name = "Roo Code"
		}
		return fmt.Sprintf("%s (VS Code): Settings -> API Provider -> \"OpenAI Compatible\"\nBase URL: %s\n", name, openAI), nil
	default:
		return "", fmt.Errorf("unknown tool %q", tool)
	}
}

// envVars renders environment assignments in the dialect of mode. POSIX uses
// `export` for the current shell; PowerShell sets the current session with
// `$env:` and also prints the persistent `setx` form documented in
// docs/configuration.md.
func envVars(mode platform.ShellMode, vars [][2]string) string {
	var b strings.Builder
	powerShell := mode == platform.ShellPowerShell
	for _, kv := range vars {
		if powerShell {
			fmt.Fprintf(&b, "$env:%s = %q\n", kv[0], kv[1])
		} else {
			fmt.Fprintf(&b, "export %s=%q\n", kv[0], kv[1])
		}
	}
	if powerShell {
		b.WriteString("# persist for new terminals:\n")
		for _, kv := range vars {
			fmt.Fprintf(&b, "setx %s %q\n", kv[0], kv[1])
		}
	}
	return b.String()
}
