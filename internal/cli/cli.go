package cli

import (
	"fmt"
	"io"
	"runtime"
)

// Version is the human-facing version string of the tokenhush CLI. The main
// package overrides it at startup from the ldflags-injected build version;
// the default keeps `go run` and `go test` builds meaningful.
var Version = "0.0.0-dev"

// Exit codes returned by Run. They follow the common CLI convention where a
// usage error is distinguishable from a runtime failure.
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitUsage   = 2
)

const usage = `tokenhush - local base-URL gateway that redacts secrets before they leave your machine

usage:
  tokenhush run      start the gateway in the foreground
  tokenhush status   show whether the gateway is running
  tokenhush env <tool>  print tool setup snippets
  tokenhush doctor   diagnose common setup problems
  tokenhush privacy  show requests that leave your machine for the vendor
  tokenhush update [--check]  upgrade via the owning package manager
  tokenhush rules <sync|rollback>  sync signed detection rules or roll back
  tokenhush allowlist <list|add|remove>  manage the runtime allowlist
  tokenhush version  print version and build information
`

// Run executes the tokenhush CLI with args (the arguments after the program
// name) and returns the process exit code. It writes to stdout/stderr and
// never calls os.Exit, so callers can test it without spawning a process.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}

	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, versionLine())
		return ExitOK
	case "run":
		return runCommand(args[1:], stdout, stderr)
	case "env":
		return envCommand(args[1:], stdout, stderr)
	case "doctor":
		return doctorCommand(args[1:], stdout, stderr)
	case "privacy":
		return privacyCommand(args[1:], stdout, stderr)
	case "update":
		return updateCommand(args[1:], stdout, stderr)
	case "rules":
		return rulesCommand(args[1:], stdout, stderr)
	case "allowlist":
		return allowlistCommand(args[1:], stdout, stderr)
	case "status":
		// W6.7 seam: statusCommand renders the read-only Pro badge when a
		// valid license file is present by calling proLicenseBadge().
		return statusCommand(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "tokenhush: unknown command %q\n", args[0])
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
}

// versionLine renders the version together with the build information that
// matters when reporting a bug.
func versionLine() string {
	return fmt.Sprintf("tokenhush %s (%s %s/%s)", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
