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
  tokenhush audit    show the local audit timeline
  tokenhush env      print tool setup snippets
  tokenhush doctor   diagnose common setup problems
  tokenhush version  print version and build information
`

// Run executes the tokenhush CLI with args (the arguments after the program
// name) and returns the process exit code. It writes to stdout/stderr and
// never calls os.Exit, so callers can test it without spawning a process.
//
// `run` is implemented; `status`, `audit`, `env` and `doctor` are still stubs
// that fail with ExitUsage and a "not implemented" message until their waves
// land.
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
	case "status", "audit", "env", "doctor":
		fmt.Fprintf(stderr, "%s: not implemented\n", args[0])
		fmt.Fprintf(stderr, "usage: tokenhush %s\n", args[0])
		return ExitUsage
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
