package cli

import (
	"flag"
	"fmt"
	"io"
	"runtime"

	"github.com/fregie/tokenhush/pkg/supply"
)

func init() { register("version", versionCommand) }

// Build metadata, overridable at link time with
// `-ldflags "-X github.com/fregie/tokenhush/internal/cli.commit=<sha>
// -X github.com/fregie/tokenhush/internal/cli.date=<date>"`.
var (
	commit = "unknown"
	date   = "unknown"
)

// versionCommand is the CLI entry for `tokenhush version`: the OD-1 version
// line (v0.5.0, the single source is supply.Version, the same value the rule
// manifest min_binary_version gate is evaluated against) plus build info.
func versionCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: version: unexpected argument %q\n", flags.Arg(0))
		return exitUsage
	}
	fmt.Fprintf(stdout, "tokenhush v%s %s/%s %s (commit %s, built %s)\n",
		supply.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), commit, date)
	return exitOK
}
