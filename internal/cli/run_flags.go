// run_flags.go owns the `run` flag set and the startup-failure report, split
// out of run.go to keep that file under the 250-pure-LOC guard ceiling.
package cli

import (
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/fregie/tokenhush/pkg/config"
)

// runOptions is the parsed `run` flag set. Each flag overrides the config
// value of the same setting; the redaction log is on by default.
type runOptions struct {
	configPath    string
	port          int
	logLevel      string
	logRedactions bool
}

// parseRunFlags parses the run flag set. A malformed invocation or an unknown
// flag is a usage error (exit 2) with the flag package's own diagnosis.
func parseRunFlags(args []string, stderr io.Writer) (runOptions, int) {
	opts := runOptions{logRedactions: true}
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.configPath, "config", "", "path to tokenhush.yaml (default: the platform config dir)")
	flags.IntVar(&opts.port, "port", 0, "override the listen port (1..65535)")
	flags.StringVar(&opts.logLevel, "log-level", "", "override the log level (debug, info, warn, error)")
	flags.BoolVar(&opts.logRedactions, "log-redactions", true, "print a masked line for every redacted value")
	if err := flags.Parse(args); err != nil {
		return opts, exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: run: unexpected argument %q\n", flags.Arg(0))
		return opts, exitUsage
	}
	if opts.port < 0 || opts.port > 65535 {
		fmt.Fprintf(stderr, "tokenhush: run: --port %d is outside 1..65535\n", opts.port)
		return opts, exitUsage
	}
	if opts.logLevel != "" && !slices.Contains(logLevels, opts.logLevel) {
		fmt.Fprintf(stderr, "tokenhush: run: --log-level %q is not one of %s\n", opts.logLevel, strings.Join(logLevels, ", "))
		return opts, exitUsage
	}
	return opts, exitOK
}

// applyRunOverrides folds the validated flags into the loaded config.
func applyRunOverrides(cfg config.Config, opts runOptions) config.Config {
	if opts.port != 0 {
		cfg.Listen.Port = opts.port
	}
	if opts.logLevel != "" {
		cfg.Log.Level = opts.logLevel
	}
	return cfg
}

// runFailure reports one startup failure on stderr and returns exit 1.
func runFailure(stderr io.Writer, what string, err error) int {
	fmt.Fprintf(stderr, "tokenhush: run: %s: %v\n", what, err)
	return exitFailure
}
