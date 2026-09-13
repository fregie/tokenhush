package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os/exec"

	"github.com/fregie/tokenhush/pkg/update"
)

// updatePackage is the package name the install channels track for the core
// binary. The Pro CLI shares pkg/update with its own package name.
const updatePackage = "tokenhush"

// updateDetectSource and updateRunCommand are the injectable seams of
// updateCommand. Production detects the running binary and shells out to the
// package manager; tests inject a fixed source and a recording runner, so no
// test ever runs brew or scoop.
var (
	updateDetectSource = update.DetectSource
	updateRunCommand   = defaultUpdateRun
)

// defaultUpdateRun runs one package-manager command and returns its combined
// output.
func defaultUpdateRun(ctx context.Context, name string, args []string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// updateCommand is the CLI entry for `tokenhush update`: it classifies the
// install source and delegates the upgrade to the owning package manager. It
// never replaces the running binary itself, and --check only reports.
func updateCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var check bool
	fs.BoolVar(&check, "check", false, "report the install source and the planned action without installing")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage of update: tokenhush update [--check]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Upgrade tokenhush. Homebrew and Scoop installs are delegated to their")
		fmt.Fprintln(stderr, "package manager; a self-managed install only prints a notice. Nothing is")
		fmt.Fprintln(stderr, "ever replaced by this command. --check reports without changing anything.")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: update: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}

	src := updateDetectSource()
	plan := update.PlanFor(src, updatePackage, check)

	// The header carries the path for the human; the path never enters a
	// command. A Command is present only for a real package-manager delegation,
	// never for --check, the self-managed notice, or manual guidance.
	if plan.Source.Exe != "" {
		fmt.Fprintf(stdout, "tokenhush update: install source: %s (%s)\n", plan.Source.Kind, plan.Source.Exe)
	} else {
		fmt.Fprintf(stdout, "tokenhush update: install source: %s\n", plan.Source.Kind)
	}
	fmt.Fprintln(stdout, plan.Message)

	if plan.Command == nil {
		return ExitOK
	}

	out, err := updateRunCommand(context.Background(), plan.Command[0], plan.Command[1:])
	if out != "" {
		if _, werr := io.WriteString(stdout, out); werr != nil {
			return ExitFailure
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: update: %s failed: %v\n", plan.Command[0], err)
		return ExitFailure
	}
	return ExitOK
}
