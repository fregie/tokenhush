package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/update"
)

// updatePackage is the package name the install channels track for the core
// binary. The Pro CLI shares pkg/update with its own package name.
const updatePackage = "tokenhush"

// EnvNoUpdateCheck disables the vendor-bound update check. It is one of the two
// disclosed switchable egress categories (the other is rule sync); the update
// path honours it before any connection so no request leaves the machine.
const EnvNoUpdateCheck = "TOKENHUSH_NO_UPDATE_CHECK"

// updateDetectSource, updateRunCommand and updateNewEngine are the injectable
// seams of updateCommand. Production detects the running binary, shells out to
// the package manager and builds the signed-update engine; tests inject a fixed
// source, a recording runner and an httptest-backed engine, so no test ever
// runs brew, scoop, or reaches the network.
var (
	updateDetectSource = update.DetectSource
	updateRunCommand   = defaultUpdateRun
	updateNewEngine    = defaultUpdateEngine
)

// updateEngine bundles the verified-key-list client and the self-update engine
// so one run reuses a single verifier and a single anti-rollback store. The
// applier is nil for --check, which never installs.
type updateEngine struct {
	checker *update.Checker
	applier *update.Applier
}

// defaultUpdateRun runs one package-manager command and returns its combined
// output.
func defaultUpdateRun(ctx context.Context, name string, args []string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// updateCheckDisabled reports whether the operator asked to switch the update
// check off. Only an explicit truthy value disables it.
func updateCheckDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvNoUpdateCheck))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// defaultUpdateEngine builds the online check/apply engine from the embedded
// roots and the platform data root. --check must not write, so it uses an
// in-process anti-rollback store; an install persists its marks.
func defaultUpdateEngine(src update.Source, check bool) (*updateEngine, error) {
	hw, err := updateHighWater(check)
	if err != nil {
		return nil, err
	}
	verifier := &update.Verifier{
		Roots:          update.DefaultRoots(),
		CurrentVersion: Version,
		HighWater:      hw,
	}
	checker, err := update.NewChecker(update.CheckConfig{
		Source:   src,
		Channel:  update.DefaultChannel,
		BaseURL:  update.DefaultBaseURL,
		Verifier: verifier,
		GOOS:     runtime.GOOS,
		GOARCH:   runtime.GOARCH,
	})
	if err != nil {
		return nil, err
	}
	eng := &updateEngine{checker: checker}
	if check {
		return eng, nil
	}
	applier, err := update.NewApplier(update.ApplyConfig{
		Source:   src,
		Channel:  update.DefaultChannel,
		BaseURL:  update.DefaultBaseURL,
		Target:   src.Exe,
		Verifier: verifier,
	})
	if err != nil {
		return nil, err
	}
	eng.applier = applier
	return eng, nil
}

// updateHighWater returns the anti-rollback store for an update run. A check is
// informational and must not touch disk, so it gets an in-process store; an
// install persists its marks so rollback protection survives a restart.
func updateHighWater(check bool) (update.HighWaterStore, error) {
	if check {
		return update.NewMemHighWater(), nil
	}
	dataDir, err := platform.DataDir()
	if err != nil {
		return nil, err
	}
	return update.OpenFileHighWater(filepath.Join(dataDir, "update", "highwater.json"))
}

// updateCommand is the CLI entry for `tokenhush update`: it classifies the
// install source and delegates the upgrade to the owning package manager. A
// self-managed install verifies the signed online release and self-updates;
// brew, scoop and unknown installs are never replaced by this command, and
// --check only reports.
func updateCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var check bool
	fs.BoolVar(&check, "check", false, "report whether an update is available, without installing")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage of update: tokenhush update [--check]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Upgrade tokenhush. Homebrew and Scoop installs are delegated to their")
		fmt.Fprintln(stderr, "package manager; a self-managed install verifies the signed release and")
		fmt.Fprintln(stderr, "self-updates. --check reports without changing anything. Set")
		fmt.Fprintf(stderr, "%s=1 to disable the update check (no request).\n", EnvNoUpdateCheck)
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
	if src.Kind == update.SourceSelfManaged {
		return selfManagedUpdate(src, check, stdout, stderr)
	}

	plan := update.PlanFor(src, updatePackage, check)

	// The header carries the path for the human; the path never enters a
	// command. A Command is present only for a real package-manager delegation,
	// never for --check or manual guidance.
	printUpdateSource(stdout, plan.Source)
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

// selfManagedUpdate runs the signed online update for a self-managed install.
// --check applies the key list and manifest and reports only; an install does
// the same verification and then hands off to the two-phase applier. Any
// failure is surfaced, and a rejection never writes the binary.
func selfManagedUpdate(src update.Source, check bool, stdout, stderr io.Writer) int {
	printUpdateSource(stdout, src)
	if updateCheckDisabled() {
		fmt.Fprintf(stdout, "tokenhush update: update check disabled by %s; no request sent\n", EnvNoUpdateCheck)
		return ExitOK
	}
	eng, err := updateNewEngine(src, check)
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: update: %v\n", err)
		return ExitFailure
	}
	if check {
		res, err := eng.checker.Check(context.Background())
		if err != nil {
			fmt.Fprintf(stderr, "tokenhush: update: %v\n", err)
			return ExitFailure
		}
		for _, warning := range res.Warnings {
			fmt.Fprintf(stderr, "tokenhush: %s\n", warning)
		}
		fmt.Fprintln(stdout, updateCheckLine(res))
		return ExitOK
	}
	// Apply re-verifies the manifest and fetches the independent kill-switch
	// document itself, so the install decision never relies on the pre-flight
	// check's outcome.
	if _, err := eng.checker.Check(context.Background()); err != nil {
		fmt.Fprintf(stderr, "tokenhush: update: %v\n", err)
		return ExitFailure
	}
	res, err := eng.applier.Apply(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: update: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintln(stdout, updateApplyLine(res))
	return ExitOK
}

// printUpdateSource renders the install-source header. The path is for the
// human only and never enters a command.
func printUpdateSource(stdout io.Writer, src update.Source) {
	if src.Exe != "" {
		fmt.Fprintf(stdout, "tokenhush update: install source: %s (%s)\n", src.Kind, src.Exe)
		return
	}
	fmt.Fprintf(stdout, "tokenhush update: install source: %s\n", src.Kind)
}

// updateCheckLine renders the read-only --check report.
func updateCheckLine(res update.CheckResult) string {
	switch {
	case res.PlatformMismatch:
		return fmt.Sprintf("update check: no update for this platform (latest manifest is %s)", res.LatestVersion)
	case res.UpdateAvailable:
		return fmt.Sprintf("update check: update available: %s (current %s)", res.LatestVersion, res.CurrentVersion)
	default:
		return fmt.Sprintf("update check: up to date (%s)", res.CurrentVersion)
	}
}

// updateApplyLine renders the result of an applied update.
func updateApplyLine(res update.ApplyResult) string {
	switch res.Status {
	case update.ApplyUpdated:
		return fmt.Sprintf("tokenhush update: updated to %s (serial %d)", res.Version, res.Serial)
	case update.ApplyPending:
		return fmt.Sprintf("tokenhush update: %s staged for the next restart (serial %d)", res.Version, res.Serial)
	default:
		return fmt.Sprintf("tokenhush update: already up to date (%s)", res.Version)
	}
}
