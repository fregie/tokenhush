package cli

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/update"
)

// stubUpdate replaces the two update seams for the duration of a test. The
// detection seam returns src; the runner seam is run (which must be non-nil so
// no test can reach the real exec path). The engine seam fails the test unless
// the test installs its own via stubUpdateEngine, so a self-managed path can
// never reach the network by accident.
func stubUpdate(t *testing.T, src update.Source, run func(context.Context, string, []string) (string, error)) {
	t.Helper()
	origSource, origRun, origEngine := updateDetectSource, updateRunCommand, updateNewEngine
	t.Cleanup(func() {
		updateDetectSource, updateRunCommand, updateNewEngine = origSource, origRun, origEngine
	})
	updateDetectSource = func() update.Source { return src }
	updateRunCommand = run
	updateNewEngine = func(update.Source, bool) (*updateEngine, error) {
		t.Fatal("test did not expect the online update engine to be built")
		return nil, nil
	}
}

// stubUpdateEngine installs an in-test engine builder. Call it after stubUpdate
// so the guard it replaces is itself restored on cleanup.
func stubUpdateEngine(t *testing.T, fn func(update.Source, bool) (*updateEngine, error)) {
	t.Helper()
	orig := updateNewEngine
	t.Cleanup(func() { updateNewEngine = orig })
	updateNewEngine = fn
}

// failIfRun is the runner for paths that must not execute anything.
func failIfRun(t *testing.T) func(context.Context, string, []string) (string, error) {
	return func(_ context.Context, name string, args []string) (string, error) {
		t.Fatalf("update must not execute %q %v", name, args)
		return "", nil
	}
}

// recordRuns records each executed command as a single space-joined string.
func recordRuns(calls *[]string) func(context.Context, string, []string) (string, error) {
	return func(_ context.Context, name string, args []string) (string, error) {
		*calls = append(*calls, strings.Join(append([]string{name}, args...), " "))
		return "manager output\n", nil
	}
}

// snapshotTree maps every regular file under root to its content, so a test can
// assert that update wrote nothing.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		snap[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return snap
}

// TestUpdateCommandBrewDelegatesToManager is the happy path: a Homebrew install
// must run `brew upgrade --cask tokenhush` and leave the running binary byte
// for byte untouched (Homebrew owns the replacement; tokenhush never
// self-replaces).
func TestUpdateCommandBrewDelegatesToManager(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "tokenhush")
	if err := os.WriteFile(exe, []byte("ORIGINAL-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, dir)

	var calls []string
	stubUpdate(t, update.Source{Kind: update.SourceBrew, Exe: exe}, recordRuns(&calls))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("update exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	if len(calls) != 1 || calls[0] != "brew upgrade --cask tokenhush" {
		t.Fatalf("executed commands = %v, want exactly [brew upgrade --cask tokenhush]", calls)
	}
	if after := snapshotTree(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("brew path must not touch the binary: before=%v after=%v", before, after)
	}
	if !strings.Contains(stdout.String(), "brew upgrade --cask tokenhush") {
		t.Errorf("output should name the delegated command, got %q", stdout.String())
	}
}

// TestUpdateCommandScoopDelegatesToManager is the Windows happy path.
func TestUpdateCommandScoopDelegatesToManager(t *testing.T) {
	var calls []string
	stubUpdate(t, update.Source{Kind: update.SourceScoop, Exe: `C:\Users\me\scoop\shims\tokenhush.exe`}, recordRuns(&calls))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("update exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	if len(calls) != 1 || calls[0] != "scoop update tokenhush" {
		t.Fatalf("executed commands = %v, want exactly [scoop update tokenhush]", calls)
	}
}

// TestUpdateCommandSelfManagedDisabledMakesNoRequest asserts the update-check
// switch stops a self-managed run before any engine is built, so no request
// leaves the machine.
func TestUpdateCommandSelfManagedDisabledMakesNoRequest(t *testing.T) {
	t.Setenv(EnvNoUpdateCheck, "1")
	stubUpdate(t, update.Source{Kind: update.SourceSelfManaged, Exe: "/home/me/.local/bin/tokenhush"}, failIfRun(t))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update", "--check"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("update --check exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), EnvNoUpdateCheck) {
		t.Errorf("output must name the switch, got %q", stdout.String())
	}
}

// TestUpdateCommandUnknownGivesManualGuidance asserts an unknown origin runs
// nothing and prints the manual paths.
func TestUpdateCommandUnknownGivesManualGuidance(t *testing.T) {
	stubUpdate(t, update.Source{Kind: update.SourceUnknown, Exe: "/usr/bin/tokenhush"}, failIfRun(t))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("update exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"brew upgrade --cask tokenhush", "scoop update tokenhush"} {
		if !strings.Contains(out, want) {
			t.Errorf("manual guidance missing %q, got %q", want, out)
		}
	}
}

// TestUpdateCommandCheckDoesNotInstall asserts --check reports the source and
// runs nothing, for every package-managed or unknown kind.
func TestUpdateCommandCheckDoesNotInstall(t *testing.T) {
	for _, kind := range []update.SourceKind{
		update.SourceBrew, update.SourceScoop, update.SourceUnknown,
	} {
		stubUpdate(t, update.Source{Kind: kind, Exe: "/opt/homebrew/Cellar/tokenhush/0.3.0/bin/tokenhush"}, failIfRun(t))

		var stdout, stderr bytes.Buffer
		if code := Run([]string{"update", "--check"}, &stdout, &stderr); code != ExitOK {
			t.Fatalf("%s --check exit = %d, want %d (stderr %q)", kind, code, ExitOK, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "install source: "+string(kind)) {
			t.Errorf("%s --check output missing source, got %q", kind, out)
		}
		if !strings.Contains(out, "no changes") {
			t.Errorf("%s --check output must state no changes, got %q", kind, out)
		}
	}
}

// TestUpdateCommandManagerFailureIsReported asserts a package-manager failure is
// a runtime failure, not a silent success.
func TestUpdateCommandManagerFailureIsReported(t *testing.T) {
	stubUpdate(t, update.Source{Kind: update.SourceBrew, Exe: "/opt/homebrew/Cellar/tokenhush/0.3.0/bin/tokenhush"},
		func(_ context.Context, name string, args []string) (string, error) {
			return "", os.ErrPermission
		})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update"}, &stdout, &stderr); code != ExitFailure {
		t.Fatalf("update exit = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "brew") {
		t.Errorf("stderr should name the failed manager, got %q", stderr.String())
	}
}

// TestUpdateCommandUsage guards the argument surface.
func TestUpdateCommandUsage(t *testing.T) {
	stubUpdate(t, update.Source{Kind: update.SourceUnknown}, failIfRun(t))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update", "extra"}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("update with unexpected arg exit = %d, want %d", code, ExitUsage)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"update", "--help"}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("update --help exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "Usage of update:") {
		t.Errorf("update --help must print its usage, got %q", stderr.String())
	}
}
