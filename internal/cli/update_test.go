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
// no test can reach the real exec path).
func stubUpdate(t *testing.T, src update.Source, run func(context.Context, string, []string) (string, error)) {
	t.Helper()
	origSource, origRun := updateDetectSource, updateRunCommand
	t.Cleanup(func() {
		updateDetectSource, updateRunCommand = origSource, origRun
	})
	updateDetectSource = func() update.Source { return src }
	updateRunCommand = run
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

// TestUpdateCommandSelfManagedIsNoticeOnly is the failure-path guard: a
// self-managed install must run nothing and write nothing.
func TestUpdateCommandSelfManagedIsNoticeOnly(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, ".local", "bin", "tokenhush")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("ORIGINAL"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, dir)

	stubUpdate(t, update.Source{Kind: update.SourceSelfManaged, Exe: exe}, failIfRun(t))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"update"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("update exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	if after := snapshotTree(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("self-managed must not write anything: before=%v after=%v", before, after)
	}
	if !strings.Contains(stdout.String(), "later release") {
		t.Errorf("self-managed notice must mention the later release, got %q", stdout.String())
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
// runs nothing, for every detected kind.
func TestUpdateCommandCheckDoesNotInstall(t *testing.T) {
	for _, kind := range []update.SourceKind{
		update.SourceBrew, update.SourceScoop, update.SourceSelfManaged, update.SourceUnknown,
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
