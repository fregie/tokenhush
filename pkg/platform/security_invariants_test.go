package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNoWriteToBinaryDir is the W5.4 named invariant (docs/security.md §1,
// docs/12 §4): tokenhush never resolves or writes below the running binary's
// directory — a read-only Homebrew keg or Program Files prefix — nor below the
// current working directory. It pins the real resolvers, the override refusal,
// and that a write to the resolved data directory leaves the executable
// directory untouched.
func TestNoWriteToBinaryDir(t *testing.T) {
	t.Setenv(homeEnvVar, "")

	cfg, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir(): %v", err)
	}
	data, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir(): %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable(): %v", err)
	}
	exeDir := filepath.Dir(exe)

	for name, dir := range map[string]string{"ConfigDir": cfg, "DataDir": data} {
		if !filepath.IsAbs(dir) {
			t.Errorf("%s = %q, want an absolute path", name, dir)
		}
		if sameOrInside(runtime.GOOS, exeDir, dir) {
			t.Errorf("%s = %q is the executable dir %q or inside it", name, dir, exeDir)
		}
		if sameOrInside(runtime.GOOS, cwd, dir) {
			t.Errorf("%s = %q is the CWD %q or inside it", name, dir, cwd)
		}
	}

	t.Run("override_into_exec_dir_is_refused", func(t *testing.T) {
		prefix := t.TempDir()
		// The override is built with filepath.Join (host separators), so the
		// simulated goos must be the host's or the containment guard misses it.
		_, _, err := pathsFor(runtime.GOOS,
			stubEnv(map[string]string{homeEnvVar: filepath.Join(prefix, "data")}),
			stubDir(testLinuxConfigBase), stubDir(testLinuxHome), stubDir(prefix))
		if !errors.Is(err, ErrPathInExecDir) {
			t.Fatalf("pathsFor(override inside exec dir) error = %v, want ErrPathInExecDir", err)
		}
	})

	t.Run("resolved_data_dir_receives_writes_not_exec_dir", func(t *testing.T) {
		override := t.TempDir()
		t.Setenv(homeEnvVar, override)
		resolved, err := DataDir()
		if err != nil {
			t.Fatalf("DataDir() with override: %v", err)
		}
		if sameOrInside(runtime.GOOS, exeDir, resolved) {
			t.Fatalf("resolved DataDir %q is inside the executable dir %q", resolved, exeDir)
		}

		before := dirFingerprint(t, exeDir)
		if err := os.MkdirAll(resolved, 0o700); err != nil {
			t.Fatalf("MkdirAll(resolved data dir): %v", err)
		}
		probe := filepath.Join(resolved, "write-probe.tmp")
		if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
			t.Fatalf("write into resolved data dir: %v", err)
		}
		if _, err := os.Stat(probe); err != nil {
			t.Fatalf("write probe missing after write: %v", err)
		}
		if after := dirFingerprint(t, exeDir); after != before {
			t.Fatalf("executable dir entry fingerprint changed: before=%q after=%q", before, after)
		}
	})
}

// dirFingerprint returns the sorted entry names of dir (os.ReadDir already
// sorts by filename) joined into one stable string.
func dirFingerprint(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, ",")
}
