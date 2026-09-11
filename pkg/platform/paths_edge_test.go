package platform

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Space and non-ASCII fixtures for the cross-OS path table. Every value is a
// pure string, so the windows/darwin shapes are pinned identically from any
// host (docs/13 §10.3 case 2).
const (
	testLinuxConfigSpaced = "/home/пользователь/My Config"
	testLinuxHomeSpaced   = "/home/пользователь"
	testLinuxExecSpaced   = "/opt/My App 应用"

	testWindowsConfigSpaced       = `C:\Users\某用户\AppData\Roaming`
	testWindowsLocalAppDataSpaced = `C:\Users\某用户\AppData\Local`
	testWindowsHomeSpaced         = `C:\Users\某用户`
	testWindowsExecSpaced         = `C:\Program Files\Tokenhush 应用`

	testDarwinHomeUnicode = "/Users/某用户"
)

// TestPathsSpacesAndNonASCII covers the malformed-input edge class W2.1 does not
// pin: user directories containing spaces, non-ASCII characters, trailing
// separators and mixed separators. Values must be preserved verbatim (never
// trimmed or re-encoded), the windows shape must come out with backslashes, and
// the executable-dir guard must keep working on such paths.
func TestPathsSpacesAndNonASCII(t *testing.T) {
	tests := []struct {
		name          string
		goos          string
		env           map[string]string
		userConfigDir func() (string, error)
		userHomeDir   func() (string, error)
		execDir       func() (string, error)
		wantConfig    string
		wantData      string
		wantErr       error
	}{
		{
			name:          "linux_config_with_spaces_and_trailing_separator",
			goos:          "linux",
			userConfigDir: stubDir(testLinuxConfigSpaced + "/"),
			userHomeDir:   stubDir(testLinuxHomeSpaced),
			execDir:       stubDir(testLinuxExecSpaced),
			wantConfig:    testLinuxConfigSpaced + "/tokenhush",
			wantData:      testLinuxHomeSpaced + "/.local/share/tokenhush",
		},
		{
			name:          "linux_xdg_data_home_with_spaces_and_unicode",
			goos:          "linux",
			env:           map[string]string{xdgDataHomeEnvVar: "/data/My 数据"},
			userConfigDir: stubDir(testLinuxConfigSpaced),
			userHomeDir:   stubDir(testLinuxHomeSpaced),
			execDir:       stubDir(testLinuxExecSpaced),
			wantConfig:    testLinuxConfigSpaced + "/tokenhush",
			wantData:      "/data/My 数据/tokenhush",
		},
		{
			name: "linux_override_with_spaces_and_unicode_is_trimmed",
			goos: "linux",
			env:  map[string]string{homeEnvVar: "  /tmp/My Config 数据  "},
			// Failing resolvers prove the override short-circuits them even
			// for a path that needs trimming.
			userConfigDir: stubErr(errors.New("resolver failed")),
			userHomeDir:   stubErr(errors.New("resolver failed")),
			execDir:       stubDir(testLinuxExecSpaced),
			wantConfig:    "/tmp/My Config 数据",
			wantData:      "/tmp/My Config 数据",
		},
		{
			name:          "darwin_unicode_user_spaced_application_support",
			goos:          "darwin",
			userConfigDir: stubDir(testDarwinHomeUnicode + "/Library/Application Support"),
			userHomeDir:   stubDir(testDarwinHomeUnicode),
			execDir:       stubDir(testDarwinExec),
			wantConfig:    testDarwinHomeUnicode + "/Library/Application Support/tokenhush",
			wantData:      testDarwinHomeUnicode + "/Library/Application Support/tokenhush",
		},
		{
			name:          "windows_spaced_unicode_defaults",
			goos:          "windows",
			env:           map[string]string{localAppDataEnvVar: testWindowsLocalAppDataSpaced},
			userConfigDir: stubDir(testWindowsConfigSpaced),
			userHomeDir:   stubDir(testWindowsHomeSpaced),
			execDir:       stubDir(testWindowsExecSpaced),
			wantConfig:    testWindowsConfigSpaced + `\tokenhush`,
			wantData:      testWindowsLocalAppDataSpaced + `\tokenhush`,
		},
		{
			name:          "windows_unicode_bases_with_forward_slashes",
			goos:          "windows",
			env:           map[string]string{localAppDataEnvVar: `C:/Users/某用户/AppData/Local`},
			userConfigDir: stubDir(`C:/Users/某用户/AppData/Roaming`),
			userHomeDir:   stubDir(testWindowsHomeSpaced),
			execDir:       stubDir(testWindowsExecSpaced),
			wantConfig:    `C:\Users\某用户\AppData\Roaming\tokenhush`,
			wantData:      `C:\Users\某用户\AppData\Local\tokenhush`,
		},
		{
			name:          "windows_unicode_bases_with_trailing_separators",
			goos:          "windows",
			env:           map[string]string{localAppDataEnvVar: testWindowsLocalAppDataSpaced + `\`},
			userConfigDir: stubDir(testWindowsConfigSpaced + `\`),
			userHomeDir:   stubDir(testWindowsHomeSpaced),
			execDir:       stubDir(testWindowsExecSpaced),
			wantConfig:    testWindowsConfigSpaced + `\tokenhush`,
			wantData:      testWindowsLocalAppDataSpaced + `\tokenhush`,
		},
		{
			name:          "windows_unicode_override",
			goos:          "windows",
			env:           map[string]string{homeEnvVar: `D:\便携 目录\tokenhush`},
			userConfigDir: stubDir(testWindowsConfigSpaced),
			userHomeDir:   stubDir(testWindowsHomeSpaced),
			execDir:       stubDir(testWindowsExecSpaced),
			wantConfig:    `D:\便携 目录\tokenhush`,
			wantData:      `D:\便携 目录\tokenhush`,
		},
		{
			name:          "linux_exec_guard_spaces_unicode_override_inside",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: testLinuxExecSpaced + "/data/配置"},
			userConfigDir: stubDir(testLinuxConfigSpaced),
			userHomeDir:   stubDir(testLinuxHomeSpaced),
			execDir:       stubDir(testLinuxExecSpaced),
			wantErr:       ErrPathInExecDir,
		},
		{
			name:          "linux_exec_guard_spaces_unicode_override_equal",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: testLinuxExecSpaced},
			userConfigDir: stubDir(testLinuxConfigSpaced),
			userHomeDir:   stubDir(testLinuxHomeSpaced),
			execDir:       stubDir(testLinuxExecSpaced),
			wantErr:       ErrPathInExecDir,
		},
		{
			name:          "linux_exec_guard_spaces_unicode_sibling_allowed",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: testLinuxExecSpaced + "-portable"},
			userConfigDir: stubDir(testLinuxConfigSpaced),
			userHomeDir:   stubDir(testLinuxHomeSpaced),
			execDir:       stubDir(testLinuxExecSpaced),
			wantConfig:    testLinuxExecSpaced + "-portable",
			wantData:      testLinuxExecSpaced + "-portable",
		},
		{
			name:          "windows_exec_guard_spaces_unicode_mixed_separators",
			goos:          "windows",
			env:           map[string]string{homeEnvVar: `C:/Program Files/Tokenhush 应用\data/`},
			userConfigDir: stubDir(testWindowsConfigSpaced),
			userHomeDir:   stubDir(testWindowsHomeSpaced),
			execDir:       stubDir(`c:\program files\tokenhush 应用\`),
			wantErr:       ErrPathInExecDir,
		},
		{
			name:          "windows_exec_guard_spaces_unicode_sibling_allowed",
			goos:          "windows",
			env:           map[string]string{homeEnvVar: testWindowsExecSpaced + ` 2`},
			userConfigDir: stubDir(testWindowsConfigSpaced),
			userHomeDir:   stubDir(testWindowsHomeSpaced),
			execDir:       stubDir(testWindowsExecSpaced),
			wantConfig:    testWindowsExecSpaced + ` 2`,
			wantData:      testWindowsExecSpaced + ` 2`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotConfig, gotData, err := pathsFor(tc.goos, stubEnv(tc.env), tc.userConfigDir, tc.userHomeDir, tc.execDir)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("pathsFor() error = %v, want errors.Is(err, %v)", err, tc.wantErr)
				}
				if gotConfig != "" || gotData != "" {
					t.Fatalf("pathsFor() returned (%q, %q) alongside error; want empty dirs", gotConfig, gotData)
				}
				return
			}
			if err != nil {
				t.Fatalf("pathsFor() unexpected error: %v", err)
			}
			if gotConfig != tc.wantConfig {
				t.Errorf("configDir = %q, want %q", gotConfig, tc.wantConfig)
			}
			if gotData != tc.wantData {
				t.Errorf("dataDir = %q, want %q", gotData, tc.wantData)
			}
		})
	}
}

// TestPathsSpacesUnicodeExported pins the exported helpers against a real
// directory whose path contains spaces and non-ASCII characters: ConfigDir and
// DataDir return the override verbatim and ConfigFile joins the config file
// name with the host separator.
func TestPathsSpacesUnicodeExported(t *testing.T) {
	home := filepath.Join(t.TempDir(), "My Config 数据", "tokenhush home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", home, err)
	}
	t.Setenv(homeEnvVar, home)

	cfg, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir(): %v", err)
	}
	if cfg != home {
		t.Fatalf("ConfigDir() = %q, want %q", cfg, home)
	}

	data, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir(): %v", err)
	}
	if data != home {
		t.Fatalf("DataDir() = %q, want %q", data, home)
	}

	file, err := ConfigFile()
	if err != nil {
		t.Fatalf("ConfigFile(): %v", err)
	}
	if want := filepath.Join(home, configFileName); file != want {
		t.Fatalf("ConfigFile() = %q, want %q", file, want)
	}
}

// TestPathsExecDirGuardExported drives the executable-dir guard through the
// exported API: an override aimed inside the running binary's directory is
// refused by ConfigDir, DataDir and ConfigFile alike.
func TestPathsExecDirGuardExported(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable(): %v", err)
	}
	t.Setenv(homeEnvVar, filepath.Join(filepath.Dir(exe), "data", "My Config 数据"))

	if _, err := ConfigDir(); !errors.Is(err, ErrPathInExecDir) {
		t.Fatalf("ConfigDir() error = %v, want ErrPathInExecDir", err)
	}
	if _, err := DataDir(); !errors.Is(err, ErrPathInExecDir) {
		t.Fatalf("DataDir() error = %v, want ErrPathInExecDir", err)
	}
	if _, err := ConfigFile(); !errors.Is(err, ErrPathInExecDir) {
		t.Fatalf("ConfigFile() error = %v, want ErrPathInExecDir", err)
	}
}

// TestPathsReadOnlyPrefixWriteAttempts splits the read-only install prefix
// contract in two. The pure-path half runs on every OS and pins that a
// spaced/non-ASCII prefix is never resolved into and refuses overrides. The
// write half uses chmod 0555 on POSIX (on Windows chmod cannot make a directory
// unwritable) and asserts that write attempts return errors.Is-checkable
// fs.ErrPermission errors instead of panicking.
func TestPathsReadOnlyPrefixWriteAttempts(t *testing.T) {
	t.Run("pure_paths_cross_os", func(t *testing.T) {
		// Simulated windows prefix with spaces and non-ASCII: resolution never
		// lands inside it and an override into it is refused.
		cfg, data, err := pathsFor("windows",
			stubEnv(map[string]string{localAppDataEnvVar: testWindowsLocalAppDataSpaced}),
			stubDir(testWindowsConfigSpaced), stubDir(testWindowsHomeSpaced), stubDir(testWindowsExecSpaced))
		if err != nil {
			t.Fatalf("pathsFor(windows): %v", err)
		}
		if sameOrInside("windows", testWindowsExecSpaced, cfg) || sameOrInside("windows", testWindowsExecSpaced, data) {
			t.Fatalf("windows resolution = (%q, %q) is inside exec dir %q", cfg, data, testWindowsExecSpaced)
		}
		_, _, err = pathsFor("windows",
			stubEnv(map[string]string{homeEnvVar: testWindowsExecSpaced + `\data\某用户`}),
			stubDir(testWindowsConfigSpaced), stubDir(testWindowsHomeSpaced), stubDir(testWindowsExecSpaced))
		if !errors.Is(err, ErrPathInExecDir) {
			t.Fatalf("windows override into %q error = %v, want ErrPathInExecDir", testWindowsExecSpaced, err)
		}

		// Host-native prefix: the override short-circuits before any OS base,
		// so this case is valid on whichever OS runs the suite.
		prefix := t.TempDir()
		_, _, err = pathsFor(runtime.GOOS,
			stubEnv(map[string]string{homeEnvVar: filepath.Join(prefix, "data", "My Config 数据")}),
			stubDir(testLinuxConfigBase), stubDir(testLinuxHome), stubDir(prefix))
		if !errors.Is(err, ErrPathInExecDir) {
			t.Fatalf("host override inside %q error = %v, want ErrPathInExecDir", prefix, err)
		}
	})

	t.Run("write_attempts_return_permission_errors", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("chmod cannot make a directory unwritable on Windows")
		}

		dir := filepath.Join(t.TempDir(), "My Config 数据")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatalf("Chmod(%q, 0555): %v", dir, err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		// Precondition: this runner really cannot write here; a privileged
		// runner would make the assertions below vacuous.
		probe := filepath.Join(dir, "writability-probe.tmp")
		if err := os.WriteFile(probe, []byte("probe"), 0o600); err == nil {
			_ = os.Remove(probe)
			t.Skipf("directory %q is still writable (privileged runner or permission-less FS)", dir)
		} else if !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("write probe error = %v, want fs.ErrPermission", err)
		}

		writes := map[string]func() error{
			"os.WriteFile": func() error {
				return os.WriteFile(filepath.Join(dir, "file 数据.tmp"), []byte("data"), 0o600)
			},
			"os.MkdirAll": func() error {
				return os.MkdirAll(filepath.Join(dir, "sub 目录"), 0o700)
			},
		}
		for name, write := range writes {
			err := write() // must not panic
			if err == nil {
				t.Fatalf("%s into read-only dir %q succeeded, want an error", name, dir)
			}
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("%s error = %v, want errors.Is(err, fs.ErrPermission)", name, err)
			}
		}
	})
}
