package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Path fixtures use platform-native separators so the expected values are
// identical no matter which host runs the suite.
const (
	testDarwinConfigBase = "/Users/u/Library/Application Support"
	testDarwinHome       = "/Users/u"
	testDarwinExec       = "/opt/homebrew/bin"

	testLinuxConfigBase = "/home/u/.config"
	testLinuxHome       = "/home/u"
	testLinuxExec       = "/usr/bin"

	testWindowsConfigBase   = `C:\Users\u\AppData\Roaming`
	testWindowsLocalAppData = `C:\Users\u\AppData\Local`
	testWindowsHome         = `C:\Users\u`
	testWindowsExec         = `C:\Program Files\tokenhush`
)

func stubEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func stubDir(dir string) func() (string, error) {
	return func() (string, error) { return dir, nil }
}

func stubErr(err error) func() (string, error) {
	return func() (string, error) { return "", err }
}

// TestPaths is the cross-OS table test for pathsFor: darwin, linux and windows
// are simulated on any host because every OS input is injected.
func TestPaths(t *testing.T) {
	boom := errors.New("resolver failed")

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
			name:          "darwin_defaults",
			goos:          "darwin",
			userConfigDir: stubDir(testDarwinConfigBase),
			userHomeDir:   stubDir(testDarwinHome),
			execDir:       stubDir(testDarwinExec),
			wantConfig:    testDarwinConfigBase + "/tokenhush",
			wantData:      testDarwinHome + "/Library/Application Support/tokenhush",
		},
		{
			name: "darwin_override_beats_failing_resolvers",
			goos: "darwin",
			env:  map[string]string{homeEnvVar: "/tmp/tokenhush-portable"},
			// Both resolvers fail: the override must short-circuit them.
			userConfigDir: stubErr(boom),
			userHomeDir:   stubErr(boom),
			execDir:       stubDir(testDarwinExec),
			wantConfig:    "/tmp/tokenhush-portable",
			wantData:      "/tmp/tokenhush-portable",
		},
		{
			name:          "darwin_home_unavailable",
			goos:          "darwin",
			userConfigDir: stubDir(testDarwinConfigBase),
			userHomeDir:   stubErr(boom),
			execDir:       stubDir(testDarwinExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "linux_defaults",
			goos:          "linux",
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      testLinuxHome + "/.local/share/tokenhush",
		},
		{
			name:          "linux_xdg_data_home_set",
			goos:          "linux",
			env:           map[string]string{xdgDataHomeEnvVar: "/data/xdg"},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      "/data/xdg/tokenhush",
		},
		{
			name:          "linux_xdg_data_home_relative_ignored",
			goos:          "linux",
			env:           map[string]string{xdgDataHomeEnvVar: "relative/data"},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      testLinuxHome + "/.local/share/tokenhush",
		},
		{
			name:          "linux_xdg_data_home_blank_ignored",
			goos:          "linux",
			env:           map[string]string{xdgDataHomeEnvVar: "   "},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      testLinuxHome + "/.local/share/tokenhush",
		},
		{
			name:          "linux_xdg_data_home_needs_no_home",
			goos:          "linux",
			env:           map[string]string{xdgDataHomeEnvVar: "/data/xdg"},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubErr(boom),
			execDir:       stubDir(testLinuxExec),
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      "/data/xdg/tokenhush",
		},
		{
			name:          "linux_config_unavailable",
			goos:          "linux",
			userConfigDir: stubErr(boom),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "linux_config_empty",
			goos:          "linux",
			userConfigDir: stubDir(""),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "linux_config_whitespace_only",
			goos:          "linux",
			userConfigDir: stubDir("   "),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "linux_config_resolver_nil",
			goos:          "linux",
			userConfigDir: nil,
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "linux_home_unavailable",
			goos:          "linux",
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubErr(boom),
			execDir:       stubDir(testLinuxExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "linux_home_and_config_unavailable",
			goos:          "linux",
			userConfigDir: stubErr(boom),
			userHomeDir:   stubErr(boom),
			execDir:       stubDir(testLinuxExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "tokenhush_home_whitespace_only_is_ignored",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: "   "},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      testLinuxHome + "/.local/share/tokenhush",
		},
		{
			name:          "tokenhush_home_empty_is_ignored",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: ""},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      testLinuxHome + "/.local/share/tokenhush",
		},
		{
			name:          "tokenhush_home_trimmed",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: "  /tmp/tokenhush-home  "},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir(testLinuxExec),
			wantConfig:    "/tmp/tokenhush-home",
			wantData:      "/tmp/tokenhush-home",
		},
		{
			name:          "windows_defaults",
			goos:          "windows",
			env:           map[string]string{localAppDataEnvVar: testWindowsLocalAppData},
			userConfigDir: stubDir(testWindowsConfigBase),
			userHomeDir:   stubDir(testWindowsHome),
			execDir:       stubDir(testWindowsExec),
			wantConfig:    testWindowsConfigBase + `\tokenhush`,
			wantData:      testWindowsLocalAppData + `\tokenhush`,
		},
		{
			name:          "windows_localappdata_missing",
			goos:          "windows",
			userConfigDir: stubDir(testWindowsConfigBase),
			userHomeDir:   stubDir(testWindowsHome),
			execDir:       stubDir(testWindowsExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "windows_localappdata_blank",
			goos:          "windows",
			env:           map[string]string{localAppDataEnvVar: "  "},
			userConfigDir: stubDir(testWindowsConfigBase),
			userHomeDir:   stubDir(testWindowsHome),
			execDir:       stubDir(testWindowsExec),
			wantErr:       ErrPathUnavailable,
		},
		{
			name:          "windows_override",
			goos:          "windows",
			env:           map[string]string{homeEnvVar: `D:\portable\tokenhush`},
			userConfigDir: stubDir(testWindowsConfigBase),
			userHomeDir:   stubDir(testWindowsHome),
			execDir:       stubDir(testWindowsExec),
			wantConfig:    `D:\portable\tokenhush`,
			wantData:      `D:\portable\tokenhush`,
		},
		{
			name:          "windows_forward_slashes_normalized",
			goos:          "windows",
			env:           map[string]string{localAppDataEnvVar: `C:/Users/u/AppData/Local`},
			userConfigDir: stubDir(`C:/Users/u/AppData/Roaming`),
			userHomeDir:   stubDir(testWindowsHome),
			execDir:       stubDir(testWindowsExec),
			wantConfig:    `C:\Users\u\AppData\Roaming\tokenhush`,
			wantData:      `C:\Users\u\AppData\Local\tokenhush`,
		},
		{
			name:          "override_into_exec_dir_rejected",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: "/opt/tokenhush/data"},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir("/opt/tokenhush"),
			wantErr:       ErrPathInExecDir,
		},
		{
			name:          "override_equal_to_exec_dir_rejected",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: "/usr/local/bin"},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir("/usr/local/bin"),
			wantErr:       ErrPathInExecDir,
		},
		{
			name:          "override_sibling_of_exec_dir_allowed",
			goos:          "linux",
			env:           map[string]string{homeEnvVar: "/opt/tokenhush-portable"},
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir("/opt/tokenhush"),
			wantConfig:    "/opt/tokenhush-portable",
			wantData:      "/opt/tokenhush-portable",
		},
		{
			name:          "windows_override_exec_dir_guard_case_insensitive",
			goos:          "windows",
			env:           map[string]string{homeEnvVar: `c:\Program Files\Tokenhush\data`},
			userConfigDir: stubDir(testWindowsConfigBase),
			userHomeDir:   stubDir(testWindowsHome),
			execDir:       stubDir(`C:\Program Files\tokenhush`),
			wantErr:       ErrPathInExecDir,
		},
		{
			name:          "default_config_inside_exec_dir_rejected",
			goos:          "linux",
			userConfigDir: stubDir("/opt/tokenhush/etc"),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubDir("/opt/tokenhush"),
			wantErr:       ErrPathInExecDir,
		},
		{
			name:          "exec_dir_resolver_error_ignored",
			goos:          "linux",
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       stubErr(boom),
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      testLinuxHome + "/.local/share/tokenhush",
		},
		{
			name:          "exec_dir_resolver_nil_ignored",
			goos:          "linux",
			userConfigDir: stubDir(testLinuxConfigBase),
			userHomeDir:   stubDir(testLinuxHome),
			execDir:       nil,
			wantConfig:    testLinuxConfigBase + "/tokenhush",
			wantData:      testLinuxHome + "/.local/share/tokenhush",
		},
		{
			name:          "unknown_goos_uses_unix_defaults",
			goos:          "freebsd",
			userConfigDir: stubDir("/home/u/.config"),
			userHomeDir:   stubDir("/home/u"),
			execDir:       stubDir("/usr/local/bin"),
			wantConfig:    "/home/u/.config/tokenhush",
			wantData:      "/home/u/.local/share/tokenhush",
		},
		{
			name:          "ios_matches_darwin_data_layout",
			goos:          "ios",
			userConfigDir: stubDir(testDarwinConfigBase),
			userHomeDir:   stubDir(testDarwinHome),
			execDir:       stubDir(testDarwinExec),
			wantConfig:    testDarwinConfigBase + "/tokenhush",
			wantData:      testDarwinHome + "/Library/Application Support/tokenhush",
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

// TestPathsNeverCwdOrExecutableDir pins the negative invariant on the exported
// API with the real OS resolvers: tokenhush paths never point at the current
// working directory or the running binary's directory.
func TestPathsNeverCwdOrExecutableDir(t *testing.T) {
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
		if sameOrInside(runtime.GOOS, cwd, dir) {
			t.Errorf("%s = %q is the CWD %q or inside it", name, dir, cwd)
		}
		if sameOrInside(runtime.GOOS, exeDir, dir) {
			t.Errorf("%s = %q is the executable dir %q or inside it", name, dir, exeDir)
		}
	}
}

// TestPathsReadOnlyInstallPrefix simulates a read-only install prefix (e.g. a
// Homebrew keg or an MSI Program Files directory): resolution must not return
// any path inside it, and an explicit override into it must be refused.
//
// The prefix comes from t.TempDir() and is therefore host-native, so this test
// resolves with runtime.GOOS: the executable-dir guard must see containment
// with the host's own separators, on Windows included.
func TestPathsReadOnlyInstallPrefix(t *testing.T) {
	prefix := t.TempDir()
	if err := os.Chmod(prefix, 0o555); err != nil {
		t.Fatalf("chmod install prefix: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(prefix, 0o755) })

	cfg, data, err := pathsFor(runtime.GOOS, stubEnv(nil), stubDir(testLinuxConfigBase), stubDir(testLinuxHome), stubDir(prefix))
	if err != nil {
		t.Fatalf("pathsFor() with read-only exec dir: %v", err)
	}
	if sameOrInside(runtime.GOOS, prefix, cfg) {
		t.Errorf("ConfigDir = %q is inside the read-only install prefix %q", cfg, prefix)
	}
	if sameOrInside(runtime.GOOS, prefix, data) {
		t.Errorf("DataDir = %q is inside the read-only install prefix %q", data, prefix)
	}

	// The write probe is meaningful on POSIX only; on Windows chmod cannot make
	// a directory unwritable. A privileged runner may also succeed, so a
	// successful write is reported rather than failed.
	if runtime.GOOS != "windows" {
		probe := filepath.Join(prefix, "probe.tmp")
		if werr := os.WriteFile(probe, []byte("probe"), 0o600); werr == nil {
			t.Logf("write probe into %q succeeded (privileged runner); read-only status not asserted", prefix)
			_ = os.Remove(probe)
		}
	}

	// An override aimed straight at the read-only prefix is refused. The
	// override is built with filepath.Join, i.e. host-native separators, so
	// runtime.GOOS is the only goos whose guard can see the containment.
	_, _, err = pathsFor(runtime.GOOS, stubEnv(map[string]string{homeEnvVar: filepath.Join(prefix, "data")}), stubDir(testLinuxConfigBase), stubDir(testLinuxHome), stubDir(prefix))
	if !errors.Is(err, ErrPathInExecDir) {
		t.Fatalf("pathsFor(override inside read-only prefix) error = %v, want ErrPathInExecDir", err)
	}

	entries, err := os.ReadDir(prefix)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", prefix, err)
	}
	if len(entries) != 0 {
		t.Fatalf("install prefix %q gained %d entries; path resolution must not write", prefix, len(entries))
	}
}

// TestPathsExecDirGuardSeparators locks the separator robustness of the
// executable-dir guard, the defect that made windows-latest red: a host-native
// prefix joined with filepath.Join produced backslashes while the simulated
// goos was "linux", so sameOrInside found no containment. Simulated-GOOS
// callers must keep paths and goos consistent; mixed-separator inputs must
// still be refused on Windows, and a backslash must never be treated as a
// separator on POSIX (where it is a legal filename byte).
func TestPathsExecDirGuardSeparators(t *testing.T) {
	// The exact shape CI executes on Windows: a host-native prefix (t.TempDir)
	// joined with filepath.Join must be refused on whichever OS runs the suite.
	t.Run("host_native_paths", func(t *testing.T) {
		prefix := t.TempDir()
		_, _, err := pathsFor(runtime.GOOS, stubEnv(map[string]string{homeEnvVar: filepath.Join(prefix, "data")}), stubDir(testLinuxConfigBase), stubDir(testLinuxHome), stubDir(prefix))
		if !errors.Is(err, ErrPathInExecDir) {
			t.Fatalf("host-native override inside %q was not refused: %v", prefix, err)
		}
	})

	tests := []struct {
		name        string
		goos        string
		override    string
		execDir     string
		wantRefused bool
	}{
		{
			name:        "windows_backslash_paths",
			goos:        "windows",
			override:    `C:\Program Files\tokenhush\data`,
			execDir:     `C:\Program Files\tokenhush`,
			wantRefused: true,
		},
		{
			name:        "windows_mixed_separators",
			goos:        "windows",
			override:    `C:/Program Files\tokenhush/data`,
			execDir:     `C:\Program Files\tokenhush`,
			wantRefused: true,
		},
		{
			name:        "windows_mixed_trailing_separators",
			goos:        "windows",
			override:    `C:\Program Files/tokenhush\data\`,
			execDir:     `C:/Program Files/tokenhush/`,
			wantRefused: true,
		},
		{
			name:        "windows_override_equals_exec_dir",
			goos:        "windows",
			override:    `C:\Program Files\Tokenhush`,
			execDir:     `C:\Program Files\tokenhush`,
			wantRefused: true,
		},
		{
			name:        "windows_sibling_not_refused",
			goos:        "windows",
			override:    `C:\Program Files\tokenhush-portable`,
			execDir:     `C:\Program Files\tokenhush`,
			wantRefused: false,
		},
		{
			name:        "posix_backslash_is_not_a_separator",
			goos:        "linux",
			override:    `/opt/tokenhush\data`,
			execDir:     `/opt/tokenhush`,
			wantRefused: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := pathsFor(tc.goos, stubEnv(map[string]string{homeEnvVar: tc.override}), stubDir(testLinuxConfigBase), stubDir(testLinuxHome), stubDir(tc.execDir))
			if refused := errors.Is(err, ErrPathInExecDir); refused != tc.wantRefused {
				t.Fatalf("pathsFor(goos=%q, override=%q, execDir=%q) error = %v, want refused=%v", tc.goos, tc.override, tc.execDir, err, tc.wantRefused)
			}
		})
	}
}

// TestPathsExecDirIndependence proves the resolved dirs do not depend on the
// executable's directory at all.
func TestPathsExecDirIndependence(t *testing.T) {
	wantConfig, wantData, err := pathsFor("linux", stubEnv(nil), stubDir(testLinuxConfigBase), stubDir(testLinuxHome), stubDir(testLinuxExec))
	if err != nil {
		t.Fatalf("pathsFor(): %v", err)
	}

	others := []struct {
		name    string
		execDir func() (string, error)
	}{
		{"other_dir", stubDir("/somewhere/else/bin")},
		{"error", stubErr(errors.New("executable lookup failed"))},
		{"nil", nil},
	}
	for _, other := range others {
		gotConfig, gotData, err := pathsFor("linux", stubEnv(nil), stubDir(testLinuxConfigBase), stubDir(testLinuxHome), other.execDir)
		if err != nil {
			t.Fatalf("%s: pathsFor() unexpected error: %v", other.name, err)
		}
		if gotConfig != wantConfig || gotData != wantData {
			t.Errorf("%s: pathsFor() = (%q, %q), want (%q, %q)", other.name, gotConfig, gotData, wantConfig, wantData)
		}
	}
}

// TestPathsConfigFile covers the config-file helper derived from ConfigDir.
func TestPathsConfigFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(homeEnvVar, dir)

	got, err := ConfigFile()
	if err != nil {
		t.Fatalf("ConfigFile(): %v", err)
	}
	want := filepath.Join(dir, configFileName)
	if got != want {
		t.Errorf("ConfigFile() = %q, want %q", got, want)
	}
}

// TestPathsConfigFileUnavailable asserts ConfigFile propagates the typed error
// when no config base can be resolved (and never falls back to the CWD).
func TestPathsConfigFileUnavailable(t *testing.T) {
	t.Setenv(homeEnvVar, "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("AppData", "")

	got, err := ConfigFile()
	if !errors.Is(err, ErrPathUnavailable) {
		t.Fatalf("ConfigFile() error = %v, want ErrPathUnavailable", err)
	}
	if got != "" {
		t.Fatalf("ConfigFile() = %q alongside error; want empty string", got)
	}
}

// TestPathsShellSnippetMode covers the POSIX/PowerShell discriminator consumed
// by internal/cli (and later W6.1).
func TestPathsShellSnippetMode(t *testing.T) {
	tests := []struct {
		goos string
		want ShellMode
	}{
		{"windows", ShellPowerShell},
		{"linux", ShellPOSIX},
		{"darwin", ShellPOSIX},
		{"freebsd", ShellPOSIX},
	}
	for _, tc := range tests {
		if got := shellSnippetModeFor(tc.goos); got != tc.want {
			t.Errorf("shellSnippetModeFor(%q) = %q, want %q", tc.goos, got, tc.want)
		}
	}
	if got := ShellSnippetMode(); got != shellSnippetModeFor(runtime.GOOS) {
		t.Errorf("ShellSnippetMode() = %q, want %q", got, shellSnippetModeFor(runtime.GOOS))
	}
}
