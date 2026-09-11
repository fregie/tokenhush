package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// appDirName is the per-application directory appended below every OS base
	// directory.
	appDirName = "tokenhush"

	// configFileName is the V1 configuration file (docs/13 §7).
	configFileName = "tokenhush.yaml"

	// homeEnvVar overrides both the config and the data directory. It exists
	// for tests and portable installs.
	homeEnvVar = "TOKENHUSH_HOME"

	// xdgDataHomeEnvVar and localAppDataEnvVar are the OS-specific bases that
	// receive the data directory.
	xdgDataHomeEnvVar  = "XDG_DATA_HOME"
	localAppDataEnvVar = "LOCALAPPDATA"
)

var (
	// ErrPathUnavailable reports that a required OS user directory (config or
	// home) could not be determined, for example because the relevant
	// environment variable is unset. Path resolution never falls back to the
	// current working directory, so callers must surface this error.
	ErrPathUnavailable = errors.New("platform: user directory unavailable")

	// ErrPathInExecDir reports that a resolved path would be the running
	// binary's own directory or live inside it. Homebrew kegs and MSI /
	// Program Files prefixes are read-only, so tokenhush refuses such a path
	// up front instead of failing later at write time.
	ErrPathInExecDir = errors.New("platform: path is inside the executable directory")
)

// ShellMode identifies the shell dialect used for snippets printed by the CLI.
type ShellMode string

const (
	// ShellPOSIX is the sh/bash/zsh dialect used on macOS, Linux and the BSDs.
	ShellPOSIX ShellMode = "posix"

	// ShellPowerShell is the dialect used on Windows.
	ShellPowerShell ShellMode = "powershell"
)

// ShellSnippetMode returns the shell dialect for the current OS: PowerShell on
// Windows, POSIX everywhere else. internal/cli uses this instead of branching
// on runtime.GOOS itself.
func ShellSnippetMode() ShellMode {
	return shellSnippetModeFor(runtime.GOOS)
}

// ConfigDir returns the directory that holds tokenhush's configuration
// (tokenhush.yaml), normally `<user config dir>/tokenhush`.
//
// TOKENHUSH_HOME, when set to a non-blank value, overrides the OS default for
// both ConfigDir and DataDir. Resolution never uses the current working
// directory or the executable's directory; a TOKENHUSH_HOME aimed at the
// latter is rejected with ErrPathInExecDir.
func ConfigDir() (string, error) {
	configDir, _, err := pathsFor(runtime.GOOS, os.Getenv, os.UserConfigDir, os.UserHomeDir, executableDir)
	return configDir, err
}

// DataDir returns the directory that holds tokenhush's persistent data (the
// audit database): `~/Library/Application Support/tokenhush` on macOS,
// `$XDG_DATA_HOME/tokenhush` (default `~/.local/share/tokenhush`) on Linux and
// `%LOCALAPPDATA%\tokenhush` on Windows. TOKENHUSH_HOME overrides it; see
// ConfigDir.
func DataDir() (string, error) {
	_, dataDir, err := pathsFor(runtime.GOOS, os.Getenv, os.UserConfigDir, os.UserHomeDir, executableDir)
	return dataDir, err
}

// ConfigFile returns the absolute path of the V1 configuration file,
// `<ConfigDir>/tokenhush.yaml` (docs/13 §7).
func ConfigFile() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return joinPath(runtime.GOOS, dir, configFileName), nil
}

// shellSnippetModeFor is the pure core of ShellSnippetMode.
func shellSnippetModeFor(goos string) ShellMode {
	if goos == "windows" {
		return ShellPowerShell
	}
	return ShellPOSIX
}

// executableDir returns the directory containing the running binary. It is
// consulted only to reject writes into a (possibly read-only) install prefix.
func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// pathsFor is the pure core of ConfigDir/DataDir. Every OS- and
// environment-dependent input is injected, so the darwin/linux/windows logic
// is testable from any host and runtime.GOOS stays confined to pkg/platform.
//
// Precedence: TOKENHUSH_HOME (trimmed, non-blank) wins for both directories;
// otherwise the OS defaults from docs/13 §3.1 apply. On success both returned
// directories are absolute and never point at the executable's directory. On
// error both are empty.
func pathsFor(
	goos string,
	getenv func(string) string,
	userConfigDir, userHomeDir, execDir func() (string, error),
) (configDir, dataDir string, err error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}

	if home := strings.TrimSpace(getenv(homeEnvVar)); home != "" {
		if err := rejectExecDir(goos, home, execDir); err != nil {
			return "", "", err
		}
		return home, home, nil
	}

	configBase, err := resolveUserDir("config", userConfigDir)
	if err != nil {
		return "", "", err
	}
	configDir = joinPath(goos, configBase, appDirName)

	dataBase, err := dataBaseFor(goos, getenv, userHomeDir)
	if err != nil {
		return "", "", err
	}
	dataDir = joinPath(goos, dataBase, appDirName)

	for _, dir := range []string{configDir, dataDir} {
		if err := rejectExecDir(goos, dir, execDir); err != nil {
			return "", "", err
		}
	}
	return configDir, dataDir, nil
}

// dataBaseFor resolves the OS base directory below which the per-app data
// directory lives. The standard library has no UserDataDir, so each OS is
// spelled out per docs/13 §3.1.
func dataBaseFor(goos string, getenv func(string) string, userHomeDir func() (string, error)) (string, error) {
	if goos == "windows" {
		local := strings.TrimSpace(getenv(localAppDataEnvVar))
		if local == "" {
			return "", fmt.Errorf("%w: %%%s%% is not defined", ErrPathUnavailable, localAppDataEnvVar)
		}
		return local, nil
	}

	// XDG base directory spec: $XDG_DATA_HOME must be absolute; blank and
	// relative values are ignored in favour of the home-relative default.
	if goos != "darwin" && goos != "ios" {
		if xdg := strings.TrimSpace(getenv(xdgDataHomeEnvVar)); strings.HasPrefix(xdg, "/") {
			return xdg, nil
		}
	}

	home, err := resolveUserDir("home", userHomeDir)
	if err != nil {
		return "", err
	}
	if goos == "darwin" || goos == "ios" {
		return joinPath(goos, home, "Library/Application Support"), nil
	}
	return joinPath(goos, home, ".local/share"), nil
}

// resolveUserDir validates an injected user-directory resolver. A nil resolver,
// a resolver error and a blank result all become ErrPathUnavailable so callers
// never see a half-resolved path.
func resolveUserDir(what string, resolve func() (string, error)) (string, error) {
	if resolve == nil {
		return "", fmt.Errorf("%w: %s resolver is nil", ErrPathUnavailable, what)
	}
	dir, err := resolve()
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrPathUnavailable, what, err)
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrPathUnavailable, what)
	}
	return dir, nil
}

// rejectExecDir returns ErrPathInExecDir when dir is the executable's directory
// or lives inside it. An unusable execDir resolver disables the guard rather
// than failing resolution: the guard is defence in depth, not an input.
func rejectExecDir(goos, dir string, execDir func() (string, error)) error {
	if execDir == nil {
		return nil
	}
	exe, err := execDir()
	if err != nil || strings.TrimSpace(exe) == "" {
		return nil
	}
	if sameOrInside(goos, exe, dir) {
		return fmt.Errorf("%w: %q", ErrPathInExecDir, dir)
	}
	return nil
}

// joinPath appends name to dir using the separator of goos. Windows results
// are normalised to backslashes so simulated-GOOS tests on a POSIX host see
// the same shape a real Windows build produces.
func joinPath(goos, dir, name string) string {
	if dir == "" {
		return name
	}
	var joined string
	switch {
	case strings.HasSuffix(dir, "/") || strings.HasSuffix(dir, `\`):
		joined = dir + name
	case goos == "windows":
		joined = dir + `\` + name
	default:
		joined = dir + "/" + name
	}
	if goos == "windows" {
		joined = strings.ReplaceAll(joined, "/", `\`)
	}
	return joined
}

// sameOrInside reports whether child is parent itself or nested below it,
// using pure string comparison (no filesystem access). Windows comparisons are
// case-insensitive because the platform's filesystems are.
func sameOrInside(goos, parent, child string) bool {
	if goos == "windows" {
		parent = strings.TrimRight(strings.ToLower(strings.ReplaceAll(parent, "/", `\`)), `\`)
		child = strings.TrimRight(strings.ToLower(strings.ReplaceAll(child, "/", `\`)), `\`)
		if parent == "" || child == "" {
			return false
		}
		return parent == child || strings.HasPrefix(child, parent+`\`)
	}

	parent = strings.TrimRight(parent, "/")
	child = strings.TrimRight(child, "/")
	if parent == "" || child == "" {
		return false
	}
	return parent == child || strings.HasPrefix(child, parent+"/")
}
