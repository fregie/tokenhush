// Package platform resolves the per-OS directories tokenhush uses. It is a
// leaf: nothing but the standard library, and no secret store or service code.
//
// Layout by operating system:
//
//	linux:   ConfigDir = $XDG_CONFIG_HOME/tokenhush, else $HOME/.config/tokenhush
//	         DataDir   = $XDG_DATA_HOME/tokenhush,   else $HOME/.local/share/tokenhush
//	darwin:  ConfigDir = $HOME/Library/Application Support/tokenhush/config
//	         DataDir   = $HOME/Library/Application Support/tokenhush/Data
//	windows: ConfigDir = %AppData%\tokenhush
//	         DataDir   = %LocalAppData%\tokenhush
//
// Setting TOKENHUSH_HOME overrides both directories with one coherent layout:
// ConfigDir is <TOKENHUSH_HOME>/config and DataDir is <TOKENHUSH_HOME>/data.
// A TOKENHUSH_HOME that points at or inside the directory holding the running
// executable is rejected with ErrHomeInsideExecutable. An empty TOKENHUSH_HOME
// counts as unset.
package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrHomeInsideExecutable is returned when TOKENHUSH_HOME points at or inside
// the directory that holds the running executable.
var ErrHomeInsideExecutable = errors.New("platform: TOKENHUSH_HOME is inside the executable directory")

// homeEnv overrides both directories when it is set to a non-empty value.
const homeEnv = "TOKENHUSH_HOME"

const (
	configSubdir = "config"
	dataSubdir   = "data"
)

// Runtime hooks. Production values are the standard library; tests swap them
// so every OS branch is reachable on every host.
var (
	goos        = runtime.GOOS
	userHomeDir = os.UserHomeDir
	lookupEnv   = os.LookupEnv
	executable  = os.Executable
)

// ConfigDir returns the directory that holds tokenhush configuration.
func ConfigDir() (string, error) {
	config, _, err := dirs()
	return config, err
}

// DataDir returns the directory that holds tokenhush runtime data.
func DataDir() (string, error) {
	_, data, err := dirs()
	return data, err
}

// dirs resolves both directories so ConfigDir and DataDir can never disagree
// about the layout.
func dirs() (config, data string, err error) {
	if override, ok := lookupEnv(homeEnv); ok && override != "" {
		if err := rejectExecutableHome(override); err != nil {
			return "", "", err
		}
		return filepath.Join(override, configSubdir), filepath.Join(override, dataSubdir), nil
	}
	home, err := userHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("platform: resolve home directory: %w", err)
	}
	return resolveDirs(goos, home, lookupEnv)
}

// resolveDirs is the pure per-OS layout table. It never touches the
// environment itself: lookup supplies every variable.
func resolveDirs(goosName, home string, lookup func(string) (string, bool)) (config, data string, err error) {
	switch goosName {
	case "linux":
		config = filepath.Join(xdgBase(home, lookup, "XDG_CONFIG_HOME", ".config"), "tokenhush")
		data = filepath.Join(xdgBase(home, lookup, "XDG_DATA_HOME", filepath.Join(".local", "share")), "tokenhush")
	case "darwin":
		base := filepath.Join(home, "Library", "Application Support", "tokenhush")
		config = filepath.Join(base, configSubdir)
		data = filepath.Join(base, "Data")
	case "windows":
		config = filepath.Join(appDataBase(home, lookup), "tokenhush")
		data = filepath.Join(localAppDataBase(home, lookup), "tokenhush")
	default:
		return "", "", fmt.Errorf("platform: unsupported operating system %q", goosName)
	}
	return config, data, nil
}

// xdgBase returns the XDG base directory, falling back to home/fallback.
func xdgBase(home string, lookup func(string) (string, bool), env, fallback string) string {
	if value, ok := lookup(env); ok && value != "" {
		return value
	}
	return filepath.Join(home, fallback)
}

// appDataBase returns %AppData% (Roaming), falling back to the profile path.
func appDataBase(home string, lookup func(string) (string, bool)) string {
	if value, ok := lookup("APPDATA"); ok && value != "" {
		return value
	}
	return filepath.Join(home, "AppData", "Roaming")
}

// localAppDataBase returns %LocalAppData%, falling back to the profile path.
func localAppDataBase(home string, lookup func(string) (string, bool)) string {
	if value, ok := lookup("LOCALAPPDATA"); ok && value != "" {
		return value
	}
	return filepath.Join(home, "AppData", "Local")
}

// rejectExecutableHome fails when home points at or inside the directory that
// holds the running executable, where a data directory would be writable code.
func rejectExecutableHome(home string) error {
	exe, err := executable()
	if err != nil {
		return fmt.Errorf("platform: resolve executable: %w", err)
	}
	absHome, err := filepath.Abs(home)
	if err != nil {
		return fmt.Errorf("platform: resolve %s: %w", homeEnv, err)
	}
	exeDir := filepath.Dir(exe)
	if absHome == exeDir || strings.HasPrefix(absHome, exeDir+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s", ErrHomeInsideExecutable, home)
	}
	return nil
}
