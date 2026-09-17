package platform

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// stubRuntime swaps the package-level runtime hooks so every OS branch is
// reachable on any host. The cleanup restores the previous hooks.
func stubRuntime(t *testing.T, goosName, home string, env map[string]string) {
	t.Helper()
	prevGoos, prevHome, prevLookup, prevExec := goos, userHomeDir, lookupEnv, executable
	goos = goosName
	userHomeDir = func() (string, error) { return home, nil }
	lookupEnv = func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}
	executable = func() (string, error) {
		return filepath.Join(string(filepath.Separator), "usr", "local", "bin", "tokenhush"), nil
	}
	t.Cleanup(func() {
		goos, userHomeDir, lookupEnv, executable = prevGoos, prevHome, prevLookup, prevExec
	})
}

func TestConfigDirAndDataDirPerOS(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		home   string
		env    map[string]string
		config string
		data   string
	}{
		{
			name:   "linux honours XDG_CONFIG_HOME and XDG_DATA_HOME",
			goos:   "linux",
			home:   "/home/u",
			env:    map[string]string{"XDG_CONFIG_HOME": "/xdg/config", "XDG_DATA_HOME": "/xdg/data"},
			config: filepath.Join("/xdg/config", "tokenhush"),
			data:   filepath.Join("/xdg/data", "tokenhush"),
		},
		{
			name:   "linux falls back to ~/.config and ~/.local/share",
			goos:   "linux",
			home:   "/home/u",
			config: filepath.Join("/home/u", ".config", "tokenhush"),
			data:   filepath.Join("/home/u", ".local", "share", "tokenhush"),
		},
		{
			name:   "linux honours a partial XDG override",
			goos:   "linux",
			home:   "/home/u",
			env:    map[string]string{"XDG_DATA_HOME": "/xdg/data"},
			config: filepath.Join("/home/u", ".config", "tokenhush"),
			data:   filepath.Join("/xdg/data", "tokenhush"),
		},
		{
			name:   "darwin uses Application Support config and Data",
			goos:   "darwin",
			home:   "/Users/u",
			config: filepath.Join("/Users/u", "Library", "Application Support", "tokenhush", "config"),
			data:   filepath.Join("/Users/u", "Library", "Application Support", "tokenhush", "Data"),
		},
		{
			name:   "windows uses %AppData% and %LocalAppData%",
			goos:   "windows",
			home:   "C:/Users/u",
			env:    map[string]string{"APPDATA": "C:/Users/u/AppData/Roaming", "LOCALAPPDATA": "C:/Users/u/AppData/Local"},
			config: filepath.Join("C:/Users/u/AppData/Roaming", "tokenhush"),
			data:   filepath.Join("C:/Users/u/AppData/Local", "tokenhush"),
		},
		{
			name:   "windows falls back to the profile AppData trees",
			goos:   "windows",
			home:   "C:/Users/u",
			config: filepath.Join("C:/Users/u", "AppData", "Roaming", "tokenhush"),
			data:   filepath.Join("C:/Users/u", "AppData", "Local", "tokenhush"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubRuntime(t, tt.goos, tt.home, tt.env)
			gotConfig, err := ConfigDir()
			if err != nil {
				t.Fatalf("ConfigDir() error = %v", err)
			}
			if gotConfig != tt.config {
				t.Errorf("ConfigDir() = %q, want %q", gotConfig, tt.config)
			}
			gotData, err := DataDir()
			if err != nil {
				t.Fatalf("DataDir() error = %v", err)
			}
			if gotData != tt.data {
				t.Errorf("DataDir() = %q, want %q", gotData, tt.data)
			}
		})
	}
}

func TestTokenhushHomeOverridesBothDirectories(t *testing.T) {
	for _, goosName := range []string{"linux", "darwin", "windows", "plan9"} {
		t.Run(goosName, func(t *testing.T) {
			stubRuntime(t, goosName, "/home/u", map[string]string{"TOKENHUSH_HOME": "/override"})
			gotConfig, err := ConfigDir()
			if err != nil {
				t.Fatalf("ConfigDir() error = %v", err)
			}
			if want := filepath.Join("/override", "config"); gotConfig != want {
				t.Errorf("ConfigDir() = %q, want %q", gotConfig, want)
			}
			gotData, err := DataDir()
			if err != nil {
				t.Fatalf("DataDir() error = %v", err)
			}
			if want := filepath.Join("/override", "data"); gotData != want {
				t.Errorf("DataDir() = %q, want %q", gotData, want)
			}
		})
	}
}

func TestEmptyTokenhushHomeFallsBackToOSLayout(t *testing.T) {
	stubRuntime(t, "linux", "/home/u", map[string]string{"TOKENHUSH_HOME": ""})
	got, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir() error = %v", err)
	}
	if want := filepath.Join("/home/u", ".config", "tokenhush"); got != want {
		t.Errorf("ConfigDir() = %q, want %q", got, want)
	}
}

func TestConfigDirRejectsHomeInsideExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable(): %v", err)
	}
	exeDir := filepath.Dir(exe)
	for _, home := range []string{exeDir, filepath.Join(exeDir, "nested")} {
		t.Run(home, func(t *testing.T) {
			t.Setenv("TOKENHUSH_HOME", home)
			if _, err := ConfigDir(); !errors.Is(err, ErrHomeInsideExecutable) {
				t.Errorf("ConfigDir() error = %v, want ErrHomeInsideExecutable", err)
			}
			if _, err := DataDir(); !errors.Is(err, ErrHomeInsideExecutable) {
				t.Errorf("DataDir() error = %v, want ErrHomeInsideExecutable", err)
			}
		})
	}
}

func TestTokenhushHomeSiblingOfExecutableIsAccepted(t *testing.T) {
	stubRuntime(t, "linux", "/home/u", map[string]string{"TOKENHUSH_HOME": "/opt/tokenhush-backup"})
	executable = func() (string, error) { return "/opt/app/tokenhush", nil }
	got, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir() error = %v", err)
	}
	if want := filepath.Join("/opt/tokenhush-backup", "config"); got != want {
		t.Errorf("ConfigDir() = %q, want %q", got, want)
	}
}

func TestHomeResolutionErrorIsReturned(t *testing.T) {
	stubRuntime(t, "linux", "", nil)
	homeErr := errors.New("no home")
	userHomeDir = func() (string, error) { return "", homeErr }
	if _, err := ConfigDir(); !errors.Is(err, homeErr) {
		t.Errorf("ConfigDir() error = %v, want wrapped %v", err, homeErr)
	}
	if _, err := DataDir(); !errors.Is(err, homeErr) {
		t.Errorf("DataDir() error = %v, want wrapped %v", err, homeErr)
	}
}

func TestExecutableResolutionErrorIsReturned(t *testing.T) {
	stubRuntime(t, "linux", "/home/u", map[string]string{"TOKENHUSH_HOME": "/override"})
	execErr := errors.New("no executable")
	executable = func() (string, error) { return "", execErr }
	if _, err := ConfigDir(); !errors.Is(err, execErr) {
		t.Errorf("ConfigDir() error = %v, want wrapped %v", err, execErr)
	}
}

func TestUnsupportedOSIsRejected(t *testing.T) {
	stubRuntime(t, "plan9", "/home/u", nil)
	if _, err := ConfigDir(); err == nil || !strings.Contains(err.Error(), "plan9") {
		t.Errorf("ConfigDir() error = %v, want an unsupported-OS error naming plan9", err)
	}
	if _, err := DataDir(); err == nil || !strings.Contains(err.Error(), "plan9") {
		t.Errorf("DataDir() error = %v, want an unsupported-OS error naming plan9", err)
	}
}

// TestExportedSurface pins the package API: exactly the two resolvers plus the
// sentinel, nothing else.
func TestExportedSurface(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "paths.go", nil, 0)
	if err != nil {
		t.Fatalf("parse paths.go: %v", err)
	}
	got := exportedNames(file)
	want := []string{"ConfigDir", "DataDir", "ErrHomeInsideExecutable"}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("exported names = %v, want exactly %v", got, want)
	}
}

// TestPackageImportsStdlibOnly proves the package stays on the standard
// library: no import path in paths.go carries a dot in its first segment.
func TestPackageImportsStdlibOnly(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "paths.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse paths.go: %v", err)
	}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		first := path
		if i := strings.Index(path, "/"); i >= 0 {
			first = path[:i]
		}
		if strings.Contains(first, ".") {
			t.Errorf("import %q is not stdlib", path)
		}
	}
}

// exportedNames returns the sorted exported package-level identifiers declared
// in file.
func exportedNames(file *ast.File) []string {
	var names []string
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() {
				names = append(names, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						names = append(names, s.Name.Name)
					}
				case *ast.ValueSpec:
					for _, name := range s.Names {
						if name.IsExported() {
							names = append(names, name.Name)
						}
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}
