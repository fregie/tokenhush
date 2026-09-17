// License guard: no copyleft dependency may enter the module graph, and every
// require in go.mod must expose a verifiable license file in the module cache.
package guards

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// copyleftPhrases are matched case-insensitively after whitespace runs are
// collapsed to single spaces. Bare GPL/LGPL/AGPL are covered by the long forms
// and by the short tokens below.
var copyleftPhrases = []string{
	"GNU GENERAL PUBLIC LICENSE",
	"GNU LESSER GENERAL PUBLIC LICENSE",
	"GNU LIBRARY GENERAL PUBLIC LICENSE",
	"GNU AFFERO GENERAL PUBLIC LICENSE",
	"AGPL",
	"GPL",
}

// isCopyleft reports whether text carries a GPL/LGPL/AGPL license, tolerating
// case and spacing differences.
func isCopyleft(text string) bool {
	normalized := strings.ToUpper(strings.Join(strings.Fields(text), " "))
	for _, phrase := range copyleftPhrases {
		if strings.Contains(normalized, phrase) {
			return true
		}
	}
	return false
}

// licenseViolations checks every module against its resolved license text and
// returns the sorted list of violations: unverifiable licenses and copyleft
// licenses are both forbidden.
func licenseViolations(mods []string, licenseText func(module string) (text string, found bool)) []string {
	var violations []string
	for _, module := range mods {
		text, found := licenseText(module)
		if !found {
			violations = append(violations, fmt.Sprintf("module %s: license not verifiable", module))
			continue
		}
		if isCopyleft(text) {
			violations = append(violations, fmt.Sprintf("module %s: copyleft license (GPL/AGPL) is forbidden", module))
		}
	}
	sort.Strings(violations)
	return violations
}

// requiredModulePaths returns every module path required by go.mod, direct and
// indirect, sorted.
func requiredModulePaths(t *testing.T) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	mod, err := parseGoMod(string(content))
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	seen := map[string]bool{}
	var paths []string
	for _, group := range []map[string]string{mod.direct, mod.indirect} {
		for path := range group {
			if seen[path] {
				continue
			}
			seen[path] = true
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths
}

// moduleCacheDir locates the Go module cache: `go env GOMODCACHE` first, then
// the environment, then GOPATH/pkg/mod, then ~/go/pkg/mod.
func moduleCacheDir(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "go", "env", "GOMODCACHE").Output(); err == nil {
		if dir := strings.TrimSpace(string(out)); dir != "" {
			return dir
		}
	}
	if dir := strings.TrimSpace(os.Getenv("GOMODCACHE")); dir != "" {
		return dir
	}
	if gopath := strings.TrimSpace(os.Getenv("GOPATH")); gopath != "" {
		return filepath.Join(gopath, "pkg", "mod")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("locate module cache: %v", err)
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

// escapeModulePath applies the Go module cache's `!`-escaping for upper-case
// letters: github.com/BurntSushi/toml -> github.com/!burnt!sushi/toml.
func escapeModulePath(module string) string {
	var b strings.Builder
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// decodeModuleElement reverses the `!`-escaping of one cache path element.
func decodeModuleElement(element string) string {
	var b strings.Builder
	for i := 0; i < len(element); i++ {
		if element[i] == '!' && i+1 < len(element) && element[i+1] >= 'a' && element[i+1] <= 'z' {
			b.WriteByte(element[i+1] - ('a' - 'A'))
			i++
			continue
		}
		b.WriteByte(element[i])
	}
	return b.String()
}

// moduleCandidates returns every module cache directory that holds a copy of
// module: the raw spelling, then the `!`-escaped spelling, and finally a
// basename walk for caches with a different layout.
func moduleCandidates(cache, module string) []string {
	var dirs []string
	for _, pattern := range []string{module, escapeModulePath(module)} {
		matches, err := filepath.Glob(filepath.Join(cache, pattern+"@*"))
		if err != nil {
			continue
		}
		dirs = append(dirs, matches...)
	}
	if len(dirs) > 0 {
		sort.Strings(dirs)
		return dirs
	}

	base := lastPathElement(module)
	_ = filepath.WalkDir(cache, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		at := strings.Index(name, "@")
		if at > 0 {
			if decodeModuleElement(name[:at]) == base {
				dirs = append(dirs, path)
			}
			return filepath.SkipDir
		}
		return nil
	})
	sort.Strings(dirs)
	return dirs
}

// moduleLicenseText finds and reads a LICENSE*/COPYING* file for module in the
// module cache. found is false when no readable license file exists.
func moduleLicenseText(t *testing.T, cache, module string) (string, bool) {
	t.Helper()
	for _, dir := range moduleCandidates(cache, module) {
		for _, pattern := range []string{"LICENSE*", "COPYING*"} {
			matches, err := filepath.Glob(filepath.Join(dir, pattern))
			if err != nil {
				continue
			}
			sort.Strings(matches)
			for _, match := range matches {
				info, err := os.Stat(match)
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				data, err := os.ReadFile(match)
				if err != nil {
					continue
				}
				return string(data), true
			}
		}
	}
	return "", false
}

func TestLicenseGuardRejectsCopyleft(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		found   bool
		wantHit string
	}{
		{
			name:    "AGPL",
			text:    "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007",
			found:   true,
			wantHit: "copyleft license (GPL/AGPL) is forbidden",
		},
		{
			name:    "GPL",
			text:    "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991",
			found:   true,
			wantHit: "copyleft license (GPL/AGPL) is forbidden",
		},
		{
			name:    "LGPL",
			text:    "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999",
			found:   true,
			wantHit: "copyleft license (GPL/AGPL) is forbidden",
		},
		{
			name:    "irregular whitespace and case",
			text:    "gnu  general\tpublic\nlicense",
			found:   true,
			wantHit: "copyleft license (GPL/AGPL) is forbidden",
		},
		{
			name:  "MIT is fine",
			text:  "MIT License\n\nCopyright (c) 2024 Example\n\nPermission is hereby granted, free of charge...",
			found: true,
		},
		{
			name:    "license not found",
			found:   false,
			wantHit: "license not verifiable",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := licenseViolations([]string{"example.com/mod"}, func(string) (string, bool) {
				return tc.text, tc.found
			})
			if tc.wantHit == "" {
				if len(got) != 0 {
					t.Fatalf("licenseViolations() = %v, want no violations", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("licenseViolations() = %v, want exactly one violation", got)
			}
			if !strings.Contains(got[0], "example.com/mod") || !strings.Contains(got[0], tc.wantHit) {
				t.Errorf("licenseViolations() = %q, want it to name example.com/mod and %q", got[0], tc.wantHit)
			}
		})
	}
}

func TestLicenseGuardProductTree(t *testing.T) {
	mods := requiredModulePaths(t)
	if len(mods) == 0 {
		t.Fatal("go.mod requires no modules; the license guard would be vacuous")
	}
	cache := moduleCacheDir(t)
	violations := licenseViolations(mods, func(module string) (string, bool) {
		return moduleLicenseText(t, cache, module)
	})
	for _, v := range violations {
		t.Errorf("%s", v)
	}
}
