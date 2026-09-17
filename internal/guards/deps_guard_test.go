// Package guards holds repository invariants that are cheap enough to check
// on every `go test ./...` run. The dependency guard is deliberately
// stdlib-only: it must not pull in golang.org/x/mod (Must-NOT-Have #14).
package guards

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// semverRE accepts the pinned version style used in go.mod requires.
var semverRE = regexp.MustCompile(`^v\d+\.\d+\.\d+([-+].+)?$`)

// goVersionRE accepts `go 1.25` and `go 1.25.0` but nothing outside 1.25.x.
var goVersionRE = regexp.MustCompile(`^1\.25(\.\d+)?$`)

// goModFile is the hand-parsed subset of go.mod this guard cares about.
type goModFile struct {
	module      string
	goDirective string
	direct      map[string]string // module path -> version, no `// indirect` marker
	indirect    map[string]string // module path -> version, marked `// indirect`
}

// parseGoMod parses go.mod content using the standard library only.
//
// It understands comment lines, single-line `require x vN`, and
// `require ( ... )` blocks with optional `// indirect` markers. It returns an
// error instead of panicking on malformed require entries.
func parseGoMod(content string) (goModFile, error) {
	mod := goModFile{direct: map[string]string{}, indirect: map[string]string{}}
	scanner := bufio.NewScanner(strings.NewReader(content))
	inRequireBlock := false
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		code, comment := splitGoModComment(scanner.Text())
		line := strings.TrimSpace(code)
		if line == "" {
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			if err := mod.addRequire(line, comment, lineNo); err != nil {
				return mod, err
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "module "):
			mod.module = strings.TrimSpace(strings.TrimPrefix(line, "module "))
		case strings.HasPrefix(line, "go "):
			mod.goDirective = strings.TrimSpace(strings.TrimPrefix(line, "go "))
		case line == "require (":
			inRequireBlock = true
		case strings.HasPrefix(line, "require "):
			if err := mod.addRequire(strings.TrimSpace(strings.TrimPrefix(line, "require ")), comment, lineNo); err != nil {
				return mod, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return mod, fmt.Errorf("scan go.mod: %w", err)
	}
	if inRequireBlock {
		return mod, fmt.Errorf("go.mod line %d: unterminated require block", lineNo)
	}
	return mod, nil
}

// addRequire records one require entry, e.g. `github.com/goccy/go-yaml v1.19.2`
// or the same line followed by a `// indirect` comment.
func (m *goModFile) addRequire(code, comment string, lineNo int) error {
	fields := strings.Fields(code)
	if len(fields) == 0 {
		return fmt.Errorf("go.mod line %d: empty require entry", lineNo)
	}
	path := fields[0]
	version := ""
	if len(fields) > 1 {
		version = fields[1]
	}
	if !semverRE.MatchString(version) {
		return fmt.Errorf("go.mod line %d: require %q has no valid semver version (got %q)", lineNo, path, version)
	}
	if strings.Contains(comment, "indirect") {
		m.indirect[path] = version
	} else {
		m.direct[path] = version
	}
	return nil
}

// splitGoModComment splits a go.mod line into its code and trailing `//` comment.
func splitGoModComment(line string) (code, comment string) {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i], line[i+2:]
	}
	return line, ""
}

// repoRoot locates the repository root from this test file's own path so the
// guard works regardless of the working directory go test runs from.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed: cannot locate the repository root")
	}
	// file is <root>/internal/guards/deps_guard_test.go
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

func TestGoModPinsOnlyTheYAMLDirectDependency(t *testing.T) {
	const wantModule = "github.com/fregie/tokenhush"
	// Must-NOT-Have #14: github.com/goccy/go-yaml is the single pinned
	// third-party dependency of the rewrite.
	wantDirect := map[string]string{
		"github.com/goccy/go-yaml": "v1.19.2",
	}
	// goccy/go-yaml v1.19.2 declares no requires of its own, so the rewrite
	// must have no indirect dependencies (and Must-NOT-Have #7 keeps the
	// deleted keyring dependency and its transitive modules out).
	wantIndirect := map[string]string{}

	content, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	mod, err := parseGoMod(string(content))
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}

	if mod.module != wantModule {
		t.Errorf("module path = %q, want %q", mod.module, wantModule)
	}
	if !goVersionRE.MatchString(mod.goDirective) {
		t.Errorf("go directive = %q, want it to match ^1.25 (e.g. 1.25 or 1.25.0)", mod.goDirective)
	}

	for path, version := range mod.direct {
		if _, ok := wantDirect[path]; !ok {
			t.Errorf("forbidden direct dependency %s %s: github.com/goccy/go-yaml is the only allowed direct third-party require", path, version)
		}
	}
	for path, wantVersion := range wantDirect {
		gotVersion, ok := mod.direct[path]
		switch {
		case !ok:
			t.Errorf("required direct dependency %s %s is missing from go.mod", path, wantVersion)
		case gotVersion != wantVersion:
			t.Errorf("direct dependency %s is pinned to %s, want %s", path, gotVersion, wantVersion)
		}
	}

	for path, version := range mod.indirect {
		if _, ok := wantIndirect[path]; !ok {
			t.Errorf("forbidden indirect dependency %s %s: the rewrite must have no indirect requires", path, version)
		}
	}
	for path, wantVersion := range wantIndirect {
		gotVersion, ok := mod.indirect[path]
		switch {
		case !ok:
			t.Errorf("required indirect dependency %s %s is missing from go.mod", path, wantVersion)
		case gotVersion != wantVersion:
			t.Errorf("indirect dependency %s is pinned to %s, want %s", path, gotVersion, wantVersion)
		}
	}
}

func TestParseGoModMalformedInputDoesNotPanic(t *testing.T) {
	malformed := []struct {
		name    string
		content string
	}{
		{
			name:    "require without version",
			content: "module example.com/m\n\ngo 1.25.0\n\nrequire github.com/goccy/go-yaml\n",
		},
		{
			name:    "require block entry without version",
			content: "module example.com/m\n\ngo 1.25.0\n\nrequire (\n\tgithub.com/goccy/go-yaml\n)\n",
		},
		{
			name:    "unterminated require block",
			content: "module example.com/m\n\ngo 1.25.0\n\nrequire (\n\tgithub.com/goccy/go-yaml v1.19.2\n",
		},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseGoMod(tc.content); err == nil {
				t.Errorf("parseGoMod(%q) succeeded, want a clean error for malformed input", tc.content)
			}
		})
	}

	// An empty go.mod must not panic either: the parser returns an empty
	// module and the guard's own assertions report the failure.
	mod, err := parseGoMod("")
	if err != nil {
		t.Fatalf("parseGoMod(\"\") returned error %v; empty input must surface via guard assertions, not a parser error", err)
	}
	if mod.module != "" || mod.goDirective != "" || len(mod.direct) != 0 || len(mod.indirect) != 0 {
		t.Errorf("parseGoMod(\"\") = %+v, want a zero value", mod)
	}
}
