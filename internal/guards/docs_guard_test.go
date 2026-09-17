// docs_guard_test.go asserts that the command set documented across the eight
// D8 doc files equals the CLI's real command set (see realCLICommands).
//
// The synthetic half (TestDocsGuardCommandSet) always runs and is the positive
// control for documentedCommands + commandSetViolations. The product half
// (TestDocsGuardProductTree) skips with the recorded "docs" guard id until both
// docs/ and internal/cli exist (product half completes in W6.5); once both are
// present it fails only on present-but-forbidden facts: an undocumented CLI
// command, a documented command the CLI does not have, or an unexpected file
// under docs/ (including docs/README.md).
package guards

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// d8Docs is the D8 documentation set: every one of these files must exist.
var d8Docs = []string{
	"README.md",
	"README.zh-CN.md",
	"docs/architecture.md",
	"docs/architecture.zh-CN.md",
	"docs/security.md",
	"docs/security.zh-CN.md",
	"docs/plugins.md",
	"docs/plugins.zh-CN.md",
}

// extraAllowedDocs are non-D8 files permitted under docs/.
var extraAllowedDocs = []string{"docs/PRO-MIGRATION.md"}

// realCLICommands is the CLI's real command set. Keep in sync with the command
// registration in internal/cli (W6.5).
var realCLICommands = []string{"run", "rules", "update", "status", "env", "version", "privacy"}

var (
	docsBacktickRe = regexp.MustCompile("`([^`\n]+)`")
	docsCommandRe  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// documentedCommands extracts every command named as `tokenhush <cmd>` or as a
// fenced-code line starting with "tokenhush <cmd>". Trailing words and flags
// are ignored. The result is distinct and sorted.
func documentedCommands(text string) []string {
	seen := map[string]bool{}
	record := func(token string) {
		fields := strings.Fields(token)
		if len(fields) < 2 || fields[0] != "tokenhush" {
			return
		}
		cmd := fields[1]
		if !docsCommandRe.MatchString(cmd) {
			return
		}
		seen[cmd] = true
	}
	for _, m := range docsBacktickRe.FindAllStringSubmatch(text, -1) {
		record(m[1])
	}
	inFence := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence && strings.HasPrefix(line, "tokenhush ") {
			record(line)
		}
	}
	out := make([]string, 0, len(seen))
	for cmd := range seen {
		out = append(out, cmd)
	}
	sort.Strings(out)
	return out
}

// commandSetViolations reports every mismatch between the documented command
// set and the CLI's real command set. The result is sorted and deduplicated.
func commandSetViolations(documented, real []string) []string {
	docSet := guardsStringSet(documented)
	realSet := guardsStringSet(real)
	var out []string
	if len(docSet) == 0 {
		out = append(out, "documented command set is empty")
	}
	for cmd := range docSet {
		if !realSet[cmd] {
			out = append(out, fmt.Sprintf("documented command %s does not exist in the CLI", cmd))
		}
	}
	for cmd := range realSet {
		if !docSet[cmd] {
			out = append(out, fmt.Sprintf("CLI command %s is not documented", cmd))
		}
	}
	sort.Strings(out)
	return guardsUniqueStrings(out)
}

// guardsStringSet builds a set from non-empty strings.
func guardsStringSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		if item != "" {
			set[item] = true
		}
	}
	return set
}

// guardsUniqueStrings removes duplicates, preserving first-seen order.
func guardsUniqueStrings(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

// guardsPathIsDir reports whether path exists and is a directory.
func guardsPathIsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// guardsPathExists reports whether path exists at all.
func guardsPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestDocsGuardCommandSet is the always-running positive control: it proves the
// extractor finds commands in both documented shapes and that violations name
// both a documented-but-not-real command and every missing real command.
func TestDocsGuardCommandSet(t *testing.T) {
	partial := "# Docs\n\nStart with `tokenhush run --deep`.\n\n```sh\ntokenhush doctor\n```\n\nThen `tokenhush rules` lists the rules.\n"
	got := documentedCommands(partial)
	want := []string{"doctor", "rules", "run"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("documentedCommands = %v, want %v", got, want)
	}

	violations := commandSetViolations(got, realCLICommands)
	if !guardsContainsString(violations, "documented command doctor does not exist in the CLI") {
		t.Errorf("violations = %v, want documented-but-not-real doctor", violations)
	}
	for _, missing := range []string{"status", "env", "version", "privacy", "update"} {
		wanted := "CLI command " + missing + " is not documented"
		if !guardsContainsString(violations, wanted) {
			t.Errorf("violations = %v, want %q", violations, wanted)
		}
	}
	for _, bogus := range []string{
		"documented command run does not exist in the CLI",
		"documented command rules does not exist in the CLI",
	} {
		if guardsContainsString(violations, bogus) {
			t.Errorf("violations = %v, unexpected %q", violations, bogus)
		}
	}

	if v := commandSetViolations(nil, realCLICommands); !guardsContainsString(v, "documented command set is empty") {
		t.Errorf("violations = %v, want emptiness violation", v)
	}

	var matching strings.Builder
	matching.WriteString("# Commands\n\n")
	for _, cmd := range realCLICommands {
		fmt.Fprintf(&matching, "`tokenhush %s`\n\n", cmd)
	}
	if v := commandSetViolations(documentedCommands(matching.String()), realCLICommands); len(v) != 0 {
		t.Errorf("matching doc produced violations: %v", v)
	}
}

// guardsContainsString reports whether items contains want.
func guardsContainsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// TestDocsGuardProductTree checks the real documentation tree and command set.
// It skips (with the recorded "docs" guard id) until docs/ and internal/cli
// both exist, so every wave stays green while the product half is absent.
func TestDocsGuardProductTree(t *testing.T) {
	root := repoRoot(t)
	docsDir := filepath.Join(root, "docs")
	cliDir := filepath.Join(root, "internal", "cli")
	if !guardsPathIsDir(docsDir) || !guardsPathIsDir(cliDir) {
		skipGuard(t, "docs", "docs and CLI not written yet (product half completes in W6.5)")
		return
	}

	expected := map[string]bool{}
	for _, rel := range d8Docs {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(abs); err != nil {
			t.Errorf("doc %s is missing: %v", rel, err)
		}
		if strings.HasPrefix(rel, "docs/") {
			expected[strings.TrimPrefix(rel, "docs/")] = true
		}
	}
	for _, rel := range extraAllowedDocs {
		expected[strings.TrimPrefix(rel, "docs/")] = true
	}

	actual := map[string]bool{}
	walkErr := filepath.WalkDir(docsDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(docsDir, path)
		if relErr != nil {
			return relErr
		}
		actual[filepath.ToSlash(rel)] = true
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk docs/: %v", walkErr)
	}
	for file := range actual {
		if !expected[file] {
			t.Errorf("unexpected file under docs/: %s", file)
		}
	}
	for file := range expected {
		if !actual[file] {
			t.Errorf("required file missing under docs/: %s", file)
		}
	}

	var documented []string
	for _, rel := range d8Docs {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		documented = append(documented, documentedCommands(string(data))...)
	}
	for _, violation := range commandSetViolations(documented, realCLICommands) {
		t.Error(violation)
	}
}
