package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// cliRepoRoot is the repository root, derived from this file's location
// (<root>/internal/cli/privacy_test.go).
func cliRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// privacyOutput runs the privacy command and returns its exit code and streams.
func privacyOutput(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := privacyCommand(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// runEgressGenerator runs egress_gen.go exactly as `go generate` does (the
// same file, the same package directory) with extra arguments.
func runEgressGenerator(t *testing.T, repo string, args ...string) ([]byte, error) {
	t.Helper()
	command := exec.Command("go", append([]string{"run", "egress_gen.go"}, args...)...)
	command.Dir = filepath.Join(repo, "internal", "cli")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// egressDrift regenerates the disclosure from yamlPath and compares it with
// the committed egress_generated.go. It returns one sorted violation per
// disagreement; an empty result means the committed file is current.
func egressDrift(t *testing.T, repo, yamlPath string) []string {
	t.Helper()
	regenerated, err := runEgressGenerator(t, repo, "-in", yamlPath, "-stdout")
	if err != nil {
		return []string{"egress_gen.go failed: " + err.Error()}
	}
	committed, err := os.ReadFile(filepath.Join(repo, "internal", "cli", "egress_generated.go"))
	if err != nil {
		t.Fatalf("read egress_generated.go: %v", err)
	}
	if !bytes.Equal(regenerated, committed) {
		return []string{"egress_generated.go is stale: run `go generate ./internal/cli`"}
	}
	return nil
}

// TestPrivacyTextListsExactlyTwoCategories pins the human-readable disclosure:
// exactly two categories, each naming its switch, host and retention.
func TestPrivacyTextListsExactlyTwoCategories(t *testing.T) {
	code, stdout, stderr := privacyOutput(t)
	if code != exitOK {
		t.Fatalf("privacy = %d, want %d (stderr %q)", code, exitOK, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != len(egressDisclosure)+1 {
		t.Fatalf("privacy text has %d lines, want a header plus %d categories:\n%s", len(lines), len(egressDisclosure), stdout)
	}
	if !strings.Contains(lines[0], "2 vendor-bound categories") {
		t.Errorf("privacy text header %q does not name the two categories", lines[0])
	}
	for _, category := range egressDisclosure {
		index := slices.IndexFunc(lines, func(line string) bool {
			return strings.HasPrefix(line, category.Name+":")
		})
		if index < 0 {
			t.Errorf("privacy text has no line for category %s:\n%s", category.Name, stdout)
			continue
		}
		for _, want := range []string{category.Switch, category.Host, category.Retention} {
			if !strings.Contains(lines[index], want) {
				t.Errorf("privacy line for %s does not name %q:\n%s", category.Name, want, lines[index])
			}
		}
	}
}

// TestPrivacyJSONListsTwoCategories pins the machine-readable disclosure: the
// document carries exactly two categories and every one names its switch and
// retention.
func TestPrivacyJSONListsTwoCategories(t *testing.T) {
	code, stdout, stderr := privacyOutput(t, "--json")
	if code != exitOK {
		t.Fatalf("privacy --json = %d, want %d (stderr %q)", code, exitOK, stderr)
	}
	var doc egressDisclosureDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decode privacy --json: %v (output %q)", err, stdout)
	}
	if len(doc.Categories) != 2 {
		t.Fatalf("privacy --json lists %d categories, want exactly 2", len(doc.Categories))
	}
	names := make([]string, 0, len(doc.Categories))
	switches := make([]string, 0, len(doc.Categories))
	for _, category := range doc.Categories {
		if category.Name == "" || category.Switch == "" || category.Host == "" || category.Retention == "" {
			t.Errorf("category %+v must name name, switch, host and retention", category)
		}
		names = append(names, category.Name)
		switches = append(switches, category.Switch)
	}
	slices.Sort(names)
	slices.Sort(switches)
	wantNames := []string{"rule-sync", "update-check"}
	if !slices.Equal(names, wantNames) {
		t.Errorf("privacy --json category names = %v, want %v", names, wantNames)
	}
	wantSwitches := []string{"TOKENHUSH_NO_RULE_SYNC", "TOKENHUSH_NO_UPDATE_CHECK"}
	if !slices.Equal(switches, wantSwitches) {
		t.Errorf("privacy --json switches = %v, want %v", switches, wantSwitches)
	}
}

// TestPrivacyRejectsUnexpectedArgument pins the usage error.
func TestPrivacyRejectsUnexpectedArgument(t *testing.T) {
	code, _, stderr := privacyOutput(t, "vendor")
	if code != exitUsage {
		t.Fatalf("privacy vendor = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "privacy") {
		t.Errorf("stderr = %q, want it to name the command", stderr)
	}
}

// TestEgressGeneratedMatchesYAML is the drift test: the committed generated
// file must equal a fresh render of egress.yaml, and a scratch disclosure with
// a third category must make it fail.
func TestEgressGeneratedMatchesYAML(t *testing.T) {
	repo := cliRepoRoot(t)
	committed, err := os.ReadFile(filepath.Join(repo, "internal", "cli", "egress_generated.go"))
	if err != nil {
		t.Fatalf("read egress_generated.go: %v", err)
	}
	if !bytes.Contains(committed, []byte("Code generated")) || !bytes.Contains(committed, []byte("DO NOT EDIT")) {
		t.Fatalf("egress_generated.go lacks the generated-file marker")
	}

	t.Run("the committed file is current", func(t *testing.T) {
		if drift := egressDrift(t, repo, filepath.Join(repo, "egress.yaml")); len(drift) != 0 {
			t.Errorf("egress_generated.go drifted from egress.yaml: %v", drift)
		}
	})

	t.Run("regeneration rewrites the same bytes", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "egress_generated.go")
		if _, err := runEgressGenerator(t, repo, "-in", filepath.Join(repo, "egress.yaml"), "-out", out); err != nil {
			t.Fatalf("generate to %s: %v", out, err)
		}
		rewritten, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read %s: %v", out, err)
		}
		if !bytes.Equal(rewritten, committed) {
			t.Errorf("regenerating egress_generated.go changed it (`go generate ./...` would dirty the tree)")
		}
	})

	t.Run("a third category is drift", func(t *testing.T) {
		source, err := os.ReadFile(filepath.Join(repo, "egress.yaml"))
		if err != nil {
			t.Fatalf("read egress.yaml: %v", err)
		}
		scratch := filepath.Join(t.TempDir(), "egress.yaml")
		third := "\n  - name: analytics\n    switch: TOKENHUSH_EGRESS_ANALYTICS\n    host: analytics.example.test\n    retention: none\n"
		if err := os.WriteFile(scratch, append(source, []byte(third)...), 0o600); err != nil {
			t.Fatalf("write scratch egress.yaml: %v", err)
		}
		if drift := egressDrift(t, repo, scratch); len(drift) == 0 {
			t.Error("a third egress category did not make the drift test fail")
		}
	})
}
