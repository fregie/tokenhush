package guards

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ciPathPattern matches every repo-relative path the CI guard cares about:
// guard and layering sources, helper scripts, and root config files.
var ciPathPattern = regexp.MustCompile(`(?:internal/guards/[A-Za-z0-9_./-]+|internal/layering/[A-Za-z0-9_./-]+|scripts/[A-Za-z0-9_./-]+|\.gitleaks\.toml|\.golangci\.yml|\.goreleaser\.yaml)`)

// ciReferencedPaths extracts every repo-relative path referenced by a CI
// workflow or release config. Tokens are trimmed of trailing punctuation,
// deduplicated and sorted.
func ciReferencedPaths(workflow string) []string {
	raw := ciPathPattern.FindAllString(workflow, -1)
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimRight(p, ".,;:\"'`)]}")
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ciConfigViolations reports every defect in a CI workflow string. exists is
// the filesystem oracle for referenced repo-relative paths.
func ciConfigViolations(workflow string, exists func(rel string) bool) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(v string) {
		if seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	if exists != nil {
		for _, p := range ciReferencedPaths(workflow) {
			if !exists(p) {
				add("workflow references missing path " + p)
			}
		}
	}

	if strings.Contains(workflow, "TOKENHUSH_GUARD_FULL_GRAPH") {
		add("workflow must not export TOKENHUSH_GUARD_FULL_GRAPH")
	}

	required := []struct {
		fragment string
		message  string
	}{
		{"go build ./...", `workflow must run "go build ./..."`},
		{"go vet ./...", `workflow must run "go vet ./..."`},
		{"go test ./...", `workflow must run "go test ./..."`},
		{"bash scripts/check-layering.sh", `workflow must run "bash scripts/check-layering.sh"`},
		{"GOOS=darwin GOARCH=arm64", "workflow must cross-build GOOS=darwin GOARCH=arm64"},
		{"GOOS=linux GOARCH=amd64", "workflow must cross-build GOOS=linux GOARCH=amd64"},
		{"GOOS=windows GOARCH=amd64", "workflow must cross-build GOOS=windows GOARCH=amd64"},
		{"gitleaks", "workflow must run the secret scan"},
		{"golangci-lint", "workflow must run golangci-lint"},
	}
	for _, r := range required {
		if !strings.Contains(workflow, r.fragment) {
			add(r.message)
		}
	}

	sort.Strings(out)
	return out
}

// releaseConfigViolations reports every missing target marker in a goreleaser
// config: the effective build matrix plus checksum publication.
func releaseConfigViolations(config string) []string {
	var out []string
	for _, token := range []string{"darwin", "arm64", "linux", "amd64", "windows", "checksums.txt"} {
		if !strings.Contains(config, token) {
			out = append(out, "release config missing "+token)
		}
	}
	sort.Strings(out)
	return out
}

// readRepoFile reads a repo-relative file rooted at repoRoot(t).
func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestCIConfigRejectsMissingPath(t *testing.T) {
	t.Parallel()
	workflow := `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: go build ./...
      - run: go vet ./...
      - run: go test ./...
      - run: bash scripts/check-layering.sh
      - run: gitleaks dir .
      - run: golangci-lint run ./...
      - run: CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./...
      - run: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
      - run: CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...
`
	// exists: only the synthetic bogus path is absent.
	exists := func(rel string) bool {
		return rel != "internal/guards/nope_guard_test.go"
	}
	withBadRef := workflow + "      - run: go test ./internal/guards/nope_guard_test.go\n"
	violations := ciConfigViolations(withBadRef, exists)
	found := false
	for _, v := range violations {
		if v == "workflow references missing path internal/guards/nope_guard_test.go" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing-path violation, got %v", violations)
	}
}

func TestCIConfigProductTree(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")
	exists := func(rel string) bool {
		_, err := os.Stat(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
		return err == nil
	}
	if got := ciConfigViolations(workflow, exists); len(got) != 0 {
		t.Fatalf("ci.yml violations: %v", got)
	}
}

func TestReleaseConfigProductTree(t *testing.T) {
	config := readRepoFile(t, ".goreleaser.yaml")
	if got := releaseConfigViolations(config); len(got) != 0 {
		t.Fatalf(".goreleaser.yaml violations: %v", got)
	}
}
