// Package layering enforces the one-directional package dependency graph of
// tokenhush (goal 4).
//
// One encoded graph plus one Check backs both the Go test in this directory
// and scripts/check-layering.sh, so CI and local runs reach identical verdicts.
//
// Two modes exist:
//
//   - green mode (default) tolerates packages and required edges that do not
//     exist yet. This keeps incremental waves green while the tree is still
//     being assembled.
//   - full-graph mode (TOKENHUSH_GUARD_FULL_GRAPH=1) turns every missing
//     expected package or required edge into a violation. It is the final gate.
//
// A present forbidden edge always fails, in both modes.
//
// Notable consequences of the graph:
//
//   - pkg/filter and pkg/redact are siblings: both may import pkg/protocol, but
//     neither may import the other.
//   - internal/guards and internal/layering are analysis-only packages. No
//     allowed set contains them, with the single exception of
//     internal/layering/cmd -> internal/layering.
//   - Directory testdata and anything below it are invisible to the guard, so
//     fixture packages can model forbidden edges without tripping the tool.
package layering

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
)

// FullGraphEnv toggles full-graph mode when set to "1".
const FullGraphEnv = "TOKENHUSH_GUARD_FULL_GRAPH"

// goListFormat is the exact go list template Load runs. It is deliberately
// plain (no custom template functions) so any supported Go toolchain renders
// it: the import path, then one space per direct import.
const goListFormat = `{{.ImportPath}}{{range .Imports}} {{.}}{{end}}`

// Violation is a package or edge that breaks the allowed graph.
type Violation struct {
	Package string
	Edge    Edge
	Reason  string
}

// Skip is a package or edge that green mode tolerates for now.
type Skip struct {
	Package string
	Edge    Edge
	Reason  string
}

// Result is the deterministic outcome of Check: violations fail the guard,
// skips are informational.
type Result struct {
	Violations []Violation
	Skips      []Skip
}

// OK reports whether the guard passed.
func (r Result) OK() bool { return len(r.Violations) == 0 }

// Graph is the discovered module structure: which internal packages exist and
// which internal import edges were seen.
type Graph struct {
	Present map[string]bool
	Edges   []Edge
}

// Options selects the strictness of Check.
type Options struct {
	// FullGraph reports missing expected packages and missing required edges
	// as violations instead of skips.
	FullGraph bool
}

// Check evaluates g against the encoded graph. Violations and skips are sorted
// by package and then edge so output is stable across runs.
func Check(g Graph, opts Options) Result {
	var res Result

	present := make(map[string]bool, len(g.Present))
	for pkg := range g.Present {
		if isTestdata(pkg) {
			continue
		}
		present[pkg] = true
	}

	// Expected-package check: missing keys are violations in full-graph mode
	// and skips in green mode.
	for _, pkg := range ExpectedPackages() {
		if present[pkg] {
			continue
		}
		reason := fmt.Sprintf("expected package %s does not exist yet", pkg)
		if opts.FullGraph {
			res.Violations = append(res.Violations, Violation{Package: pkg, Reason: reason})
		} else {
			res.Skips = append(res.Skips, Skip{Package: pkg, Reason: reason})
		}
	}

	// Unknown present package: the graph is closed-world in both modes.
	for pkg := range present {
		if _, ok := allowedGraph[pkg]; !ok {
			res.Violations = append(res.Violations, Violation{
				Package: pkg,
				Reason:  fmt.Sprintf("package %s is not in the allowed dependency graph", pkg),
			})
		}
	}

	// Edge check, after dropping every edge that touches testdata.
	for _, e := range g.Edges {
		if isTestdata(e.Source) || isTestdata(e.Target) {
			continue
		}
		if !present[e.Source] {
			res.Skips = append(res.Skips, Skip{
				Package: e.Source,
				Edge:    e,
				Reason:  fmt.Sprintf("source package does not exist yet: %s", e),
			})
			continue
		}
		if !present[e.Target] {
			if opts.FullGraph {
				res.Violations = append(res.Violations, Violation{
					Package: e.Source,
					Edge:    e,
					Reason:  fmt.Sprintf("missing required edge: %s (target %s does not exist)", e, e.Target),
				})
			} else {
				res.Skips = append(res.Skips, Skip{
					Package: e.Source,
					Edge:    e,
					Reason:  fmt.Sprintf("missing required edge, target does not exist yet: %s", e),
				})
			}
			continue
		}
		if !edgeAllowed(e.Source, e.Target) {
			res.Violations = append(res.Violations, Violation{
				Package: e.Source,
				Edge:    e,
				Reason:  fmt.Sprintf("forbidden internal import: %s", e),
			})
		}
	}

	sortResult(&res)
	return res
}

// edgeAllowed reports whether the graph permits source -> target.
func edgeAllowed(source, target string) bool {
	allowed, ok := allowedGraph[source]
	if !ok {
		return false
	}
	return slices.Contains(allowed, target)
}

// isTestdata reports whether an internal suffix is testdata and must therefore
// be invisible to the guard.
func isTestdata(pkg string) bool {
	switch {
	case pkg == "testdata", strings.HasPrefix(pkg, "testdata/"), strings.HasSuffix(pkg, "/testdata"):
		return true
	default:
		return strings.Contains(pkg, "/testdata/")
	}
}

// sortResult orders violations and skips deterministically.
func sortResult(res *Result) {
	sort.SliceStable(res.Violations, func(i, j int) bool {
		a, b := res.Violations[i], res.Violations[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Edge != b.Edge {
			return a.Edge.String() < b.Edge.String()
		}
		return a.Reason < b.Reason
	})
	sort.SliceStable(res.Skips, func(i, j int) bool {
		a, b := res.Skips[i], res.Skips[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Edge != b.Edge {
			return a.Edge.String() < b.Edge.String()
		}
		return a.Reason < b.Reason
	})
}

// Runner runs one command in dir and returns its stdout. It must honor ctx.
type Runner func(ctx context.Context, dir string, args ...string) ([]byte, error)

// RunCommand is the production Runner: go via exec.CommandContext with stdout
// captured and failures augmented with stderr.
var RunCommand Runner = func(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return stdout.Bytes(), nil
}

// Load discovers the module graph in dir by running go list exactly once.
//
// Output lines are `<import path> [direct imports...]`; only module-local
// packages and imports are recorded, testdata is filtered, and blank lines are
// skipped. An empty output yields an empty Graph and no error.
func Load(ctx context.Context, dir string, run Runner) (Graph, error) {
	if run == nil {
		run = RunCommand
	}
	if err := ctx.Err(); err != nil {
		return Graph{}, fmt.Errorf("layering: load %s: %w", dir, err)
	}
	out, err := run(ctx, dir, "list", "-f", goListFormat, "./...")
	if err != nil {
		return Graph{}, fmt.Errorf("layering: load %s: %w", dir, err)
	}
	if err := ctx.Err(); err != nil {
		return Graph{}, fmt.Errorf("layering: load %s: %w", dir, err)
	}
	return parseGoList(out), nil
}

// parseGoList turns go list output into a Graph without ever panicking.
func parseGoList(out []byte) Graph {
	g := Graph{Present: map[string]bool{}}
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		source, ok := internalSuffix(fields[0])
		if !ok || isTestdata(source) {
			continue
		}
		g.Present[source] = true
		for _, imp := range fields[1:] {
			target, ok := internalSuffix(imp)
			if !ok || isTestdata(target) {
				continue
			}
			g.Edges = append(g.Edges, Edge{Source: source, Target: target})
		}
	}
	return g
}

// internalSuffix maps a full import path to its module-relative suffix.
func internalSuffix(importPath string) (string, bool) {
	importPath = strings.ReplaceAll(importPath, "\\", "/")
	if importPath == ModulePath {
		return "", true
	}
	if !strings.HasPrefix(importPath, ModulePath+"/") {
		return "", false
	}
	return strings.TrimPrefix(importPath, ModulePath+"/"), true
}

// FullGraphEnabled reports whether full-graph mode is requested.
func FullGraphEnabled() bool { return os.Getenv(FullGraphEnv) == "1" }
