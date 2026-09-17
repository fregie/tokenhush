// This file holds the encoded dependency graph: the internal packages the
// architecture expects, the edges they may form, and how an edge renders. The
// checker and the discovery code live in layering.go.
package layering

import "sort"

// ModulePath is the module path every internal layer suffix is relative to.
const ModulePath = "github.com/fregie/tokenhush"

// Edge is a directed internal import edge. Source and Target are internal
// suffixes such as "pkg/supply", not full import paths.
type Edge struct {
	Source string
	Target string
}

// String renders the edge so failures can name it exactly.
func (e Edge) String() string { return e.Source + " -> " + e.Target }

// allowedGraph is the single source of truth for the dependency direction.
// Every key is an expected package; the value lists the internal packages the
// key may import. An empty slice means "leaf: nothing internal below it".
var allowedGraph = map[string][]string{
	"pkg/platform": {},
	"pkg/audit":    {},
	"pkg/protocol": {},
	"pkg/redact":   {"pkg/protocol"},
	"pkg/filter":   {"pkg/protocol", "pkg/audit"},
	"pkg/config":   {"pkg/platform"},
	"pkg/supply":   {"pkg/platform", "pkg/filter"},
	"pkg/proxy": {
		"pkg/protocol",
		"pkg/redact",
		"pkg/filter",
		"pkg/audit",
		"pkg/config",
		"pkg/platform",
	},
	"internal/guards":       {},
	"internal/layering":     {},
	"internal/layering/cmd": {"internal/layering"},
	"internal/cli": {
		"pkg/platform",
		"pkg/audit",
		"pkg/protocol",
		"pkg/redact",
		"pkg/filter",
		"pkg/config",
		"pkg/supply",
		"pkg/proxy",
	},
	"cmd/tokenhush": {"internal/cli"},
}

// ExpectedPackages returns the sorted keys of the allowed graph.
func ExpectedPackages() []string {
	pkgs := make([]string, 0, len(allowedGraph))
	for pkg := range allowedGraph {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	return pkgs
}

// Allowed returns a sorted copy of the internal imports pkg may use. An
// unknown package gets no allowance: the graph is closed-world.
func Allowed(pkg string) []string {
	allowed, ok := allowedGraph[pkg]
	if !ok {
		return nil
	}
	out := append([]string(nil), allowed...)
	sort.Strings(out)
	return out
}
