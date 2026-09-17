package layering_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/internal/layering"
)

// fixtureEdge parses testdata/forbiddenedge/fixture.go and returns the single
// `source -> target` line it documents, asserting that the target also appears
// as a concrete import literal in the same file.
func fixtureEdge(t *testing.T) layering.Edge {
	t.Helper()
	path := filepath.Join("testdata", "forbiddenedge", "fixture.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(line, "//"))
		source, target, ok := strings.Cut(body, " -> ")
		if !ok {
			continue
		}
		source, target = strings.TrimSpace(source), strings.TrimSpace(target)
		if source == "" || target == "" {
			continue
		}
		if !strings.Contains(string(data), `"`+layering.ModulePath+"/"+target+`"`) {
			t.Fatalf("fixture does not contain the import literal %q for target %q", layering.ModulePath+"/"+target, target)
		}
		return layering.Edge{Source: source, Target: target}
	}
	t.Fatal("fixture has no `source -> target` line")
	return layering.Edge{}
}

func TestCheckDetectsForbiddenEdgeFromFixture(t *testing.T) {
	edge := fixtureEdge(t)
	if edge.Source != "pkg/supply" || edge.Target != "pkg/redact" {
		t.Fatalf("fixture edge = %s, want pkg/supply -> pkg/redact", edge)
	}

	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("full=%v", full), func(t *testing.T) {
			g := layering.Graph{
				Present: map[string]bool{edge.Source: true, edge.Target: true},
				Edges:   []layering.Edge{edge},
			}
			res := layering.Check(g, layering.Options{FullGraph: full})
			if res.OK() {
				t.Fatalf("Check(%s) = OK, want a violation in both green and full-graph mode", edge)
			}
			for _, v := range res.Violations {
				if v.Edge == edge && strings.Contains(v.Reason, edge.String()) {
					return
				}
			}
			t.Fatalf("no violation names edge %s: %+v", edge, res.Violations)
		})
	}
}

func TestCheckGreenSkipsMissingPackagesAndEdges(t *testing.T) {
	edge := layering.Edge{Source: "pkg/supply", Target: "pkg/filter"}
	g := layering.Graph{
		Present: map[string]bool{"pkg/supply": true},
		Edges:   []layering.Edge{edge},
	}
	res := layering.Check(g, layering.Options{})
	if !res.OK() {
		t.Fatalf("green Check = %+v, want OK", res.Violations)
	}

	edgeSkipped := false
	for _, s := range res.Skips {
		if s.Edge == edge {
			edgeSkipped = true
			if !strings.Contains(s.Reason, edge.String()) {
				t.Errorf("skip reason %q does not name edge %s", s.Reason, edge)
			}
		}
	}
	if !edgeSkipped {
		t.Fatalf("no skip for the missing edge %s: %+v", edge, res.Skips)
	}

	for _, pkg := range layering.ExpectedPackages() {
		if pkg == "pkg/supply" {
			continue
		}
		found := false
		for _, s := range res.Skips {
			if s.Package == pkg && s.Edge == (layering.Edge{}) {
				found = true
			}
		}
		if !found {
			t.Errorf("no skip for the missing expected package %s", pkg)
		}
	}
}

func TestCheckFullGraphFailsMissingEdgeTarget(t *testing.T) {
	edge := layering.Edge{Source: "pkg/supply", Target: "pkg/filter"}
	g := layering.Graph{
		Present: map[string]bool{"pkg/supply": true},
		Edges:   []layering.Edge{edge},
	}
	res := layering.Check(g, layering.Options{FullGraph: true})
	if res.OK() {
		t.Fatal("full-graph Check = OK, want a violation for the missing edge target")
	}
	for _, v := range res.Violations {
		if v.Edge == edge && strings.Contains(v.Reason, edge.String()) {
			return
		}
	}
	t.Fatalf("no violation names edge %s: %+v", edge, res.Violations)
}

func TestCheckFullGraphFailsMissingExpectedPackage(t *testing.T) {
	g := layering.Graph{Present: map[string]bool{"pkg/supply": true, "pkg/filter": true}}

	if res := layering.Check(g, layering.Options{}); !res.OK() {
		t.Fatalf("green Check = %+v, want OK", res.Violations)
	}

	res := layering.Check(g, layering.Options{FullGraph: true})
	if res.OK() {
		t.Fatal("full-graph Check = OK, want violations for every missing expected package")
	}
	for _, want := range []string{"pkg/platform", "cmd/tokenhush"} {
		found := false
		for _, v := range res.Violations {
			if strings.Contains(v.Reason, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no violation names the missing package %s: %+v", want, res.Violations)
		}
	}
}

func TestCheckRejectsSiblings(t *testing.T) {
	edges := []layering.Edge{
		{Source: "pkg/filter", Target: "pkg/redact"},
		{Source: "pkg/redact", Target: "pkg/filter"},
		{Source: "pkg/filter", Target: "pkg/protocol"},
		{Source: "pkg/redact", Target: "pkg/protocol"},
	}
	g := layering.Graph{
		Present: map[string]bool{"pkg/filter": true, "pkg/redact": true, "pkg/protocol": true},
		Edges:   edges,
	}
	res := layering.Check(g, layering.Options{})

	for _, e := range edges[:2] {
		found := false
		for _, v := range res.Violations {
			if v.Edge == e {
				found = true
			}
		}
		if !found {
			t.Errorf("no violation for the forbidden sibling edge %s", e)
		}
	}
	for _, e := range edges[2:] {
		for _, v := range res.Violations {
			if v.Edge == e {
				t.Errorf("unexpected violation for the allowed edge %s: %+v", e, v)
			}
		}
	}
}

func TestCheckRejectsAnalysisImports(t *testing.T) {
	edges := []layering.Edge{
		{Source: "pkg/proxy", Target: "internal/guards"},
		{Source: "internal/cli", Target: "internal/layering"},
		{Source: "internal/layering/cmd", Target: "internal/layering"},
	}
	g := layering.Graph{
		Present: map[string]bool{
			"pkg/proxy":             true,
			"internal/cli":          true,
			"internal/guards":       true,
			"internal/layering":     true,
			"internal/layering/cmd": true,
		},
		Edges: edges,
	}
	res := layering.Check(g, layering.Options{})

	for _, e := range edges[:2] {
		found := false
		for _, v := range res.Violations {
			if v.Edge == e {
				found = true
			}
		}
		if !found {
			t.Errorf("no violation for the analysis import %s", e)
		}
	}
	for _, v := range res.Violations {
		if v.Edge == edges[2] {
			t.Errorf("unexpected violation for the allowed analysis edge %s: %+v", edges[2], v)
		}
	}
}

func TestCheckIgnoresTestdata(t *testing.T) {
	testdataPkg := "internal/guards/testdata/fixturepkg"
	g := layering.Graph{
		Present: map[string]bool{testdataPkg: true},
		Edges:   []layering.Edge{{Source: testdataPkg, Target: "internal/guards"}},
	}

	res := layering.Check(g, layering.Options{})
	if !res.OK() {
		t.Fatalf("testdata package produced violations in green mode: %+v", res.Violations)
	}
	for _, s := range res.Skips {
		if strings.Contains(s.Package, "testdata") || strings.Contains(s.Reason, "testdata") {
			t.Errorf("skip mentions a testdata package: %+v", s)
		}
	}

	full := layering.Check(g, layering.Options{FullGraph: true})
	for _, v := range full.Violations {
		if strings.Contains(v.Package, "testdata") || strings.Contains(v.Reason, "testdata") {
			t.Errorf("violation mentions a testdata package: %+v", v)
		}
	}
}

func TestLoadParsesGoListOutput(t *testing.T) {
	output := strings.Join([]string{
		"github.com/fregie/tokenhush/pkg/platform",
		"",
		"github.com/fregie/tokenhush/pkg/redact github.com/fregie/tokenhush/pkg/protocol fmt",
		"github.com/fregie/tokenhush/pkg/supply github.com/fregie/tokenhush/pkg/platform github.com/fregie/tokenhush/pkg/filter",
		"github.com/fregie/tokenhush/internal/guards/testdata/fixturepkg github.com/fregie/tokenhush/internal/guards",
		"example.com/thirdparty/pkg github.com/fregie/tokenhush/pkg/audit",
		"",
	}, "\n")

	var gotDir string
	var gotArgs []string
	run := func(_ context.Context, dir string, args ...string) ([]byte, error) {
		gotDir = dir
		gotArgs = append([]string(nil), args...)
		return []byte(output), nil
	}

	g, err := layering.Load(context.Background(), "some/dir", run)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if gotDir != "some/dir" {
		t.Errorf("runner dir = %q, want some/dir", gotDir)
	}
	wantArgs := []string{"list", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./..."}
	if strings.Join(gotArgs, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("runner args = %q, want %q", gotArgs, wantArgs)
	}

	gotPresent := make([]string, 0, len(g.Present))
	for pkg := range g.Present {
		gotPresent = append(gotPresent, pkg)
	}
	sort.Strings(gotPresent)
	wantPresent := []string{"pkg/platform", "pkg/redact", "pkg/supply"}
	if strings.Join(gotPresent, " ") != strings.Join(wantPresent, " ") {
		t.Errorf("Present = %q, want %q", gotPresent, wantPresent)
	}

	wantEdges := []string{
		"pkg/redact -> pkg/protocol",
		"pkg/supply -> pkg/filter",
		"pkg/supply -> pkg/platform",
	}
	gotEdges := sortedEdgeStrings(g.Edges)
	if strings.Join(gotEdges, " ") != strings.Join(wantEdges, " ") {
		t.Errorf("Edges = %q, want %q", gotEdges, wantEdges)
	}
}

func TestLoadEmptyOutputIsNotAnError(t *testing.T) {
	g, err := layering.Load(context.Background(), ".", func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(g.Present) != 0 || len(g.Edges) != 0 {
		t.Fatalf("graph = %+v, want an empty graph and no error", g)
	}
}

func TestLoadReportsRunnerErrorAndHonorsContext(t *testing.T) {
	t.Run("runner error is wrapped", func(t *testing.T) {
		sentinel := errors.New("go list exploded")
		_, err := layering.Load(context.Background(), ".", func(context.Context, string, ...string) ([]byte, error) {
			return nil, sentinel
		})
		if err == nil || !errors.Is(err, sentinel) {
			t.Fatalf("Load error = %v, want it to wrap the runner error", err)
		}
	})

	t.Run("context deadline is propagated", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := layering.Load(ctx, ".", func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Load error = %v, want errors.Is(err, context.DeadlineExceeded)", err)
		}
	})
}

func TestFullGraphEnabled(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{value: "1", want: true},
		{value: "0", want: false},
		{value: "", want: false},
	} {
		t.Run("env="+tc.value, func(t *testing.T) {
			t.Setenv(layering.FullGraphEnv, tc.value)
			if got := layering.FullGraphEnabled(); got != tc.want {
				t.Errorf("FullGraphEnabled() with %s=%q = %v, want %v", layering.FullGraphEnv, tc.value, got, tc.want)
			}
		})
	}
}

func TestExpectedAndAllowedEncoding(t *testing.T) {
	if got := layering.Allowed("pkg/supply"); strings.Join(got, " ") != "pkg/filter pkg/platform" {
		t.Errorf("Allowed(pkg/supply) = %q, want [pkg/filter pkg/platform]", got)
	}
	if got := layering.Allowed("pkg/filter"); strings.Join(got, " ") != "pkg/audit pkg/protocol" {
		t.Errorf("Allowed(pkg/filter) = %q, want [pkg/audit pkg/protocol]", got)
	}
	if got := len(layering.ExpectedPackages()); got != 13 {
		t.Errorf("len(ExpectedPackages()) = %d, want 13", got)
	}
}

// allPackages and allEdges mirror the encoded graph exactly, pinning it from
// the outside so a silent table edit cannot pass the happy-path test.
var allPackages = []string{
	"pkg/platform",
	"pkg/audit",
	"pkg/protocol",
	"pkg/redact",
	"pkg/filter",
	"pkg/config",
	"pkg/supply",
	"pkg/proxy",
	"internal/guards",
	"internal/layering",
	"internal/layering/cmd",
	"internal/cli",
	"cmd/tokenhush",
}

var allEdges = []layering.Edge{
	{Source: "pkg/redact", Target: "pkg/protocol"},
	{Source: "pkg/filter", Target: "pkg/protocol"},
	{Source: "pkg/filter", Target: "pkg/audit"},
	{Source: "pkg/config", Target: "pkg/platform"},
	{Source: "pkg/supply", Target: "pkg/platform"},
	{Source: "pkg/supply", Target: "pkg/filter"},
	{Source: "pkg/proxy", Target: "pkg/protocol"},
	{Source: "pkg/proxy", Target: "pkg/redact"},
	{Source: "pkg/proxy", Target: "pkg/filter"},
	{Source: "pkg/proxy", Target: "pkg/audit"},
	{Source: "pkg/proxy", Target: "pkg/config"},
	{Source: "pkg/proxy", Target: "pkg/platform"},
	{Source: "internal/layering/cmd", Target: "internal/layering"},
	{Source: "internal/cli", Target: "pkg/platform"},
	{Source: "internal/cli", Target: "pkg/audit"},
	{Source: "internal/cli", Target: "pkg/protocol"},
	{Source: "internal/cli", Target: "pkg/redact"},
	{Source: "internal/cli", Target: "pkg/filter"},
	{Source: "internal/cli", Target: "pkg/config"},
	{Source: "internal/cli", Target: "pkg/supply"},
	{Source: "internal/cli", Target: "pkg/proxy"},
	{Source: "cmd/tokenhush", Target: "internal/cli"},
}

func TestCheckHappyGraph(t *testing.T) {
	present := make(map[string]bool, len(allPackages))
	for _, pkg := range allPackages {
		present[pkg] = true
	}
	g := layering.Graph{Present: present, Edges: allEdges}

	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("full=%v", full), func(t *testing.T) {
			res := layering.Check(g, layering.Options{FullGraph: full})
			if !res.OK() {
				t.Fatalf("Check = %+v, want OK", res.Violations)
			}
			if len(res.Skips) != 0 {
				t.Fatalf("Check skips = %+v, want none", res.Skips)
			}
		})
	}
}

func sortedEdgeStrings(edges []layering.Edge) []string {
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, e.String())
	}
	sort.Strings(out)
	return out
}
