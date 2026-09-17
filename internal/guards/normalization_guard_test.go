// Normalization guard: Must-NOT-Have #19 forbids base64/hex/URL/gzip
// normalization of request content before detection. Invariant 7 still lets the
// proxy decode HTTP Content-Encoding, so decoding itself is not banned — it is
// confined to an explicit allowlist of sites instead.
//
// Assertions:
//
//	(a) no normalize*/normalization* module exists;
//	(b) only allowlisted files may import a decoder package;
//	(c) no decoded value may be handed to a detector entry point (Inspect).
package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// decoderImportPaths are the stdlib packages that decode or decompress bytes.
var decoderImportPaths = map[string]bool{
	"encoding/base64": true,
	"encoding/hex":    true,
	"compress/gzip":   true,
	"compress/flate":  true,
	"compress/zlib":   true,
}

// decoderSiteExactFiles are the individually allowlisted decoder sites.
var decoderSiteExactFiles = map[string]bool{
	"pkg/filter/primitive_jwt.go": true,
	"pkg/redact/placeholder.go":   true,
}

// decodeCallNames are selector names that decode a payload. NewReader is
// handled separately because only the compress packages' NewReader decompresses.
var decodeCallNames = map[string]bool{
	"Decode":       true,
	"DecodeString": true,
	"DecodeAll":    true,
}

// compressionImportPaths are the packages whose NewReader decompresses.
var compressionImportPaths = map[string]bool{
	"compress/gzip":  true,
	"compress/flate": true,
	"compress/zlib":  true,
}

// walkGoFileRels walks root and calls fn with the repo-relative slash path of
// every .go file. Directories named .git and .omo are skipped.
func walkGoFileRels(root string, fn func(rel string) error) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".omo":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		return fn(filepath.ToSlash(rel))
	})
}

// normalizationModules reports every non-test .go file whose base name starts
// with normalize or normalization, as a repo-relative slash path. Sorted.
func normalizationModules(root string) ([]string, error) {
	var found []string
	err := walkGoFileRels(root, func(rel string) error {
		if strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		base := lastPathElement(rel)
		if strings.HasPrefix(base, "normalize") || strings.HasPrefix(base, "normalization") {
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}
	sort.Strings(found)
	return found, nil
}

// isDirectChild reports whether rel is a direct child of dir. It works on
// slash-separated paths so it is independent of the host separator.
func isDirectChild(rel, dir string) bool {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	if !strings.HasPrefix(rel, prefix) {
		return false
	}
	return !strings.Contains(rel[len(prefix):], "/")
}

// decoderSiteAllowed reports whether rel is one of the allowlisted decoder
// sites: pkg/filter/primitive_jwt.go, anything under pkg/supply/, pkg/redact/
// placeholder.go, a digest* direct child of pkg/redact/, or a direct child of
// pkg/proxy/.
func decoderSiteAllowed(rel string) bool {
	if decoderSiteExactFiles[rel] {
		return true
	}
	if strings.HasPrefix(rel, "pkg/supply/") {
		return true
	}
	if !strings.HasSuffix(rel, ".go") {
		return false
	}
	if isDirectChild(rel, "pkg/redact") && strings.Contains(lastPathElement(rel), "digest") {
		return true
	}
	return isDirectChild(rel, "pkg/proxy")
}

// decoderSiteViolations reports every production .go file that imports a
// decoder package without being an allowlisted decoder site. Sorted.
func decoderSiteViolations(root string) ([]string, error) {
	var violations []string
	err := walkGoFileRels(root, func(rel string) error {
		if strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", rel, readErr)
		}
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, src, parser.ImportsOnly)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", rel, parseErr)
		}
		for _, imp := range f.Imports {
			imported := unquoteImportPath(imp.Path.Value)
			if !decoderImportPaths[imported] || decoderSiteAllowed(rel) {
				continue
			}
			violations = append(violations, fmt.Sprintf(
				"%s: decoder import %q is not one of the four allowlisted decoder sites", rel, imported))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(violations)
	return violations, nil
}

// decoderSitesPresent reports the allowlisted decoder site files that actually
// exist under root, as repo-relative slash paths. Sorted.
func decoderSitesPresent(root string) []string {
	var sites []string
	err := walkGoFileRels(root, func(rel string) error {
		if strings.HasSuffix(rel, "_test.go") || !decoderSiteAllowed(rel) {
			return nil
		}
		sites = append(sites, rel)
		return nil
	})
	if err != nil {
		return nil
	}
	sort.Strings(sites)
	return sites
}

// isDecodeCall reports whether expr is a call that decodes payload bytes.
// Selector names Decode, DecodeString and DecodeAll always count. NewReader
// only counts when its receiver resolves to one of the compress packages, so
// bufio.NewReader never does.
func isDecodeCall(expr ast.Expr, names map[string]string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if decodeCallNames[sel.Sel.Name] {
		return true
	}
	if sel.Sel.Name != "NewReader" {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return compressionImportPaths[names[ident.Name]]
}

// isInspectCall reports whether call invokes a detector entry point named
// Inspect, either bare or through a selector.
func isInspectCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name == "Inspect"
	case *ast.SelectorExpr:
		return fun.Sel.Name == "Inspect"
	}
	return false
}

// decoderFeedsDetector parses src as path and reports every place decoded
// output reaches an Inspect call. The first pass per function body collects
// identifiers assigned from a decode call; the second flags Inspect calls
// whose argument is one of them or is itself a decode call. Sorted.
func decoderFeedsDetector(path string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	names, _ := importNames(f)

	seen := map[string]bool{}
	var violations []string
	add := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if seen[msg] {
			return
		}
		seen[msg] = true
		violations = append(violations, msg)
	}

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		tainted := map[string]bool{}
		collect := func(lhs, rhs []ast.Expr) {
			for i, value := range rhs {
				if i >= len(lhs) || !isDecodeCall(value, names) {
					continue
				}
				ident, ok := lhs[i].(*ast.Ident)
				if !ok || ident.Name == "_" {
					continue
				}
				tainted[ident.Name] = true
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.AssignStmt:
				collect(stmt.Lhs, stmt.Rhs)
			case *ast.ValueSpec:
				lhs := make([]ast.Expr, 0, len(stmt.Names))
				for _, name := range stmt.Names {
					lhs = append(lhs, name)
				}
				collect(lhs, stmt.Values)
			}
			return true
		})

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isInspectCall(call) {
				return true
			}
			for _, arg := range call.Args {
				if ident, ok := arg.(*ast.Ident); ok {
					if tainted[ident.Name] {
						add("%s: decoded value %q flows into Inspect", path, ident.Name)
					}
					continue
				}
				if isDecodeCall(arg, names) {
					add("%s: decoder output flows directly into Inspect", path)
				}
			}
			return true
		})
	}

	sort.Strings(violations)
	return violations, nil
}

// writeTempGoFile writes a Go source file under dir, creating parents.
func writeTempGoFile(t *testing.T, path, src string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// decoderImportProbe is a parseable file that imports a decoder package.
const decoderImportProbe = "package probe\n\nimport \"encoding/base64\"\n\nvar _ = base64.StdEncoding\n"

func TestNormalizationGuardDetectsNormalizeModule(t *testing.T) {
	root := t.TempDir()
	writeTempGoFile(t, filepath.Join(root, "normalize.go"), "package tmp\n")
	writeTempGoFile(t, filepath.Join(root, "pkg", "x", "normalize_candidates.go"), "package x\n")
	// Non-modules that must never be reported.
	writeTempGoFile(t, filepath.Join(root, "normalize_test.go"), "package tmp\n")
	writeTempGoFile(t, filepath.Join(root, ".omo", "normalize_hidden.go"), "package hidden\n")
	writeTempGoFile(t, filepath.Join(root, ".git", "normalize_vcs.go"), "package vcs\n")

	got, err := normalizationModules(root)
	if err != nil {
		t.Fatalf("normalizationModules(%s): %v", root, err)
	}
	want := []string{"normalize.go", "pkg/x/normalize_candidates.go"}
	if len(got) != len(want) {
		t.Fatalf("normalizationModules(%s) = %v, want exactly %v", root, got, want)
	}
	for i, path := range want {
		if got[i] != path {
			t.Errorf("normalizationModules(%s)[%d] = %q, want %q", root, i, got[i], path)
		}
	}
}

func TestNormalizationGuardDetectsUnlistedDecoder(t *testing.T) {
	root := t.TempDir()
	writeTempGoFile(t, filepath.Join(root, "pkg", "foo", "foo.go"), decoderImportProbe)
	// Test files and hidden trees are out of scope for the decoder-site rule.
	writeTempGoFile(t, filepath.Join(root, "pkg", "foo", "foo_test.go"), decoderImportProbe)
	writeTempGoFile(t, filepath.Join(root, ".omo", "bad.go"), decoderImportProbe)

	violations, err := decoderSiteViolations(root)
	if err != nil {
		t.Fatalf("decoderSiteViolations(%s): %v", root, err)
	}
	if len(violations) != 1 {
		t.Fatalf("decoderSiteViolations(%s) = %v, want exactly one violation", root, violations)
	}
	violation := violations[0]
	if !strings.Contains(violation, "pkg/foo/foo.go") || !strings.Contains(violation, "encoding/base64") {
		t.Errorf("violation %q must name both pkg/foo/foo.go and encoding/base64", violation)
	}
}

func TestNormalizationGuardAllowsNamedSites(t *testing.T) {
	root := t.TempDir()
	sites := []string{
		"pkg/filter/primitive_jwt.go",
		"pkg/supply/substrate.go",
		"pkg/supply/nested/substrate.go",
		"pkg/redact/placeholder.go",
		"pkg/redact/digest_sha256.go",
		"pkg/proxy/response_buffered.go",
	}
	for _, site := range sites {
		writeTempGoFile(t, filepath.Join(root, filepath.FromSlash(site)), decoderImportProbe)
	}

	violations, err := decoderSiteViolations(root)
	if err != nil {
		t.Fatalf("decoderSiteViolations(%s): %v", root, err)
	}
	if len(violations) != 0 {
		t.Errorf("decoderSiteViolations(%s) = %v, want no violations for allowlisted sites", root, violations)
	}

	t.Run("unlisted sibling is still reported", func(t *testing.T) {
		writeTempGoFile(t, filepath.Join(root, "pkg", "redact", "plain.go"), decoderImportProbe)
		siblingViolations, err := decoderSiteViolations(root)
		if err != nil {
			t.Fatalf("decoderSiteViolations(%s): %v", root, err)
		}
		if len(siblingViolations) != 1 || !strings.Contains(siblingViolations[0], "pkg/redact/plain.go") {
			t.Errorf("decoderSiteViolations(%s) = %v, want exactly one violation for pkg/redact/plain.go", root, siblingViolations)
		}
	})
}

func TestNormalizationGuardDetectsDecoderFeedingDetector(t *testing.T) {
	src := []byte("package p\n\nimport \"encoding/base64\"\n\ntype rule struct{}\n\nfunc f(s string, r rule) { d, _ := base64.StdEncoding.DecodeString(s); _ = r.Inspect(d) }\n")
	violations, err := decoderFeedsDetector("probe.go", src)
	if err != nil {
		t.Fatalf("decoderFeedsDetector: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("decoderFeedsDetector reported no violation for decoded output flowing into Inspect")
	}
	for _, violation := range violations {
		if !strings.Contains(violation, "probe.go") || !strings.Contains(violation, `"d"`) {
			t.Errorf("violation %q must name the file and the tainted identifier", violation)
		}
	}

	t.Run("inline decode call", func(t *testing.T) {
		inline := []byte("package p\n\nimport \"encoding/base64\"\n\ntype rule struct{}\n\nfunc f(s string, r rule) { _ = r.Inspect(base64.StdEncoding.DecodeString(s)) }\n")
		inlineViolations, err := decoderFeedsDetector("inline.go", inline)
		if err != nil {
			t.Fatalf("decoderFeedsDetector: %v", err)
		}
		if len(inlineViolations) == 0 {
			t.Fatal("decoderFeedsDetector reported no violation for an inline decode call passed to Inspect")
		}
	})

	t.Run("NewReader receiver resolution", func(t *testing.T) {
		probe := []byte(`package p

import (
	"bufio"
	"compress/gzip"
	"strings"
)

func f(s string) {
	_ = bufio.NewReader(strings.NewReader(s))
	_ = gzip.NewReader(strings.NewReader(s))
}
`)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "newreader.go", probe, 0)
		if err != nil {
			t.Fatalf("parse newreader probe: %v", err)
		}
		names, _ := importNames(f)
		got := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewReader" {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			got[ident.Name] = isDecodeCall(call, names)
			return true
		})
		if _, ok := got["bufio"]; !ok {
			t.Fatal("bufio.NewReader call was not found in the probe")
		}
		if got["bufio"] {
			t.Error("bufio.NewReader must not count as a decode call")
		}
		if _, ok := got["gzip"]; !ok {
			t.Fatal("gzip.NewReader call was not found in the probe")
		}
		if !got["gzip"] {
			t.Error("gzip.NewReader must count as a decode call")
		}
	})
}

func TestNormalizationGuardCleanFixture(t *testing.T) {
	fixtureRoot := filepath.Join(repoRoot(t), fixturePkgDir)

	modules, err := normalizationModules(fixtureRoot)
	if err != nil {
		t.Fatalf("normalizationModules(%s): %v", fixtureRoot, err)
	}
	if len(modules) != 0 {
		t.Errorf("normalizationModules(%s) = %v, want no normalization modules in the fixture", fixtureRoot, modules)
	}

	violations, err := decoderSiteViolations(fixtureRoot)
	if err != nil {
		t.Fatalf("decoderSiteViolations(%s): %v", fixtureRoot, err)
	}
	if len(violations) != 0 {
		t.Errorf("decoderSiteViolations(%s) = %v, want the fixture to import no decoders", fixtureRoot, violations)
	}

	files, ok := productionGoFiles(t, fixturePkgDir)
	if !ok {
		t.Fatalf("fixture package %s is missing", fixturePkgDir)
	}
	if len(files) == 0 {
		t.Fatalf("fixture package %s contains no production Go files", fixturePkgDir)
	}
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		feeds, err := decoderFeedsDetector(file, src)
		if err != nil {
			t.Fatalf("decoderFeedsDetector(%s): %v", file, err)
		}
		for _, violation := range feeds {
			t.Errorf("%s", violation)
		}
	}
}

func TestNormalizationGuardProductTree(t *testing.T) {
	root := repoRoot(t)

	modules, err := normalizationModules(root)
	if err != nil {
		t.Fatalf("normalizationModules(%s): %v", root, err)
	}
	if len(modules) != 0 {
		t.Errorf("normalizationModules(%s) = %v, want no normalization modules in the product tree", root, modules)
	}

	sites := decoderSitesPresent(root)
	if len(sites) == 0 {
		skipGuard(t, "normalization", "decoder sites not written yet")
		return
	}

	violations, err := decoderSiteViolations(root)
	if err != nil {
		t.Fatalf("decoderSiteViolations(%s): %v", root, err)
	}
	for _, violation := range violations {
		t.Errorf("%s", violation)
	}
	for _, site := range sites {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(site)))
		if err != nil {
			t.Fatalf("read %s: %v", site, err)
		}
		feeds, err := decoderFeedsDetector(site, src)
		if err != nil {
			t.Fatalf("decoderFeedsDetector(%s): %v", site, err)
		}
		for _, violation := range feeds {
			t.Errorf("%s", violation)
		}
	}
}
