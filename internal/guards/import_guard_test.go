// Import guard: the rewrite must stay on the standard library surface it has
// committed to. net/http, net/textproto and crypto/tls are forbidden both as
// direct imports and as rendered signatures (including aliased imports), so a
// future refactor cannot smuggle the HTTP stack back in.
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

// modulePath is the module path declared in go.mod.
const modulePath = "github.com/fregie/tokenhush"

// fixturePkgDir holds the known-clean package the import guard is exercised against.
const fixturePkgDir = "internal/guards/testdata/fixturepkg"

// guardedLeafPackages lists the dependency-light packages the rewrite is
// allowed to build out: they must never import the HTTP/TLS stack.
var guardedLeafPackages = []string{
	"pkg/protocol",
	"pkg/redact",
	"pkg/audit",
	"pkg/platform",
	"pkg/filter",
	"pkg/config",
}

// forbiddenImportPaths are import paths the rewrite must never depend on.
var forbiddenImportPaths = map[string]bool{
	"net/http":      true,
	"net/textproto": true,
	"crypto/tls":    true,
}

// forbiddenSignatures maps a rendered package-qualified signature to the import
// path that normally provides it. The rendered name is what matters: aliases
// resolve back to the canonical dotted form.
var forbiddenSignatures = map[string]string{
	"http.Request":        "net/http",
	"http.Header":         "net/http",
	"http.ResponseWriter": "net/http",
	"tls.Config":          "crypto/tls",
	"tls.Server":          "crypto/tls",
	"net.Listener":        "net",
}

// goFiles walks repoRoot(t)/rel recursively and returns every *.go file,
// sorted. ok is false when rel does not exist or is not a directory.
func goFiles(t *testing.T, rel string) (files []string, ok bool) {
	t.Helper()
	root := filepath.Join(repoRoot(t), rel)
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, false
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(files)
	return files, true
}

// productionGoFiles is goFiles without *_test.go files. ok is false when rel
// does not exist.
func productionGoFiles(t *testing.T, rel string) (files []string, ok bool) {
	t.Helper()
	all, ok := goFiles(t, rel)
	if !ok {
		return nil, false
	}
	for _, file := range all {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		files = append(files, file)
	}
	return files, true
}

// skipGuard records that a guard could not run yet, without failing the test.
func skipGuard(t *testing.T, id, reason string) {
	t.Helper()
	t.Logf("guard %s skipped: %s", id, reason)
}

// unquoteImportPath strips the surrounding quotes from an import literal. It
// tolerates an already-unquoted path so callers can pass either form.
func unquoteImportPath(lit string) string {
	if len(lit) >= 2 && (lit[0] == lit[len(lit)-1]) && (lit[0] == '"' || lit[0] == '`') {
		return lit[1 : len(lit)-1]
	}
	return lit
}

// importNames maps the identifier an import is bound to onto its import path,
// and returns the dot-imported paths. Blank imports are omitted.
func importNames(f *ast.File) (names map[string]string, dots []string) {
	names = map[string]string{}
	for _, imp := range f.Imports {
		path := unquoteImportPath(imp.Path.Value)
		if imp.Name != nil {
			switch imp.Name.Name {
			case "_":
				continue
			case ".":
				dots = append(dots, path)
				continue
			default:
				names[imp.Name.Name] = path
				continue
			}
		}
		names[lastPathElement(path)] = path
	}
	return names, dots
}

// lastPathElement returns the final segment of an import path, e.g. "http" for
// "net/http".
func lastPathElement(p string) string {
	p = unquoteImportPath(p)
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// importViolations parses src as path and reports every forbidden import and
// forbidden rendered signature it finds. Messages are sorted and deduplicated.
func importViolations(path string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	names, dots := importNames(f)
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

	for _, imp := range f.Imports {
		if forbiddenImportPaths[unquoteImportPath(imp.Path.Value)] {
			add("%s: forbidden import %q", path, unquoteImportPath(imp.Path.Value))
		}
	}

	// checkExpr flags a selector or bare identifier when it renders one of the
	// forbidden signatures.
	checkExpr := func(expr ast.Expr) {
		if expr == nil {
			return
		}
		ast.Inspect(expr, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.SelectorExpr:
				ident, ok := e.X.(*ast.Ident)
				if !ok {
					return true
				}
				if imported, known := names[ident.Name]; known {
					canonical := lastPathElement(imported) + "." + e.Sel.Name
					if forbiddenSignatures[canonical] != "" {
						add("%s: forbidden signature %s (package %q)", path, canonical, imported)
					}
					return true
				}
				canonical := ident.Name + "." + e.Sel.Name
				if forbiddenSignatures[canonical] != "" {
					add("%s: forbidden signature %s", path, canonical)
				}
			case *ast.Ident:
				for _, dotPath := range dots {
					canonical := lastPathElement(dotPath) + "." + e.Name
					if forbiddenSignatures[canonical] == dotPath {
						add("%s: forbidden signature %s (package %q)", path, canonical, dotPath)
					}
				}
			}
			return true
		})
	}

	walkFields := func(list *ast.FieldList) {
		if list == nil {
			return
		}
		for _, field := range list.List {
			checkExpr(field.Type)
		}
	}

	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			walkFields(d.Recv)
			if d.Type != nil {
				walkFields(d.Type.Params)
				walkFields(d.Type.Results)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					checkExpr(s.Type)
				case *ast.ValueSpec:
					checkExpr(s.Type)
					for _, value := range s.Values {
						checkExpr(value)
					}
				}
			}
		}
	}

	sort.Strings(violations)
	return violations, nil
}

func TestImportGuardDetectsPlantedViolation(t *testing.T) {
	src := []byte("package probe\n\nimport \"net/http\"\n\nfunc Handler(w http.ResponseWriter, r *http.Request) {}\n")
	path := filepath.Join(t.TempDir(), "probe.go")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	violations, err := importViolations(path, src)
	if err != nil {
		t.Fatalf("importViolations(%s): %v", path, err)
	}
	if len(violations) == 0 {
		t.Fatalf("importViolations(%s) reported no violations for a planted net/http handler", path)
	}
	found := false
	for _, v := range violations {
		if strings.Contains(v, "net/http") && strings.Contains(v, "http.Request") {
			found = true
		}
	}
	if !found {
		t.Errorf("no violation names both net/http and http.Request: %v", violations)
	}

	t.Run("aliased import", func(t *testing.T) {
		aliasSrc := []byte("package probe\n\nimport h \"net/http\"\n\nfunc F(r h.Request) {}\n")
		aliasPath := filepath.Join(t.TempDir(), "alias.go")
		if err := os.WriteFile(aliasPath, aliasSrc, 0o600); err != nil {
			t.Fatalf("write alias probe: %v", err)
		}
		aliasViolations, err := importViolations(aliasPath, aliasSrc)
		if err != nil {
			t.Fatalf("importViolations(%s): %v", aliasPath, err)
		}
		for _, v := range aliasViolations {
			if strings.Contains(v, "http.Request") {
				return
			}
		}
		t.Errorf("aliased h.Request was not reported as http.Request: %v", aliasViolations)
	})
}

func TestImportGuardCleanFixture(t *testing.T) {
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
		violations, err := importViolations(file, src)
		if err != nil {
			t.Fatalf("importViolations(%s): %v", file, err)
		}
		for _, v := range violations {
			t.Errorf("%s", v)
		}
	}
}

func TestImportGuardLeafPackages(t *testing.T) {
	for _, pkg := range guardedLeafPackages {
		files, ok := productionGoFiles(t, pkg)
		if !ok {
			skipGuard(t, "import", pkg+" not written yet")
			continue
		}
		for _, file := range files {
			src, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			violations, err := importViolations(file, src)
			if err != nil {
				t.Fatalf("importViolations(%s): %v", file, err)
			}
			for _, v := range violations {
				t.Errorf("%s: %s", modulePath+"/"+pkg, v)
			}
		}
	}
}
