// Absence guard: invariant 3 — tokenhush never installs a root certificate,
// never terminates TLS and never grows a MITM mode. The guard scans Go source
// for the concrete shapes such a feature would need (TLS listeners, key pairs,
// cert pools, tls.Config / http.Server literals, embedded certificates and
// MITM-flavoured config keys) and fails if any appears in production code.
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

// forbiddenCertificateConfigKeys are string literals that only make sense if
// the rewrite grew a certificate-installation or MITM mode.
var forbiddenCertificateConfigKeys = []string{
	"mitm",
	"install-cert",
	"install_cert",
	"installcert",
	"root-ca",
	"trust-store",
}

// certificateAliases carries the import bindings of a parsed file so selector
// expressions can be resolved back to their package path.
type certificateAliases struct {
	names map[string]string
	dots  []string
}

func (a certificateAliases) hasDot(path string) bool {
	for _, dot := range a.dots {
		if dot == path {
			return true
		}
	}
	return false
}

// selectsPkg reports whether expr is a package qualifier bound to pkgPath.
func (a certificateAliases) selectsPkg(expr ast.Expr, pkgPath string) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	return a.names[ident.Name] == pkgPath
}

// certificateInstallViolations parses src as path and reports every marker of
// certificate installation / TLS termination / MITM support it finds. Messages
// are prefixed with `path + ": "`, deduplicated and sorted.
func certificateInstallViolations(path string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	names, dots := importNames(f)
	aliases := certificateAliases{names: names, dots: dots}
	tlsDot := aliases.hasDot("crypto/tls")
	x509Dot := aliases.hasDot("crypto/x509")
	httpDot := aliases.hasDot("net/http")

	markers := map[string]bool{}
	report := func(marker string) { markers[marker] = true }

	hasCertPool := false
	hasAddCert := false

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			switch fun := node.Fun.(type) {
			case *ast.SelectorExpr:
				switch fun.Sel.Name {
				case "ListenAndServeTLS":
					report("ListenAndServeTLS")
				case "LoadX509KeyPair":
					report("tls.LoadX509KeyPair")
				case "X509KeyPair":
					report("tls.X509KeyPair")
				case "NewCertPool":
					hasCertPool = true
				case "AddCert":
					hasAddCert = true
				}
			case *ast.Ident:
				switch fun.Name {
				case "ListenAndServeTLS":
					report("ListenAndServeTLS")
				case "LoadX509KeyPair":
					if tlsDot {
						report("tls.LoadX509KeyPair")
					}
				case "X509KeyPair":
					if tlsDot {
						report("tls.X509KeyPair")
					}
				case "NewCertPool":
					if x509Dot {
						hasCertPool = true
					}
				case "AddCert":
					hasAddCert = true
				}
			}
		case *ast.CompositeLit:
			if isTLSConfigLiteral(node.Type, aliases, tlsDot) && literalHasField(node, "Certificates") {
				report("tls.Config literal with a Certificates field")
			}
			if isHTTPServerLiteral(node.Type, aliases, httpDot) && literalHasField(node, "TLSConfig") {
				report("http.Server literal with a TLSConfig field")
			}
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			value := strings.ToLower(unquoteImportPath(node.Value))
			for _, key := range forbiddenCertificateConfigKeys {
				if value == key {
					report(fmt.Sprintf("config key %q", key))
				}
			}
		}
		return true
	})

	if hasCertPool && hasAddCert {
		report("x509.NewCertPool combined with AddCert")
	}

	if strings.Contains(string(src), "-----BEGIN CERTIFICATE-----") {
		report("embedded certificate literal")
	}

	violations := make([]string, 0, len(markers))
	for marker := range markers {
		violations = append(violations, path+": certificate-install: "+marker)
	}
	sort.Strings(violations)
	return violations, nil
}

// isTLSConfigLiteral reports whether a composite literal type resolves to
// tls.Config, honouring aliased and dot imports of crypto/tls.
func isTLSConfigLiteral(expr ast.Expr, aliases certificateAliases, tlsDot bool) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		return aliases.selectsPkg(t.X, "crypto/tls") && t.Sel.Name == "Config"
	case *ast.Ident:
		return tlsDot && t.Name == "Config"
	}
	return false
}

// isHTTPServerLiteral reports whether a composite literal type resolves to
// http.Server, honouring aliased and dot imports of net/http.
func isHTTPServerLiteral(expr ast.Expr, aliases certificateAliases, httpDot bool) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		return aliases.selectsPkg(t.X, "net/http") && t.Sel.Name == "Server"
	case *ast.Ident:
		return httpDot && t.Name == "Server"
	}
	return false
}

// literalHasField reports whether the composite literal sets the named key.
func literalHasField(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == field {
			return true
		}
	}
	return false
}

// absenceProbe is a deliberately tainted Go file exercising every category the
// absence guard must detect.
const absenceProbe = `package probe

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

const certPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n"

var (
	keyMITM         = "mitm"
	keyInstallDash  = "install-cert"
	keyInstallSnake = "install_cert"
	keyInstallPlain = "installcert"
	keyRootCA       = "root-ca"
	keyTrustStore   = "trust-store"
)

func plant() {
	_ = http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
	_, _ = tls.LoadX509KeyPair("cert.pem", "key.pem")
	_, _ = tls.X509KeyPair([]byte(certPEM), []byte(certPEM))
	pool := x509.NewCertPool()
	pool.AddCert(nil)
	srv := &http.Server{Addr: ":443", TLSConfig: &tls.Config{Certificates: nil}}
	_ = srv
	_ = keyMITM
	_ = keyInstallDash
	_ = keyInstallSnake
	_ = keyInstallPlain
	_ = keyRootCA
	_ = keyTrustStore
}
`

func TestAbsenceNoCertificateInstallPath(t *testing.T) {
	probePath := filepath.Join(t.TempDir(), "probe.go")
	if err := os.WriteFile(probePath, []byte(absenceProbe), 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}

	violations, err := certificateInstallViolations(probePath, []byte(absenceProbe))
	if err != nil {
		t.Fatalf("certificateInstallViolations(probe): %v", err)
	}
	if len(violations) == 0 {
		t.Fatalf("planted probe file produced 0 violations; the guard is vacuous")
	}
	joined := strings.Join(violations, "\n")
	mustContain := []string{
		"certificate-install: ListenAndServeTLS",
		"certificate-install: tls.LoadX509KeyPair",
		"certificate-install: tls.X509KeyPair",
		"certificate-install: x509.NewCertPool combined with AddCert",
		"certificate-install: tls.Config literal with a Certificates field",
		"certificate-install: http.Server literal with a TLSConfig field",
		"certificate-install: embedded certificate literal",
		`certificate-install: config key "mitm"`,
		`certificate-install: config key "install-cert"`,
		`certificate-install: config key "install_cert"`,
		`certificate-install: config key "installcert"`,
		`certificate-install: config key "root-ca"`,
		`certificate-install: config key "trust-store"`,
	}
	for _, want := range mustContain {
		if !strings.Contains(joined, want) {
			t.Errorf("probe violations missing %q; got:\n%s", want, joined)
		}
	}
	for _, v := range violations {
		if !strings.HasPrefix(v, probePath+": ") {
			t.Errorf("violation %q does not start with %q", v, probePath+": ")
		}
	}

	// The real module must be clean: tokenhush never installs a certificate.
	root := repoRoot(t)
	skipDirs := map[string]bool{".git": true, ".omo": true, "testdata": true}
	scanned := 0
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		scanned++
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		violations, err := certificateInstallViolations(p, src)
		if err != nil {
			return err
		}
		if len(violations) != 0 {
			t.Errorf("%s: expected 0 certificate-install violations, got %d:\n%s", p, len(violations), strings.Join(violations, "\n"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned == 0 {
		t.Fatalf("walked %s but scanned no production .go files; guard is vacuous", root)
	}
}

func TestAbsenceGuardCleanFixture(t *testing.T) {
	files, ok := goFiles(t, fixturePkgDir)
	if !ok {
		t.Fatalf("fixture package %s is missing", fixturePkgDir)
	}
	if len(files) == 0 {
		t.Fatalf("fixture package %s contains no Go files", fixturePkgDir)
	}
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		violations, err := certificateInstallViolations(file, src)
		if err != nil {
			t.Fatalf("certificateInstallViolations(%s): %v", file, err)
		}
		if len(violations) != 0 {
			t.Errorf("%s: expected 0 certificate-install violations, got %d:\n%s", file, len(violations), strings.Join(violations, "\n"))
		}
	}
}
