// Shape guard: pkg/filter's exported rule surface is frozen. The rule contract
// may expose exactly the eight methods below, and the package may declare no
// second exported interface, so a later refactor cannot widen the extension
// point behind the guards' back.
package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"
	"testing"
)

// frozenRuleMethods is the complete, frozen exported method set of pkg/filter's
// Rule interface, rendered as `Name(args) results`.
var frozenRuleMethods = map[string]string{
	"ID":         "ID() string",
	"Type":       "Type() string",
	"Category":   "Category() string",
	"Scope":      "Scope() Scope",
	"Action":     "Action() Action",
	"Priority":   "Priority() int",
	"Confidence": "Confidence() float64",
	"Inspect":    "Inspect([]byte) []Span",
}

// renderFieldTypes renders a parameter or result list as a comma-joined list of
// types, repeating the type once per declared name. A nil or empty list renders
// to the empty string.
func renderFieldTypes(list *ast.FieldList) string {
	if list == nil || len(list.List) == 0 {
		return ""
	}
	var parts []string
	for _, field := range list.List {
		rendered := types.ExprString(field.Type)
		if len(field.Names) == 0 {
			parts = append(parts, rendered)
			continue
		}
		for range field.Names {
			parts = append(parts, rendered)
		}
	}
	return strings.Join(parts, ",")
}

// renderSignature renders one interface method as `Name(args) results`, e.g.
// `Priority() int`.
func renderSignature(name string, ft *ast.FuncType) string {
	sig := name + "(" + renderFieldTypes(ft.Params) + ")"
	if results := renderFieldTypes(ft.Results); results != "" {
		sig += " " + results
	}
	return sig
}

// ruleShapeViolations parses src as a single Go source file and reports every
// way the package it declares deviates from the frozen rule surface: missing
// methods, unexpected methods, signature mismatches, a second exported
// extension interface, or no exported Rule interface at all. Messages are
// sorted and deduplicated.
func ruleShapeViolations(src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "shape_probe.go", src, 0)
	if err != nil {
		return nil, fmt.Errorf("parse shape probe: %w", err)
	}

	var violations []string
	add := func(format string, args ...any) {
		violations = append(violations, fmt.Sprintf(format, args...))
	}

	var rule *ast.InterfaceType
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || !ast.IsExported(ts.Name.Name) {
				continue
			}
			it, ok := ts.Type.(*ast.InterfaceType)
			if !ok {
				continue
			}
			if ts.Name.Name == "Rule" {
				rule = it
				continue
			}
			add("second exported extension interface %s", ts.Name.Name)
		}
	}

	if rule == nil {
		add("no exported Rule interface")
	} else {
		present := map[string]bool{}
		for _, field := range rule.Methods.List {
			if len(field.Names) == 0 {
				add("Rule interface has unexpected embedded interface %s", types.ExprString(field.Type))
				continue
			}
			name := field.Names[0].Name
			ft, ok := field.Type.(*ast.FuncType)
			if !ok {
				add("Rule member %s is not a method", name)
				continue
			}
			present[name] = true
			sig := renderSignature(name, ft)
			if want, known := frozenRuleMethods[name]; known {
				if sig != want {
					add("Rule method %s has signature %s, want %s", name, sig, want)
				}
				continue
			}
			add("Rule interface has unexpected method %s", name)
		}
		var expected []string
		for name := range frozenRuleMethods {
			expected = append(expected, name)
		}
		sort.Strings(expected)
		for _, name := range expected {
			if !present[name] {
				add("Rule interface is missing method %s", name)
			}
		}
	}

	seen := map[string]bool{}
	var unique []string
	for _, v := range violations {
		if seen[v] {
			continue
		}
		seen[v] = true
		unique = append(unique, v)
	}
	sort.Strings(unique)
	return unique, nil
}

// hasNoRuleViolation reports whether violations say no Rule interface was
// declared in the parsed file.
func hasNoRuleViolation(violations []string) bool {
	for _, v := range violations {
		if v == "no exported Rule interface" {
			return true
		}
	}
	return false
}

func TestShapeGuardRejectsWrongRuleSet(t *testing.T) {
	broken := []byte(`package filter

type Scope int
type Action int
type Span struct{}

type Rule interface {
	ID() string
	Type() string
	Category() string
	Scope() Scope
	Action() Action
	Priority() int64
	Confidence() float64
	Extra() bool
}

type Gateway interface{ Run() }
`)
	violations, err := ruleShapeViolations(broken)
	if err != nil {
		t.Fatalf("ruleShapeViolations(broken): %v", err)
	}
	wantFragments := []string{
		"Rule interface is missing method Inspect",
		"Rule interface has unexpected method Extra",
		"Rule method Priority has signature Priority() int64, want Priority() int",
		"second exported extension interface Gateway",
	}
	for _, want := range wantFragments {
		found := false
		for _, v := range violations {
			if strings.Contains(v, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("violations %v do not report %q", violations, want)
		}
	}

	t.Run("exact frozen set", func(t *testing.T) {
		frozen := []byte(`package filter

type Scope int
type Action int
type Span struct{}

type Rule interface {
	ID() string
	Type() string
	Category() string
	Scope() Scope
	Action() Action
	Priority() int
	Confidence() float64
	Inspect([]byte) []Span
}
`)
		got, err := ruleShapeViolations(frozen)
		if err != nil {
			t.Fatalf("ruleShapeViolations(frozen): %v", err)
		}
		if len(got) != 0 {
			t.Errorf("frozen rule set reported violations: %v", got)
		}
	})

	t.Run("no rule interface", func(t *testing.T) {
		missing := []byte("package filter\n\ntype Gateway interface{ Run() }\n")
		got, err := ruleShapeViolations(missing)
		if err != nil {
			t.Fatalf("ruleShapeViolations(missing): %v", err)
		}
		if !hasNoRuleViolation(got) {
			t.Errorf("violations %v do not report a missing exported Rule interface", got)
		}
	})
}

// TestShapeGuardCleanFixture runs the shape check over the parser fixture. The
// fixture is not the rule package, so its "no exported Rule interface" report
// is expected; any other shape violation -- notably a smuggled second exported
// interface -- fails the guard.
func TestShapeGuardCleanFixture(t *testing.T) {
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
		violations, err := ruleShapeViolations(src)
		if err != nil {
			t.Fatalf("ruleShapeViolations(%s): %v", file, err)
		}
		for _, v := range violations {
			if v == "no exported Rule interface" {
				continue
			}
			t.Errorf("%s: %s", file, v)
		}
	}
}

func TestShapeGuardProductTree(t *testing.T) {
	const pkg = "pkg/filter"
	files, ok := productionGoFiles(t, pkg)
	if !ok {
		skipGuard(t, "shape", "pkg/filter not written yet (product half completes in W3.6)")
		return
	}
	ruleFound := false
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		violations, err := ruleShapeViolations(src)
		if err != nil {
			t.Fatalf("ruleShapeViolations(%s): %v", file, err)
		}
		// The Rule interface may live in a sibling file, so the per-file
		// "no Rule here" report is only a package-level signal.
		if !hasNoRuleViolation(violations) {
			ruleFound = true
		}
		for _, v := range violations {
			if v == "no exported Rule interface" {
				continue
			}
			t.Errorf("%s: %s", file, v)
		}
	}
	if !ruleFound {
		t.Errorf("%s declares no exported Rule interface", pkg)
	}
}
