package filter

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// stubRule is the in-package Rule implementation the registry and policy tests
// drive. Its inspect func is the whole behavior, so a test can express a
// keyword matcher, a panic, a malformed span or an out-of-budget result without
// a second helper type.
type stubRule struct {
	id       string
	typ      string
	category string
	scope    Scope
	action   Action
	priority int
	conf     float64
	inspect  func(leaf []byte) []Span
}

func (r stubRule) ID() string {
	if r.id != "" {
		return r.id
	}
	return "stub"
}

func (r stubRule) Type() string {
	if r.typ != "" {
		return r.typ
	}
	return TypeKeyword
}

func (r stubRule) Category() string {
	if r.category != "" {
		return r.category
	}
	return CategoryCustom
}

func (r stubRule) Scope() Scope {
	if r.scope != "" {
		return r.scope
	}
	return ScopeRequest
}

func (r stubRule) Action() Action {
	if r.action != "" {
		return r.action
	}
	return ActionWarn
}

func (r stubRule) Priority() int { return r.priority }

func (r stubRule) Confidence() float64 {
	if r.conf != 0 {
		return r.conf
	}
	return 0.9
}

func (r stubRule) Inspect(value []byte) []Span {
	if r.inspect == nil {
		return nil
	}
	return r.inspect(value)
}

// matches returns a stub that reports one span for the first occurrence of
// literal.
func matches(id string, priority int, literal string, action Action) stubRule {
	return stubRule{id: id, priority: priority, action: action, inspect: func(value []byte) []Span {
		at := bytes.Index(value, []byte(literal))
		if at < 0 {
			return nil
		}
		return []Span{{Start: at, End: at + len(literal)}}
	}}
}

// burst returns an inspect func reporting count spans of one byte each.
func burst(count int) func([]byte) []Span {
	return func([]byte) []Span {
		spans := make([]Span, count)
		for i := range spans {
			spans[i] = Span{Start: i, End: i + 1}
		}
		return spans
	}
}

// ruleIDs returns the rule ids of findings in order.
func ruleIDs(findings []AttributedFinding) []string {
	ids := make([]string, len(findings))
	for i := range findings {
		ids[i] = findings[i].RuleID
	}
	return ids
}

func mustRegister(t *testing.T, reg *Registry, rules ...Rule) {
	t.Helper()
	if err := reg.Register(rules...); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
}

func mustRegistryEvaluate(t *testing.T, reg *Registry, leaves []protocol.Leaf, phase Scope) []AttributedFinding {
	t.Helper()
	findings, err := reg.Evaluate(leaves, phase)
	if err != nil {
		t.Fatalf("Registry.Evaluate() error = %v", err)
	}
	return findings
}

// TestRegistryRejectsResponseRedact is the registration-side direction
// contract: a directly-registered rule whose scope is response or both and
// whose action is redact is rejected with ErrDirection naming the rule, and the
// rejection leaves the first registration untouched.
func TestRegistryRejectsResponseRedact(t *testing.T) {
	for _, scope := range []Scope{ScopeResponse, ScopeBoth} {
		t.Run(string(scope), func(t *testing.T) {
			reg := NewRegistry()
			first := matches("first", 5, "TOKEN", ActionWarn)
			mustRegister(t, reg, first)

			bad := matches("bad-"+string(scope), 5, "TOKEN", ActionRedact)
			bad.scope = scope
			err := reg.Register(bad)
			if !errors.Is(err, ErrDirection) {
				t.Fatalf("Register(%s + redact) error = %v, want ErrDirection", scope, err)
			}
			if !strings.Contains(err.Error(), bad.id) {
				t.Errorf("rejection %q does not name rule %q", err, bad.id)
			}
			if len(reg.entries) != 1 || reg.entries[0].id != first.id {
				t.Fatalf("rejected registration mutated the registry: entries = %+v", reg.entries)
			}
			findings := mustRegistryEvaluate(t, reg, []protocol.Leaf{leaf("a TOKEN b")}, ScopeRequest)
			if got := ruleIDs(findings); len(got) != 1 || got[0] != first.id {
				t.Fatalf("findings after rejection = %v, want only %q", got, first.id)
			}
		})
	}
}

// TestRegistryDuplicateIDLeavesFirstUntouched proves a duplicate is rejected
// typed, the first registration keeps evaluating, and the second value is never
// stored.
func TestRegistryDuplicateIDLeavesFirstUntouched(t *testing.T) {
	reg := NewRegistry()
	first := matches("dup", 10, "TOKEN", ActionWarn)
	mustRegister(t, reg, first)

	second := matches("dup", 20, "TOKEN", ActionBlock)
	err := reg.Register(second)
	if !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("Register(duplicate) error = %v, want ErrDuplicateID", err)
	}
	if !strings.Contains(err.Error(), "dup") {
		t.Errorf("rejection %q does not name the duplicate id", err)
	}
	findings := mustRegistryEvaluate(t, reg, []protocol.Leaf{leaf("a TOKEN b")}, ScopeRequest)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly the first registration", len(findings))
	}
	if findings[0].Action != ActionWarn {
		t.Errorf("finding = %+v, want the first registration's action", findings[0])
	}
}

// TestRegistryBatchIsAtomic proves no partial mutation: one bad candidate
// rejects the whole batch.
func TestRegistryBatchIsAtomic(t *testing.T) {
	reg := NewRegistry()
	good := matches("good", 10, "TOKEN", ActionWarn)
	bad := matches("good", 10, "TOKEN", ActionWarn)
	if err := reg.Register(good, bad); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("Register(good, duplicate) error = %v, want ErrDuplicateID", err)
	}
	if len(reg.entries) != 0 {
		t.Fatalf("rejected batch mutated the registry: %+v", reg.entries)
	}
}

// TestRegistryOrdersByPriorityThenID pins the deterministic order regardless of
// declaration order. Every rule reports the same span, so the stable
// (leaf, start, end) sort leaves the invocation order visible.
func TestRegistryOrdersByPriorityThenID(t *testing.T) {
	reg := NewRegistry()
	for _, rule := range []stubRule{
		matches("late", 20, "SECRET", ActionWarn),
		matches("zulu", 10, "SECRET", ActionWarn),
		matches("alpha", 10, "SECRET", ActionWarn),
	} {
		mustRegister(t, reg, rule)
	}
	findings := mustRegistryEvaluate(t, reg, []protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
	want := []string{"alpha", "zulu", "late"}
	if got := ruleIDs(findings); !reflect.DeepEqual(got, want) {
		t.Fatalf("invocation order = %v, want %v", got, want)
	}
	if findings[0].Start != findings[1].Start || findings[1].Start != findings[2].Start {
		t.Fatalf("expected identical spans to expose invocation order, got %+v", findings)
	}
}

// TestRegistryStampsOrigins proves provenance is core-owned per registration
// route: builtin, remote pack and plugin.
func TestRegistryStampsOrigins(t *testing.T) {
	reg := NewRegistry()
	if err := reg.RegisterBuiltin(matches("builtin-rule", 10, "SECRET", ActionWarn)); err != nil {
		t.Fatalf("RegisterBuiltin() error = %v", err)
	}
	set := compileDoc(t, `{"rules":[{"id":"pack-rule","type":"keyword","keywords":["SECRET"],"action":"warn","scope":"request","priority":20}]}`)
	if err := reg.RegisterCompiled(set); err != nil {
		t.Fatalf("RegisterCompiled() error = %v", err)
	}
	mustRegister(t, reg, matches("plugin-rule", 30, "SECRET", ActionWarn))

	findings := mustRegistryEvaluate(t, reg, []protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
	want := map[string]Origin{"builtin-rule": OriginBuiltin, "pack-rule": OriginRemotePack, "plugin-rule": OriginPlugin}
	if len(findings) != len(want) {
		t.Fatalf("findings = %v, want one per registration route", ruleIDs(findings))
	}
	for _, finding := range findings {
		if got := finding.Origin; got != want[finding.RuleID] {
			t.Errorf("rule %q origin = %q, want %q", finding.RuleID, got, want[finding.RuleID])
		}
	}
}

// TestRegistryCompiledRulesMatchTheDocumentPath proves the two arrival routes
// agree: the registered compiled rules produce the same findings, in the same
// order, as the compiled set itself, including allowlist suppression.
func TestRegistryCompiledRulesMatchTheDocumentPath(t *testing.T) {
	set := compileDoc(t, `{
		"allowlist": ["PROJ-1"],
		"rules": [
			{"id":"project","type":"regex","pattern":"PROJ-[0-9]+","action":"warn","priority":50},
			{"id":"zz-last","type":"regex","pattern":"PROJ-[0-9]+","action":"warn","priority":50},
			{"id":"middle","type":"regex","pattern":"PROJ-[0-9]+","action":"warn","priority":150}
		]
	}`)
	reg := NewRegistry()
	if err := reg.RegisterCompiled(set); err != nil {
		t.Fatalf("RegisterCompiled() error = %v", err)
	}
	mustRegister(t, reg, matches("between", 100, "PROJ-2", ActionWarn))

	leaves := []protocol.Leaf{leaf("PROJ-1 PROJ-2 PROJ-1 PROJ-2")}
	compiled, err := set.Evaluate(leaves, ScopeRequest)
	if err != nil {
		t.Fatalf("Compiled.Evaluate() error = %v", err)
	}
	registered := mustRegistryEvaluate(t, reg, leaves, ScopeRequest)
	want := []string{"project", "zz-last", "between", "middle", "project", "zz-last", "middle"}
	if got := ruleIDs(registered); !reflect.DeepEqual(got, want) {
		t.Fatalf("registry invocation order = %v, want %v", got, want)
	}
	packOrder := make([]string, 0, len(registered))
	for _, finding := range registered {
		if finding.Origin == OriginRemotePack {
			packOrder = append(packOrder, finding.RuleID)
		}
	}
	documentOrder := make([]string, len(compiled))
	for i := range compiled {
		documentOrder[i] = compiled[i].RuleID
	}
	if !reflect.DeepEqual(packOrder, documentOrder) {
		t.Fatalf("registered compiled order = %v, document order = %v", packOrder, documentOrder)
	}
}

// TestRegistryEvaluateFailsClosed proves every registry-level failure mode
// yields a labelled *RuleFailure and no findings, never a panic and never a
// partial result.
func TestRegistryEvaluateFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		id     string
		rule   Rule
		reason Reason
	}{
		{"panic", "boom", stubRule{id: "boom", inspect: func([]byte) []Span { panic("boom") }}, ReasonPanic},
		{"malformed span", "bad-span", stubRule{id: "bad-span", inspect: func([]byte) []Span { return []Span{{Start: 1, End: 99}} }}, ReasonMalformed},
		{"inverted span", "inverted", stubRule{id: "inverted", inspect: func([]byte) []Span { return []Span{{Start: 4, End: 2}} }}, ReasonMalformed},
		{"span budget", "greedy", stubRule{id: "greedy", inspect: burst(MaxRuleSpans + 1)}, ReasonBudget},
		{"nil rule", "ghost", (*stubRule)(nil), ReasonError},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reg := NewRegistry()
			reg.entries = append(reg.entries, registryEntry{rule: testCase.rule, origin: OriginPlugin, id: testCase.id, rank: 1})
			findings, err := reg.Evaluate([]protocol.Leaf{leaf("a SECRET b")}, ScopeRequest)
			if findings != nil {
				t.Fatalf("findings = %v, want none on a refusal", findings)
			}
			var failure *RuleFailure
			if !errors.As(err, &failure) {
				t.Fatalf("error = %v, want *RuleFailure", err)
			}
			if failure.Reason != testCase.reason {
				t.Errorf("reason = %q, want %q", failure.Reason, testCase.reason)
			}
			if failure.RuleID != testCase.id {
				t.Errorf("RuleID = %q, want %q", failure.RuleID, testCase.id)
			}
			if failure.Origin != OriginPlugin {
				t.Errorf("Origin = %q, want %q", failure.Origin, OriginPlugin)
			}
			if !errors.Is(err, ErrRuleFailure) {
				t.Errorf("errors.Is(%v, ErrRuleFailure) = false", err)
			}
		})
	}
}

// TestRegistryEvaluateBoundsTheTotal proves the document-wide bound is a
// labelled budget failure, not a truncation.
func TestRegistryEvaluateBoundsTheTotal(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg,
		stubRule{id: "one", priority: 1, inspect: burst(3000)},
		stubRule{id: "two", priority: 2, inspect: burst(3000)},
	)
	_, err := reg.Evaluate([]protocol.Leaf{leaf(strings.Repeat("a", 4000))}, ScopeRequest)
	var failure *RuleFailure
	if !errors.As(err, &failure) || failure.Reason != ReasonBudget {
		t.Fatalf("error = %v, want a *RuleFailure with reason %q", err, ReasonBudget)
	}
	if failure.RuleID != "two" {
		t.Errorf("RuleID = %q, want the rule that overran the total", failure.RuleID)
	}
}

// TestRegistryRejectsInvalidInput pins the typed input failures and the empty
// batch no-op.
func TestRegistryRejectsInvalidInput(t *testing.T) {
	var nilRegistry *Registry
	if err := nilRegistry.Register(matches("x", 1, "a", ActionWarn)); !errors.Is(err, ErrNilRegistry) {
		t.Errorf("nil Registry.Register() error = %v, want ErrNilRegistry", err)
	}
	if _, err := nilRegistry.Evaluate(nil, ScopeRequest); !errors.Is(err, ErrNilRegistry) {
		t.Errorf("nil Registry.Evaluate() error = %v, want ErrNilRegistry", err)
	}

	reg := NewRegistry()
	if err := reg.Register(); err != nil {
		t.Errorf("Register() with no rules error = %v, want nil", err)
	}
	if err := reg.RegisterCompiled(nil); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("RegisterCompiled(nil) error = %v, want ErrInvalidRule", err)
	}
	if _, err := reg.Evaluate(nil, ScopeBoth); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("Evaluate(phase=both) error = %v, want ErrInvalidValue", err)
	}
	if _, err := reg.Evaluate(nil, ""); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("Evaluate(phase=empty) error = %v, want ErrInvalidValue", err)
	}

	unknownScope := matches("scope", 1, "a", ActionWarn)
	unknownScope.scope = "sideways"
	unknownAction := matches("action", 1, "a", ActionWarn)
	unknownAction.action = "explode"
	cases := []struct {
		name string
		rule Rule
	}{
		{"nil rule", nil},
		{"bad id", matches("Bad-ID", 1, "a", ActionWarn)},
		{"unknown scope", unknownScope},
		{"unknown action", unknownAction},
		{"confidence", stubRule{id: "conf", conf: 1.5}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := NewRegistry().Register(testCase.rule)
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("Register() error = %v, want ErrInvalidRule", err)
			}
		})
	}
}

// TestRegistryEvaluateConcurrentRaceFree drives concurrent evaluations over one
// immutable registry.
func TestRegistryEvaluateConcurrentRaceFree(t *testing.T) {
	reg := NewRegistry()
	mustRegister(t, reg, matches("one", 10, "SECRET", ActionWarn), matches("two", 20, "SECRET", ActionRedact))
	leaves := []protocol.Leaf{leaf("a SECRET b")}
	baseline := mustRegistryEvaluate(t, reg, leaves, ScopeRequest)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				findings, err := reg.Evaluate(leaves, ScopeRequest)
				if err != nil {
					t.Errorf("concurrent Evaluate() error = %v", err)
					return
				}
				if !reflect.DeepEqual(findings, baseline) {
					t.Errorf("concurrent findings = %v, want %v", ruleIDs(findings), ruleIDs(baseline))
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestRuleShapeIsFrozen pins the exported rule contract from inside the
// package: exactly the eight frozen methods, and no second exported interface
// anywhere in pkg/filter's production files.
func TestRuleShapeIsFrozen(t *testing.T) {
	typ := reflect.TypeOf((*Rule)(nil)).Elem()
	want := map[string]reflect.Type{
		"ID":         reflect.TypeOf(func() string { return "" }),
		"Type":       reflect.TypeOf(func() string { return "" }),
		"Category":   reflect.TypeOf(func() string { return "" }),
		"Scope":      reflect.TypeOf(func() Scope { return "" }),
		"Action":     reflect.TypeOf(func() Action { return "" }),
		"Priority":   reflect.TypeOf(func() int { return 0 }),
		"Confidence": reflect.TypeOf(func() float64 { return 0 }),
		"Inspect":    reflect.TypeOf(func([]byte) []Span { return nil }),
	}
	if typ.NumMethod() != len(want) {
		t.Fatalf("Rule methods = %d, want exactly %d", typ.NumMethod(), len(want))
	}
	for name, signature := range want {
		method, ok := typ.MethodByName(name)
		if !ok {
			t.Errorf("Rule is missing method %s", name)
			continue
		}
		if method.Type != signature {
			t.Errorf("Rule method %s has type %s, want %s", name, method.Type, signature)
		}
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob(*.go) error = %v", err)
	}
	parsed := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				spec, ok := spec.(*ast.TypeSpec)
				if !ok || !ast.IsExported(spec.Name.Name) {
					continue
				}
				if _, isInterface := spec.Type.(*ast.InterfaceType); isInterface && spec.Name.Name != "Rule" {
					t.Errorf("%s declares a second exported interface %s", name, spec.Name.Name)
				}
			}
		}
	}
	if parsed == 0 {
		t.Fatal("no production Go files parsed")
	}
}
