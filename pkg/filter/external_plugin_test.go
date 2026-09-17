// Package filter_test is the external-plugin acceptance: a rule set defined
// outside pkg/filter proper implements the public Rule contract, registers
// through the public API, and is evaluated — alongside rules that arrived as a
// compiled document — with the deterministic order the registry documents.
package filter_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/protocol"
)

// externalRule is a Rule implementation owned by the importing package: it
// cannot see or set any core state, it only reports spans.
type externalRule struct {
	id       string
	priority int
	keyword  string
	action   filter.Action
	scope    filter.Scope
	inspect  func(leaf []byte) []filter.Span
}

func (r externalRule) ID() string { return r.id }

func (r externalRule) Type() string { return filter.TypeKeyword }

func (r externalRule) Category() string { return filter.CategoryCustom }

func (r externalRule) Scope() filter.Scope {
	if r.scope == "" {
		return filter.ScopeRequest
	}
	return r.scope
}

func (r externalRule) Action() filter.Action { return r.action }

func (r externalRule) Priority() int { return r.priority }

func (r externalRule) Confidence() float64 { return 0.8 }

func (r externalRule) Inspect(leaf []byte) []filter.Span {
	if r.inspect != nil {
		return r.inspect(leaf)
	}
	at := bytes.Index(leaf, []byte(r.keyword))
	if at < 0 {
		return nil
	}
	return []filter.Span{{Start: at, End: at + len(r.keyword)}}
}

func externalLeaf(value string) protocol.Leaf {
	return protocol.Leaf{Path: "/text", Value: []byte(value), Length: len(value)}
}

func externalRuleIDs(findings []filter.AttributedFinding) []string {
	ids := make([]string, len(findings))
	for i := range findings {
		ids[i] = findings[i].RuleID
	}
	return ids
}

// TestExternalPluginRegistersAndEvaluates is the acceptance: two external rule
// sets — one registered directly and one that arrived as a compiled document —
// register through the public API, evaluate, and produce findings in the
// documented deterministic order.
func TestExternalPluginRegistersAndEvaluates(t *testing.T) {
	doc, err := filter.DecodeDocument([]byte(`{
		"rules": [
			{"id":"pack-mid","type":"keyword","keywords":["SECRET"],"action":"warn","scope":"request","priority":15}
		]
	}`))
	if err != nil {
		t.Fatalf("DecodeDocument() error = %v", err)
	}
	set, err := filter.Compile(doc)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	reg := filter.NewRegistry()
	if err := reg.RegisterCompiled(set); err != nil {
		t.Fatalf("RegisterCompiled() error = %v", err)
	}
	err = reg.Register(
		externalRule{id: "ext-late", priority: 20, keyword: "SECRET", action: filter.ActionWarn},
		externalRule{id: "ext-early", priority: 10, keyword: "SECRET", action: filter.ActionWarn},
	)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	findings, err := reg.Evaluate([]protocol.Leaf{externalLeaf("a SECRET b")}, filter.ScopeRequest)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	want := []string{"ext-early", "pack-mid", "ext-late"}
	if got := externalRuleIDs(findings); !reflect.DeepEqual(got, want) {
		t.Fatalf("evaluation order = %v, want %v", got, want)
	}
	for _, finding := range findings {
		if finding.Origin != filter.OriginPlugin && finding.Origin != filter.OriginRemotePack {
			t.Errorf("rule %q origin = %q, want plugin or remote_pack", finding.RuleID, finding.Origin)
		}
	}
	if findings[0].Start != 2 || findings[0].End != 8 {
		t.Errorf("ext-early span = [%d,%d), want [2,8)", findings[0].Start, findings[0].End)
	}
}

// TestExternalPluginRejectionsAreTyped drives the two public rejections from
// outside the package: a duplicate id and a response-capable redact rule. The
// first registration must keep working after each rejection.
func TestExternalPluginRejectionsAreTyped(t *testing.T) {
	reg := filter.NewRegistry()
	first := externalRule{id: "first", priority: 10, keyword: "TOKEN", action: filter.ActionWarn}
	if err := reg.Register(first); err != nil {
		t.Fatalf("Register(first) error = %v", err)
	}

	duplicate := externalRule{id: "first", priority: 10, keyword: "TOKEN", action: filter.ActionBlock}
	if err := reg.Register(duplicate); !errors.Is(err, filter.ErrDuplicateID) {
		t.Fatalf("Register(duplicate) error = %v, want ErrDuplicateID", err)
	}
	for _, scope := range []filter.Scope{filter.ScopeResponse, filter.ScopeBoth} {
		bad := externalRule{id: "redact-" + string(scope), priority: 10, keyword: "TOKEN", action: filter.ActionRedact, scope: scope}
		err := reg.Register(bad)
		if !errors.Is(err, filter.ErrDirection) {
			t.Fatalf("Register(%s + redact) error = %v, want ErrDirection", scope, err)
		}
		if !strings.Contains(err.Error(), bad.id) {
			t.Errorf("rejection %q does not name rule %q", err, bad.id)
		}
	}

	findings, err := reg.Evaluate([]protocol.Leaf{externalLeaf("a TOKEN b")}, filter.ScopeRequest)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got := externalRuleIDs(findings); !reflect.DeepEqual(got, []string{"first"}) {
		t.Fatalf("findings after rejections = %v, want only the first registration", got)
	}
	if findings[0].Action != filter.ActionWarn {
		t.Errorf("first registration action = %q, want warn", findings[0].Action)
	}
}

// TestExternalPluginFailureIsLabelled proves a failing external rule fails
// closed with a typed, labelled refusal rather than a panic or a silent pass.
func TestExternalPluginFailureIsLabelled(t *testing.T) {
	reg := filter.NewRegistry()
	boom := externalRule{id: "ext-boom", priority: 10, action: filter.ActionWarn, inspect: func([]byte) []filter.Span {
		panic("external rule blew up")
	}}
	if err := reg.Register(boom); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	findings, err := reg.Evaluate([]protocol.Leaf{externalLeaf("a TOKEN b")}, filter.ScopeRequest)
	if findings != nil {
		t.Fatalf("findings = %v, want none on a refusal", findings)
	}
	var failure *filter.RuleFailure
	if !errors.As(err, &failure) {
		t.Fatalf("error = %v, want *filter.RuleFailure", err)
	}
	if failure.RuleID != boom.id || failure.Reason != filter.ReasonPanic || failure.Origin != filter.OriginPlugin {
		t.Fatalf("failure = %+v, want %s/panic/plugin", failure, boom.id)
	}
}
