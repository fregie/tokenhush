package rules

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

func docOf(phase extension.Phase, contents ...string) *extension.Document {
	leaves := make([]extension.Leaf, 0, len(contents))
	for _, c := range contents {
		leaves = append(leaves, extension.Leaf{Path: "#/l", Content: []byte(c), Len: len(c)})
	}
	return &extension.Document{Phase: phase, Tool: "t", Leaves: leaves}
}

func mustCompile(t *testing.T, cfg *Config, opts Options) *Interpreter {
	t.Helper()
	interp, err := Compile(cfg, opts)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return interp
}

func mustInspect(t *testing.T, interp *Interpreter, doc *extension.Document) []extension.Finding {
	t.Helper()
	got, err := interp.Inspect(doc)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	return got
}

// TestStampsRuleIDForAudit locks the ADR-0020 §4 contract: every remote rule hit
// is attributable to its rule_id.
func TestStampsRuleIDForAudit(t *testing.T) {
	cfg := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
		ID: "internal-ticket", Type: RuleRegex, Pattern: `PROJ-[0-9]{4,}`, Action: "warn",
	}}}
	interp := mustCompile(t, cfg, DefaultOptions())
	got := mustInspect(t, interp, docOf(extension.RequestContent, "see PROJ-1234"))
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want 1", got)
	}
	f := got[0]
	if f.Type != "custom:internal-ticket" || f.Meta["rule_id"] != "internal-ticket" {
		t.Errorf("finding = %+v, want attributable rule_id", f)
	}
	if f.PluginID != DefaultPluginID {
		t.Errorf("PluginID = %q, want %q", f.PluginID, DefaultPluginID)
	}
}

func TestOptionsOverrideIdentity(t *testing.T) {
	cfg := &Config{SchemaVersion: SchemaVersion, Blocklist: []string{"DO-NOT-SEND"}}
	interp := mustCompile(t, cfg, Options{PluginID: "customrules", Priority: 30})
	if interp.ID() != "customrules" {
		t.Errorf("ID() = %q, want customrules", interp.ID())
	}
	caps := interp.Capabilities()
	if caps.Priority != 30 || !caps.CanBlock || !caps.ReadContent {
		t.Errorf("Capabilities() = %+v, want priority 30 / ReadContent / CanBlock", caps)
	}
}

func TestCanBlockReflectsContent(t *testing.T) {
	warnOnly := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
		ID: "r", Type: RuleKeyword, Keywords: []string{"x"}, Action: "warn",
	}}}
	if mustCompile(t, warnOnly, DefaultOptions()).Capabilities().CanBlock {
		t.Error("warn-only config declared CanBlock, want false")
	}
	withBlock := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
		ID: "r", Type: RuleKeyword, Keywords: []string{"x"}, Action: "block",
	}}}
	if !mustCompile(t, withBlock, DefaultOptions()).Capabilities().CanBlock {
		t.Error("block rule did not declare CanBlock, want true")
	}
}

func TestOrderingIsDeterministic(t *testing.T) {
	cfg := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
		ID: "kw", Type: RuleKeyword, Keywords: []string{"PROJ"}, Action: "warn",
	}}}
	interp := mustCompile(t, cfg, DefaultOptions())
	doc := docOf(extension.RequestContent, "x PROJ z", "PROJ PROJ")
	first := mustInspect(t, interp, doc)
	again := mustInspect(t, interp, doc)
	if !reflect.DeepEqual(first, again) {
		t.Errorf("Inspect not deterministic:\n%+v\n%+v", first, again)
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].LeafIndex > first[i].LeafIndex {
			t.Fatalf("findings not ordered by leaf: %+v", first)
		}
	}
}

func TestInspectFailsLoudOnMatchLimit(t *testing.T) {
	cfg := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
		ID: "r", Type: RuleKeyword, Keywords: []string{"a"}, Action: "warn",
	}}}
	interp := mustCompile(t, cfg, DefaultOptions())
	_, err := interp.Inspect(docOf(extension.RequestContent, strings.Repeat("a", MaxMatches+1)))
	if !errors.Is(err, ErrTooManyMatches) {
		t.Fatalf("error = %v, want ErrTooManyMatches", err)
	}
}

// TestCompileRejectsAllowAction documents that an allow action is invalid rule
// content; remote packs carrying one are rejected earlier by the floor.
func TestCompileRejectsAllowAction(t *testing.T) {
	cfg := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
		ID: "allow-all", Type: RuleKeyword, Keywords: []string{"x"}, Action: "allow",
	}}}
	if _, err := Compile(cfg, DefaultOptions()); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("error = %v, want ErrInvalidRule", err)
	}
}
