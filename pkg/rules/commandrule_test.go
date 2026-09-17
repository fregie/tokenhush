package rules

import (
	"errors"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// TestCommandRuleCompiles pins the new `command` rule type: it compiles into the
// high-risk command set, not into content findings, and the compiled projection
// carries the specific command plus the optional mutating shape.
func TestCommandRuleCompiles(t *testing.T) {
	cfg := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
		ID:         "custom.dangerctl",
		Type:       RuleCommand,
		Action:     "block",
		Command:    "dangerctl",
		Subcommand: "admin",
		Verbs:      []string{"nuke", "purge"},
		Targets:    []string{"/danger"},
	}}}
	interp, err := Compile(cfg, DefaultOptions())
	if err != nil {
		t.Fatalf("Compile(command rule) = %v, want nil", err)
	}
	cmds := interp.CommandRules()
	if len(cmds) != 1 {
		t.Fatalf("CommandRules() = %d entries, want 1", len(cmds))
	}
	got := cmds[0]
	if got.ID != "custom.dangerctl" || got.Command != "dangerctl" || got.Subcommand != "admin" {
		t.Fatalf("CommandRules()[0] = %+v", got)
	}
	if len(got.Verbs) != 2 || got.Verbs[0] != "nuke" || len(got.Targets) != 1 {
		t.Fatalf("CommandRules()[0] verbs/targets = %+v", got)
	}
	// A command rule produces no content findings.
	doc := docOf(extension.RequestContent, "dangerctl admin nuke")
	if findings, err := interp.Inspect(doc); err != nil || len(findings) != 0 {
		t.Fatalf("Inspect() = (%v, %v), want no findings", findings, err)
	}
	// The accessor returns a copy.
	cmds[0].Verbs[0] = "tampered"
	if interp.CommandRules()[0].Verbs[0] != "nuke" {
		t.Fatal("CommandRules() returned an aliased slice")
	}
}

// TestCommandRuleRejectsGenericCommands is the load-time gate: a rule that names
// a generic shell, interpreter, wrapper, redirection or wildcard is rejected, so
// a blanket rule over generic shell surface can never be shipped.
func TestCommandRuleRejectsGenericCommands(t *testing.T) {
	generic := []string{"sh", "bash", "zsh", "python3", "sudo", "env", "xargs", "*", ">", ">>", "/bin/bash"}
	for _, cmd := range generic {
		cfg := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
			ID: "custom.generic", Type: RuleCommand, Action: "block", Command: cmd,
		}}}
		if _, err := Compile(cfg, DefaultOptions()); !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("Compile(command %q) = %v, want ErrInvalidRule", cmd, err)
		}
	}
}

// TestCommandRuleRejectsMalformed pins the rest of the command-rule validation:
// a missing command, a non-block action, command fields on a regex rule and an
// oversized verb list are all rejected.
func TestCommandRuleRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{"missing_command", Rule{ID: "custom.x", Type: RuleCommand, Action: "block"}},
		{"non_block_action", Rule{ID: "custom.x", Type: RuleCommand, Action: "warn", Command: "dangerctl"}},
		{"regex_with_command_field", Rule{ID: "custom.x", Type: RuleRegex, Action: "block", Pattern: "x", Command: "dangerctl"}},
		{"keyword_with_targets", Rule{ID: "custom.x", Type: RuleKeyword, Action: "block", Keywords: []string{"x"}, Targets: []string{"/a"}}},
		{"too_many_verbs", Rule{ID: "custom.x", Type: RuleCommand, Action: "block", Command: "dangerctl", Verbs: repeatToken("v", MaxCommandVerbsPerRule+1)}},
		{"padded_command", Rule{ID: "custom.x", Type: RuleCommand, Action: "block", Command: " dangerctl "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{SchemaVersion: SchemaVersion, Rules: []Rule{tc.rule}}
			if _, err := Compile(cfg, DefaultOptions()); err == nil {
				t.Fatalf("Compile(%s) = nil error, want a rejection", tc.name)
			}
		})
	}
}

// repeatToken returns n copies of prefix, unique enough for a bounded list.
func repeatToken(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	return out
}
