package gateway

import (
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/rules"
)

// TestBuildPipelineInstallsRulePackCommandRules is the end-to-end
// rule-extensibility proof: a high-risk command declared only in the rule pack
// becomes refused by the C8 guard, with no binary change.
func TestBuildPipelineInstallsRulePackCommandRules(t *testing.T) {
	cfg := &rules.Config{SchemaVersion: rules.SchemaVersion, Rules: []rules.Rule{{
		ID:         "custom.dangerctl",
		Type:       rules.RuleCommand,
		Action:     "block",
		Command:    "dangerctl",
		Subcommand: "admin",
		Verbs:      []string{"nuke"},
	}}}
	pipe, err := BuildPipeline(BuildOptions{
		Rules:          cfg,
		SelfProtection: SelfProtectionConfig{Enabled: true, Modes: []string{config.SelfProtectionModeCLICommand}},
	})
	if err != nil {
		t.Fatalf("BuildPipeline = %v, want nil", err)
	}
	installed := pipe.MutationChannelCommandRules()
	if len(installed) != 1 || installed[0].Command != "dangerctl" {
		t.Fatalf("installed rule-pack commands = %+v, want the dangerctl rule", installed)
	}
	if class, matched := pipe.DetectMutationChannel("dangerctl admin nuke --force"); !matched || class != proxy.MutationChannelCLI {
		t.Fatalf("dangerctl = (%q, %v), want (%q, true)", class, matched, proxy.MutationChannelCLI)
	}
	if _, matched := pipe.DetectMutationChannel("dangerctl admin status"); matched {
		t.Fatal("a non-mutating dangerctl subcommand was refused")
	}
}

// TestBuildPipelineRejectsGenericCommandRule pins that the load gate is on the
// construction path: a rule naming a generic shell aborts startup rather than
// being installed as a blanket rule.
func TestBuildPipelineRejectsGenericCommandRule(t *testing.T) {
	cfg := &rules.Config{SchemaVersion: rules.SchemaVersion, Rules: []rules.Rule{{
		ID: "custom.shell", Type: rules.RuleCommand, Action: "block", Command: "sh",
	}}}
	_, err := BuildPipeline(BuildOptions{
		Rules:          cfg,
		SelfProtection: SelfProtectionConfig{Enabled: true, Modes: []string{config.SelfProtectionModeCLICommand}},
	})
	if err == nil {
		t.Fatal("BuildPipeline accepted a generic command rule")
	}
}
