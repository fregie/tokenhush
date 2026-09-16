package gateway

import (
	"errors"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/rules"
)

// validRemoteRules is a self-contained remote rule pack: one regex rule whose
// acme- token shape cannot collide with any built-in detector.
func validRemoteRules() *rules.Config {
	return &rules.Config{
		SchemaVersion: rules.SchemaVersion,
		Rules: []rules.Rule{{
			ID:      "acme-token",
			Type:    rules.RuleRegex,
			Pattern: "acme-[0-9a-f]{32}",
			Action:  string(extension.Redact),
		}},
	}
}

// inspectorIDs returns the registered inspector ids for phase, in execution
// order.
func inspectorIDs(registry *extension.Registry, phase extension.Phase) []string {
	inspectors := registry.Inspectors(phase)
	ids := make([]string, 0, len(inspectors))
	for _, insp := range inspectors {
		ids = append(ids, insp.ID())
	}
	return ids
}

// containsID reports whether ids contains want.
func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestBuildPipelineRegistersRemoteRules pins the wiring of BuildOptions.Rules:
// the pack is compiled with rules.DefaultOptions() and the interpreter is
// registered under rules.DefaultPluginID at rules.DefaultPriority, after the
// built-in detectors.
func TestBuildPipelineRegistersRemoteRules(t *testing.T) {
	opts := BuildOptions{
		Detectors: []string{config.DetectorPrefix},
		Rules:     validRemoteRules(),
	}
	if _, err := BuildPipeline(opts); err != nil {
		t.Fatalf("BuildPipeline with remote rules: %v", err)
	}
	registry, err := buildRegistry(opts)
	if err != nil {
		t.Fatalf("buildRegistry with remote rules: %v", err)
	}
	ids := inspectorIDs(registry, extension.RequestContent)
	if !containsID(ids, rules.DefaultPluginID) {
		t.Fatalf("remote rules interpreter %q not registered; inspectors = %v", rules.DefaultPluginID, ids)
	}
	if !containsID(ids, config.DetectorPrefix) {
		t.Fatalf("built-in detector %q missing alongside remote rules; inspectors = %v", config.DetectorPrefix, ids)
	}
	for _, insp := range registry.Inspectors(extension.RequestContent) {
		if insp.ID() != rules.DefaultPluginID {
			continue
		}
		if got := insp.Capabilities().Priority; got != rules.DefaultPriority {
			t.Errorf("interpreter priority = %d, want %d", got, rules.DefaultPriority)
		}
	}
}

// TestBuildPipelineRejectsInvalidRemoteRules pins the fail-closed boundary: a
// malformed remote pack aborts construction with a typed, errors.Is-testable
// error and never yields a partially built pipeline.
func TestBuildPipelineRejectsInvalidRemoteRules(t *testing.T) {
	tests := []struct {
		name string
		cfg  *rules.Config
		want error
	}{
		{
			name: "missing schema version",
			cfg:  &rules.Config{SchemaVersion: 0},
			want: rules.ErrSchemaVersion,
		},
		{
			name: "duplicate rule id",
			cfg: &rules.Config{
				SchemaVersion: rules.SchemaVersion,
				Rules: []rules.Rule{
					{ID: "acme-token", Type: rules.RuleRegex, Pattern: "acme-[0-9a-f]{32}", Action: string(extension.Redact)},
					{ID: "acme-token", Type: rules.RuleRegex, Pattern: "acme-[0-9a-f]{64}", Action: string(extension.Redact)},
				},
			},
			want: rules.ErrInvalidRule,
		},
		{
			name: "non-compiling regex",
			cfg: &rules.Config{
				SchemaVersion: rules.SchemaVersion,
				Rules: []rules.Rule{
					{ID: "acme-token", Type: rules.RuleRegex, Pattern: "acme-[", Action: string(extension.Redact)},
				},
			},
			want: rules.ErrInvalidRegex,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := BuildOptions{Detectors: []string{config.DetectorPrefix}, Rules: tt.cfg}
			pipeline, err := BuildPipeline(opts)
			if err == nil {
				t.Fatalf("BuildPipeline(%s) = nil error, want errors.Is %v", tt.name, tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("BuildPipeline(%s) error = %v, want errors.Is %v", tt.name, err, tt.want)
			}
			if pipeline != nil {
				t.Errorf("BuildPipeline(%s) returned a non-nil pipeline alongside the error %v", tt.name, err)
			}
		})
	}
}

// TestBuildPipelineRulesNilDropsNoBuiltins pins the inertness contract: with
// Rules nil the remote path is never taken, so the request-content inspector
// set is exactly the enabled built-in detectors and never contains the
// remote-rule interpreter.
func TestBuildPipelineRulesNilDropsNoBuiltins(t *testing.T) {
	detectors := []string{config.DetectorPrefix, config.DetectorJWT, config.DetectorEmail}
	opts := BuildOptions{Detectors: detectors}
	if _, err := BuildPipeline(opts); err != nil {
		t.Fatalf("BuildPipeline without remote rules: %v", err)
	}
	registry, err := buildRegistry(opts)
	if err != nil {
		t.Fatalf("buildRegistry without remote rules: %v", err)
	}
	ids := inspectorIDs(registry, extension.RequestContent)
	if containsID(ids, rules.DefaultPluginID) {
		t.Errorf("Rules nil registered the remote-rule interpreter; inspectors = %v", ids)
	}
	got := make(map[string]bool, len(ids))
	for _, id := range ids {
		got[id] = true
	}
	if len(got) != len(detectors) {
		t.Errorf("inspector count = %d (%v), want %d enabled built-ins (%v)", len(got), ids, len(detectors), detectors)
	}
	for _, id := range detectors {
		if !got[id] {
			t.Errorf("enabled built-in %q missing; inspectors = %v", id, ids)
		}
	}
}
