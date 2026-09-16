package gateway

import (
	"maps"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/rules"
)

// TestFailClosedDetectorsRemoteRules pins the two-parameter contract of
// failClosedDetectors: the remote-rule interpreter is marked FailClosed exactly
// when the rule pack is active. With rulesActive false the interpreter key must
// be ABSENT (an absent entry means FailOpenWarn), never present with a zero or
// FailOpenWarn value, and the built-ins must stay FailClosed either way.
func TestFailClosedDetectorsRemoteRules(t *testing.T) {
	tests := []struct {
		name        string
		detectors   []string
		rulesActive bool
		want        map[string]extension.FailurePolicy
	}{
		{
			name:        "active rules add the interpreter",
			detectors:   []string{},
			rulesActive: true,
			want: map[string]extension.FailurePolicy{
				rules.DefaultPluginID: extension.FailClosed,
			},
		},
		{
			name:        "inactive rules omit the interpreter",
			detectors:   []string{},
			rulesActive: false,
			want:        map[string]extension.FailurePolicy{},
		},
		{
			name:        "built-ins keep fail closed with active rules",
			detectors:   []string{config.DetectorJWT, config.DetectorEmail},
			rulesActive: true,
			want: map[string]extension.FailurePolicy{
				config.DetectorJWT:    extension.FailClosed,
				config.DetectorEmail:  extension.FailClosed,
				rules.DefaultPluginID: extension.FailClosed,
			},
		},
		{
			name:        "built-ins keep fail closed without active rules",
			detectors:   []string{config.DetectorJWT, config.DetectorEmail},
			rulesActive: false,
			want: map[string]extension.FailurePolicy{
				config.DetectorJWT:   extension.FailClosed,
				config.DetectorEmail: extension.FailClosed,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := failClosedDetectors(tt.detectors, tt.rulesActive)
			if !maps.Equal(got, tt.want) {
				t.Errorf("failClosedDetectors(%v, %t) = %v, want %v", tt.detectors, tt.rulesActive, got, tt.want)
			}
		})
	}
}

// TestFailClosedDetectorsRemoteRulesNegativeControl is the stale-state probe:
// an empty detector list with rulesActive false must never synthesize the
// interpreter key, and rulesActive true must map it to FailClosed (not merely
// contain the key).
func TestFailClosedDetectorsRemoteRulesNegativeControl(t *testing.T) {
	inactive := failClosedDetectors([]string{}, false)
	if policy, ok := inactive[rules.DefaultPluginID]; ok {
		t.Errorf("rulesActive=false synthesized %q = %q; want key absent", rules.DefaultPluginID, policy)
	}

	active := failClosedDetectors([]string{}, true)
	policy, ok := active[rules.DefaultPluginID]
	if !ok {
		t.Fatalf("rulesActive=true omitted %q; map = %v", rules.DefaultPluginID, active)
	}
	if policy != extension.FailClosed {
		t.Errorf("%q policy = %q, want %q", rules.DefaultPluginID, policy, extension.FailClosed)
	}
}
