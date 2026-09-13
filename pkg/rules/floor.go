package rules

// The non-weakening floor (ADR-0020 §3). It constrains *remote* rule packs only:
// a remote pack may add detections and tighten sensitivity, but it may never
// lower the compiled-in security baseline. Local `detectors:` switches in
// tokenhush.yaml are the user's own choice and are deliberately out of scope —
// the floor does not read, alter, or depend on them.

import (
	"errors"
	"fmt"
	"slices"

	"github.com/fregie/tokenhush/pkg/extension"
)

// Floor errors.
var (
	// ErrFloorDisablesDetector reports a remote pack that tries to turn a
	// built-in detector off.
	ErrFloorDisablesDetector = errors.New("rules: remote pack may not disable a built-in detector")
	// ErrFloorRemovesCategory reports a remote pack that tries to drop a
	// required detection category.
	ErrFloorRemovesCategory = errors.New("rules: remote pack may not remove a required category")
	// ErrFloorAutoAllow reports a remote pack that tries to auto-allow content
	// through an allow-action rule.
	ErrFloorAutoAllow = errors.New("rules: remote pack may not auto-allow")
)

// Baseline is the compiled-in lower bound a remote pack may not go below.
type Baseline struct {
	// Detectors lists the built-in detector ids that must stay enabled.
	Detectors []string
	// Categories lists the built-in finding categories that must remain
	// detectable.
	Categories []string
}

// DefaultBaseline returns the compiled-in detector ids and categories frozen by
// docs/security.md. It is the floor boundary: built-in defaults, not any local
// user configuration.
func DefaultBaseline() Baseline {
	return Baseline{
		Detectors:  []string{"prefix", "high_entropy", "jwt", "private_key", "luhn", "email"},
		Categories: []string{"api_key", "high_entropy", "jwt", "private_key", "credit_card", "email"},
	}
}

// Check rejects a remote pack that weakens the baseline. A compliant pack
// passes unchanged. The check never mutates the pack and never consults local
// configuration.
func (b Baseline) Check(p *Pack) error {
	if p == nil {
		return nil
	}
	for id, enabled := range p.Detectors {
		if enabled {
			continue
		}
		if slices.Contains(b.Detectors, id) {
			return fmt.Errorf("%w: %s", ErrFloorDisablesDetector, id)
		}
	}
	for _, category := range p.DisabledCategories {
		if slices.Contains(b.Categories, category) {
			return fmt.Errorf("%w: %s", ErrFloorRemovesCategory, category)
		}
	}
	for _, rule := range p.Rules {
		if extension.Action(rule.Action) == extension.Allow {
			return fmt.Errorf("%w: rule %q", ErrFloorAutoAllow, rule.ID)
		}
	}
	return nil
}
