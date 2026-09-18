package filter

// floor.go is the non-weakening floor (OD-3). It constrains REMOTE PACKS only:
// a signed pack may add detections and tighten sensitivity, but it may never
// lower the compiled-in baseline. Local operator configuration — the
// `detectors:` switches in tokenhush.yaml — is the operator's own choice and is
// deliberately out of scope: the floor never reads, alters or depends on it.
//
// The floor rejects exactly four things: the three the legacy client already
// rejected — a pack that disables a baseline detector, a pack that drops a
// required category, and a rule carrying an `allow` action — plus one explicit
// contract amendment: a rule whose email options set Replace. Additive email
// suffixes only EXTEND the built-in set, but Replace swaps it out, so a pack
// could silently refuse to detect the addresses the built-ins cover while still
// passing the other checks. It is ALLOWLIST-NEUTRAL: it does not inspect
// global or per-rule allowlists. The frozen canary `rules-pack-rich` itself
// carries both, so a stricter floor would reject real packs, drop the client to
// built-ins and leave it weaker than the client it replaces. Making this check
// inspect allowlists is a security regression, not a hardening.

import (
	"errors"
	"fmt"
	"slices"
)

// Floor sentinels. ErrFloor classifies every floor rejection; the four
// wrapped kinds are the frozen floor contract surfaced to plugin authors and
// pinned by pkg/filter/floor_test.go and pkg/supply/rules_test.go.
// specific sentinels each wrap it, so errors.Is branches on either granularity.
var (
	ErrFloor                 = errors.New("filter: floor violation")
	ErrFloorDisablesDetector = fmt.Errorf("%w: remote pack may not disable a built-in detector", ErrFloor)
	ErrFloorRemovesCategory  = fmt.Errorf("%w: remote pack may not remove a required category", ErrFloor)
	ErrFloorAutoAllow        = fmt.Errorf("%w: remote pack may not auto-allow", ErrFloor)
	ErrFloorNarrowsEmail     = fmt.Errorf("%w: remote pack may not replace the built-in email suffix set", ErrFloor)
)

// FloorError is one floor rejection. Kind is the sentinel errors.Is matches —
// ErrFloorDisablesDetector, ErrFloorRemovesCategory, ErrFloorAutoAllow or
// ErrFloorNarrowsEmail — and Item names the offending baseline detector id,
// baseline category, or the rule id (the rule carrying the `allow` action and
// the rule whose email options replace the built-in suffix set).
type FloorError struct {
	Kind error
	Item string
}

// Error renders `<kind>: <item>`.
func (e *FloorError) Error() string { return e.Kind.Error() + ": " + e.Item }

// Unwrap returns the sentinel Kind.
func (e *FloorError) Unwrap() error { return e.Kind }

// FloorBaseline is the compiled-in lower bound a remote pack may not go below.
type FloorBaseline struct {
	// Detectors lists the built-in detector ids that must stay enabled.
	Detectors []string
	// Categories lists the built-in finding categories that must stay detectable.
	Categories []string
}

// DefaultFloorBaseline returns the compiled-in baseline: all six built-in
// detector ids and all six built-in categories, derived from the frozen
// built-in table and deliberately independent of BuiltinConfig — high_entropy
// being off by default does not shrink the floor.
func DefaultFloorBaseline() FloorBaseline {
	rules := BuiltinDetectors()
	baseline := FloorBaseline{
		Detectors:  make([]string, 0, len(rules)),
		Categories: make([]string, 0, len(rules)),
	}
	for _, rule := range rules {
		baseline.Detectors = append(baseline.Detectors, rule.ID())
		baseline.Categories = append(baseline.Categories, rule.Category())
	}
	return baseline
}

// Check rejects a remote pack that weakens the baseline; a compliant pack
// passes unchanged. A document that is not a remote pack (RemotePack false) is
// never checked, because local operator switches stay the operator's choice. A
// nil document is ignored. The check never mutates the document and never
// consults an allowlist — it is allowlist-neutral by design (OD-3).
func (b FloorBaseline) Check(doc *Document) error {
	if doc == nil || !doc.RemotePack {
		return nil
	}
	for _, id := range b.Detectors {
		if enabled, present := doc.Detectors[id]; present && !enabled {
			return &FloorError{Kind: ErrFloorDisablesDetector, Item: id}
		}
	}
	for _, category := range doc.DisabledCategories {
		if slices.Contains(b.Categories, category) {
			return &FloorError{Kind: ErrFloorRemovesCategory, Item: category}
		}
	}
	for i := range doc.Rules {
		if doc.Rules[i].Action == ActionAllow {
			return &FloorError{Kind: ErrFloorAutoAllow, Item: doc.Rules[i].ID}
		}
	}
	// Fourth rejection (explicit contract amendment): an email rule that sets
	// Replace swaps the built-in suffix set for the pack's own. It is checked
	// last on purpose, so the three legacy rejections keep their existing
	// precedence and a pack the v0.4.x client already rejected still reports
	// the same reason. Additive suffixes stay allowed: they only extend the
	// built-in set (see the floor header comment).
	for i := range doc.Rules {
		if doc.Rules[i].Options != nil && doc.Rules[i].Options.Email != nil && doc.Rules[i].Options.Email.Replace {
			return &FloorError{Kind: ErrFloorNarrowsEmail, Item: doc.Rules[i].ID}
		}
	}
	return nil
}
