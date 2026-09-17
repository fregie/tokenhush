package filter

// floor_test.go pins OD-3 and the frozen floor behaviour: the floor rejects
// exactly three things — a remote pack that disables a baseline detector, drops
// a required category, or carries an `allow` action — and it is
// allowlist-neutral, proven by a positive test so it cannot be "helpfully"
// tightened later. The floor applies to remote packs only; local operator
// switches are never inspected.

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// remotePack decodes a fixture and asserts it decoded as a remote pack, so a
// floor test can never pass because the document was silently treated as local.
func remotePack(t *testing.T, body string) *Document {
	t.Helper()
	doc, err := DecodeDocument([]byte(body))
	if err != nil {
		t.Fatalf("DecodeDocument(%s) error = %v", body, err)
	}
	if !doc.RemotePack {
		t.Fatalf("fixture decoded as a local document, want a remote pack: %s", body)
	}
	return doc
}

// assertFloorRejection asserts the rejection's sentinel, that it is a typed
// *FloorError, and that it names the offending item.
func assertFloorRejection(t *testing.T, err, kind error, item string) {
	t.Helper()
	if !errors.Is(err, kind) {
		t.Fatalf("Check() error = %v, want %v", err, kind)
	}
	if !errors.Is(err, ErrFloor) {
		t.Errorf("Check() error = %v, want it to match the ErrFloor family", err)
	}
	var floorErr *FloorError
	if !errors.As(err, &floorErr) {
		t.Fatalf("Check() error = %v, want a typed *FloorError", err)
	}
	if floorErr.Item != item {
		t.Errorf("rejection Item = %q, want %q", floorErr.Item, item)
	}
	if !strings.Contains(err.Error(), item) {
		t.Errorf("rejection %q does not name %q", err, item)
	}
	t.Logf("rejected: %v", err)
}

// TestFloorRejectsDisabledBaselineDetector is the frozen rejection: a remote
// pack that turns off a baseline detector is rejected naming that detector.
func TestFloorRejectsDisabledBaselineDetector(t *testing.T) {
	doc := remotePack(t, `{"serial": 7, "key_id": "rules-2026a", "detectors": {"prefix": false}}`)
	assertFloorRejection(t, DefaultFloorBaseline().Check(doc), ErrFloorDisablesDetector, DetectorPrefix)
}

// TestFloorRejectsDroppedCategory is the frozen rejection: a remote pack that
// drops a baseline category is rejected naming that category.
func TestFloorRejectsDroppedCategory(t *testing.T) {
	doc := remotePack(t, `{"serial": 7, "key_id": "rules-2026a", "disabled_categories": ["credit_card"]}`)
	assertFloorRejection(t, DefaultFloorBaseline().Check(doc), ErrFloorRemovesCategory, CategoryCreditCard)
}

// TestFloorRejectsAllowRule is the frozen rejection: no rule of a remote pack
// may carry the `allow` action; the rejection names the rule id.
func TestFloorRejectsAllowRule(t *testing.T) {
	doc := remotePack(t, `{"serial": 7, "key_id": "rules-2026a", "rules": [
		{"id": "open-door", "type": "keyword", "keywords": ["x"], "action": "allow"}
	]}`)
	assertFloorRejection(t, DefaultFloorBaseline().Check(doc), ErrFloorAutoAllow, "open-door")
}

// TestFloorIsAllowlistNeutral is the OD-3 positive assertion: a remote pack
// carrying a global allowlist and a per-rule allowlist is ACCEPTED with zero
// violations. The fixture asserts it really carries both lists, so acceptance
// cannot be vacuous, and the floor must never inspect them.
func TestFloorIsAllowlistNeutral(t *testing.T) {
	doc := remotePack(t, `{"serial": 7, "key_id": "rules-2026a", "allowlist": ["example.com"], "rules": [
		{"id": "ticket", "type": "keyword", "keywords": ["PROJ-"], "action": "warn", "allowlist": ["not-a-secret"]}
	]}`)
	if len(doc.Allowlist) != 1 || len(doc.Rules) != 1 || len(doc.Rules[0].Allowlist) != 1 {
		t.Fatalf("fixture lost its allowlists: %+v", doc)
	}
	if err := DefaultFloorBaseline().Check(doc); err != nil {
		t.Fatalf("Check() rejected an allowlist-carrying remote pack: %v (OD-3: the floor is allowlist-neutral)", err)
	}
	t.Logf("accepted: zero violations (global allowlist %v, per-rule allowlist %v)", doc.Allowlist, doc.Rules[0].Allowlist)
}

// TestFloorAcceptsCompliantRemotePack is the positive control: a pack that adds
// rules and keeps every baseline detector enabled passes unchanged.
func TestFloorAcceptsCompliantRemotePack(t *testing.T) {
	doc := remotePack(t, `{"serial": 7, "key_id": "rules-2026a", "detectors": {"prefix": true}, "rules": [
		{"id": "ticket", "type": "keyword", "keywords": ["PROJ-"], "action": "warn"}
	]}`)
	if err := DefaultFloorBaseline().Check(doc); err != nil {
		t.Fatalf("Check() error = %v, want nil for a compliant remote pack", err)
	}
}

// TestFloorBaselineIsAllSix pins the baseline: all six detector ids and all six
// categories, regardless of the runtime default that leaves entropy off.
func TestFloorBaselineIsAllSix(t *testing.T) {
	baseline := DefaultFloorBaseline()
	if len(baseline.Detectors) != 6 || len(baseline.Categories) != 6 {
		t.Fatalf("baseline = %+v, want all six detector ids and all six categories", baseline)
	}
	for _, id := range []string{"prefix", "email", "luhn", "jwt", "private_key", "high_entropy"} {
		if !slices.Contains(baseline.Detectors, id) {
			t.Errorf("baseline detectors %v are missing %q", baseline.Detectors, id)
		}
	}
	for _, category := range []string{"api_key", "email", "credit_card", "jwt", "private_key", "high_entropy"} {
		if !slices.Contains(baseline.Categories, category) {
			t.Errorf("baseline categories %v are missing %q", baseline.Categories, category)
		}
	}

	// The runtime default excludes entropy; the baseline must not shrink with it.
	if slices.Contains(builtinIDs(DefaultBuiltinDetectors()), DetectorHighEntropy) {
		t.Fatalf("default set unexpectedly includes %s", DetectorHighEntropy)
	}
	if !slices.Contains(baseline.Detectors, DetectorHighEntropy) {
		t.Fatalf("baseline detectors %v lost %s with the runtime default", baseline.Detectors, DetectorHighEntropy)
	}
}

// TestFloorAppliesToRemotePacksOnly pins the scope: a local operator document
// that violates every floor rule is not floor-rejected, because local switches
// stay the operator's choice.
func TestFloorAppliesToRemotePacksOnly(t *testing.T) {
	body := `{"detectors": {"prefix": false}, "disabled_categories": ["credit_card"], "rules": [
		{"id": "local-allow", "type": "keyword", "keywords": ["x"], "action": "allow"}
	]}`
	doc, err := DecodeDocument([]byte(body))
	if err != nil {
		t.Fatalf("DecodeDocument(%s) error = %v", body, err)
	}
	if doc.RemotePack {
		t.Fatalf("fixture decoded as a remote pack, want a local document")
	}
	if err := DefaultFloorBaseline().Check(doc); err != nil {
		t.Fatalf("floor rejected a local operator document: %v", err)
	}
	if err := DefaultFloorBaseline().Check(nil); err != nil {
		t.Fatalf("floor rejected a nil document: %v", err)
	}
}
