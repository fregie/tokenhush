package config

import (
	"reflect"
	"testing"
)

// TestLocalDetectorSwitchesAreUserChoice is the ADR-0020 §3 regression: the
// local `detectors:` switches are the user's own selection and keep their exact
// pre-existing semantics. The remote-rule floor never reads or rewrites them, so
// this behavior must not change when remote rules are introduced.
func TestLocalDetectorSwitchesAreUserChoice(t *testing.T) {
	cfg := Default()
	// high_entropy is opt-in; enable it so the exercised set is all six and the
	// switch order stays pinned.
	cfg.Detectors.HighEntropy = true
	want := []string{DetectorPrefix, DetectorHighEntropy, DetectorJWT, DetectorPrivateKey, DetectorLuhn, DetectorEmail}
	if got := cfg.Detectors.EnabledIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("EnabledIDs with high_entropy enabled = %v, want %v", got, want)
	}

	cfg.Detectors.Prefix = false
	want = []string{DetectorHighEntropy, DetectorJWT, DetectorPrivateKey, DetectorLuhn, DetectorEmail}
	if got := cfg.Detectors.EnabledIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("EnabledIDs after local disable = %v, want %v", got, want)
	}
}
