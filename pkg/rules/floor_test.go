package rules

import (
	"errors"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
)

func compliantPack() Pack {
	return Pack{
		Channel:          "stable",
		MinBinaryVersion: "0.3.0",
		Serial:           7,
		KeyID:            "rules-2026a",
		NotBefore:        time.Unix(1_700_000_000, 0),
		Expires:          time.Unix(1_800_000_000, 0),
		Signature:        "sig",
		Config: Config{SchemaVersion: SchemaVersion, Rules: []Rule{{
			ID: "ticket", Type: RuleRegex, Pattern: `PROJ-[0-9]{4,}`, Action: "warn",
		}}},
	}
}

// TestFloorRejectsDisabledDetector is the B6 failure acceptance: a remote pack
// that tries to turn off a built-in detector is rejected.
func TestFloorRejectsDisabledDetector(t *testing.T) {
	p := compliantPack()
	p.Detectors = map[string]bool{"prefix": false}
	err := DefaultBaseline().Check(&p)
	if !errors.Is(err, ErrFloorDisablesDetector) {
		t.Fatalf("error = %v, want ErrFloorDisablesDetector", err)
	}
}

func TestFloorRejectsRemovedCategory(t *testing.T) {
	p := compliantPack()
	p.DisabledCategories = []string{"credit_card"}
	if err := DefaultBaseline().Check(&p); !errors.Is(err, ErrFloorRemovesCategory) {
		t.Fatalf("error = %v, want ErrFloorRemovesCategory", err)
	}
}

func TestFloorRejectsAutoAllow(t *testing.T) {
	p := compliantPack()
	p.Rules = append(p.Rules, Rule{ID: "open-door", Type: RuleKeyword, Keywords: []string{"x"}, Action: "allow"})
	if err := DefaultBaseline().Check(&p); !errors.Is(err, ErrFloorAutoAllow) {
		t.Fatalf("error = %v, want ErrFloorAutoAllow", err)
	}
}

func TestFloorAllowsCompliantPack(t *testing.T) {
	p := compliantPack()
	p.Detectors = map[string]bool{"prefix": true}
	if err := DefaultBaseline().Check(&p); err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
}

// TestFloorIsIndependentOfLocalDetectorConfig is the regression that the local
// `detectors:` switches are the user's own choice and do not move the floor:
// disabling a detector locally still disables it, while a remote pack doing the
// same is rejected.
func TestFloorIsIndependentOfLocalDetectorConfig(t *testing.T) {
	local := config.Default()
	if got := len(local.Detectors.EnabledIDs()); got != 5 {
		t.Fatalf("default EnabledIDs = %d, want 5 (high_entropy is opt-in)", got)
	}
	local.Detectors.Prefix = false
	if ids := local.Detectors.EnabledIDs(); len(ids) != 4 || ids[0] == config.DetectorPrefix {
		t.Fatalf("local disable changed semantics: %v", ids)
	}

	remote := compliantPack()
	remote.Detectors = map[string]bool{config.DetectorPrefix: false}
	if err := DefaultBaseline().Check(&remote); !errors.Is(err, ErrFloorDisablesDetector) {
		t.Fatalf("remote disable error = %v, want ErrFloorDisablesDetector", err)
	}
}
