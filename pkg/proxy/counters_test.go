package proxy

import "testing"

// TestExportedCountersMoveTheirOwnAccessors pins the exported increment seam
// the assembler uses: CountRequest moves requests and CountRedactions(n) moves
// redactions by exactly n, each leaving every other counter alone. A
// non-positive n is a no-op and a nil set stays inert, so the monotonic totals
// can never move backwards or panic a status read.
func TestExportedCountersMoveTheirOwnAccessors(t *testing.T) {
	counters := NewCounters()
	counters.CountRequest()
	counters.CountRequest()
	counters.CountRedactions(3)
	if got := counters.Requests(); got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
	if got := counters.Redactions(); got != 3 {
		t.Errorf("redactions = %d, want 3", got)
	}
	for name, got := range map[string]int64{
		"ContentPolicyBlocks": counters.ContentPolicyBlocks(),
		"RuleBlocks":          counters.RuleBlocks(),
		"WalkSkips":           counters.WalkSkips(),
	} {
		if got != 0 {
			t.Errorf("%s moved on a request/redaction increment: %d", name, got)
		}
	}

	counters.CountRedactions(0)
	counters.CountRedactions(-4)
	if got := counters.Redactions(); got != 3 {
		t.Errorf("redactions = %d after non-positive increments, want 3", got)
	}

	var nilSet *Counters
	nilSet.CountRequest()
	nilSet.CountRedactions(2)
	if nilSet.Requests() != 0 || nilSet.Redactions() != 0 {
		t.Errorf("a nil set moved: requests=%d redactions=%d", nilSet.Requests(), nilSet.Redactions())
	}
}
