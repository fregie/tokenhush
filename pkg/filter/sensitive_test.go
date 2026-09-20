package filter

// sensitive_test.go is the Wave-1 red-first regression suite for Feature A: the
// document-level sensitive_keys block. It pins the strict decode and its bounds,
// the opt-in nature of the block, compilation carrying it through evaluation,
// the per-leaf gate (a gated leaf is not handed to Redact-producing rules, a
// Block-producing rule and the blocklist keep their precedence, allowlists
// suppress the gate), three-path finding parity and the request-phase-only
// direction contract.
//
// The tests drive the public API with raw JSON and protocol.Walk, so they
// compile before any sensitive-key production symbol exists. Today every
// document that names sensitive_keys is rejected as an unknown field, so each
// test is red on the assertion it names; the gate assertions describe the
// post-implementation observable the plan pins (A-FD1..A-FD5).

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// sensitiveKeyTestRuleID is the gate's frozen finding identity (A-FD2).
const sensitiveKeyTestRuleID = "sensitive_key"

// mustWalkLeaves walks one JSON body into leaves or fails the test.
func mustWalkLeaves(t *testing.T, body string) []protocol.Leaf {
	t.Helper()
	leaves, err := protocol.Walk([]byte(body))
	if err != nil {
		t.Fatalf("protocol.Walk(%q): %v", body, err)
	}
	return leaves
}

// sensitiveGateFindings keeps only the findings the sensitive-key gate produced.
func sensitiveGateFindings(findings []Finding) []Finding {
	var out []Finding
	for _, finding := range findings {
		if finding.RuleID == sensitiveKeyTestRuleID {
			out = append(out, finding)
		}
	}
	return out
}

// sensitiveGateAttributed keeps only the gate's core-stamped findings.
func sensitiveGateAttributed(findings []AttributedFinding) []AttributedFinding {
	var out []AttributedFinding
	for _, finding := range findings {
		if finding.RuleID == sensitiveKeyTestRuleID {
			out = append(out, finding)
		}
	}
	return out
}

// parityRecord is the subset of a finding the three evaluation paths must agree
// on; the origin is deliberately excluded (A-FD5).
type parityRecord struct {
	RuleID     string
	Category   string
	Action     Action
	LeafIndex  int
	Start      int
	End        int
	Confidence float64
}

func parityRecords(findings []Finding) []parityRecord {
	out := make([]parityRecord, 0, len(findings))
	for _, finding := range findings {
		out = append(out, parityRecord{
			RuleID: finding.RuleID, Category: finding.Category, Action: finding.Action,
			LeafIndex: finding.LeafIndex, Start: finding.Start, End: finding.End, Confidence: finding.Confidence,
		})
	}
	return out
}

func parityRecordsAttributed(findings []AttributedFinding) []parityRecord {
	out := make([]parityRecord, 0, len(findings))
	for _, finding := range findings {
		out = append(out, parityRecord{
			RuleID: finding.RuleID, Category: finding.Category, Action: finding.Action,
			LeafIndex: finding.LeafIndex, Start: finding.Start, End: finding.End, Confidence: finding.Confidence,
		})
	}
	return out
}

// newSensitivePaths builds the registered (Registry) and runtime (Policy) paths
// over one compiled document, so the parity tests share the exact same set.
func newSensitivePaths(t *testing.T, set *Compiled) (*Registry, *Policy) {
	t.Helper()
	reg := NewRegistry()
	if err := reg.RegisterCompiled(set); err != nil {
		t.Fatalf("RegisterCompiled: %v", err)
	}
	return reg, NewPolicy(reg, PolicyConfig{})
}

// repeatKeys returns n distinct key names, for the count-bound cases.
func repeatKeys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = "key" + strconv.Itoa(i)
	}
	return keys
}

// sensitiveKeysDocument renders a document body carrying a sensitive_keys block
// with the given key list, so a bound case can build an over-long list.
func sensitiveKeysDocument(keys []string) string {
	var b strings.Builder
	b.WriteString(`{"sensitive_keys":{"keys":[`)
	for i, key := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Quote(key))
	}
	b.WriteString(`]}}`)
	return b.String()
}

// TestDecodeSensitiveKeysStrict pins A-FD1: only keys []string and
// case_sensitive bool are accepted, an unknown sub-key is rejected by name, an
// empty key is rejected, and the key-count and per-key byte bounds fail with
// ErrBoundExceeded. MaxSensitiveKeys is pinned as the literal 256 here because
// the constant is declared in a later wave; MaxLiteralBytes already exists.
func TestDecodeSensitiveKeysStrict(t *testing.T) {
	t.Run("valid block decodes", func(t *testing.T) {
		if _, err := DecodeDocument([]byte(`{"sensitive_keys":{"keys":["password","token"],"case_sensitive":true}}`)); err != nil {
			t.Fatalf("a valid sensitive_keys block must decode: %v", err)
		}
	})
	t.Run("case_sensitive defaults when absent", func(t *testing.T) {
		if _, err := DecodeDocument([]byte(`{"sensitive_keys":{"keys":["password"]}}`)); err != nil {
			t.Fatalf("a block without case_sensitive must decode: %v", err)
		}
	})
	t.Run("unknown sub-key rejected by name", func(t *testing.T) {
		_, err := DecodeDocument([]byte(`{"sensitive_keys":{"keys":["password"],"bogus":true}}`))
		if err == nil {
			t.Fatal("an unknown sub-key must be rejected")
		}
		if !errors.Is(err, ErrUnknownField) {
			t.Errorf("error = %v, want ErrUnknownField", err)
		}
		if !strings.Contains(err.Error(), "sensitive_keys.bogus") {
			t.Errorf("error %q must name the offending sub-key sensitive_keys.bogus", err)
		}
	})
	t.Run("empty key list rejected", func(t *testing.T) {
		if _, err := DecodeDocument([]byte(sensitiveKeysDocument([]string{}))); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("error = %v, want ErrInvalidValue for an empty key list", err)
		}
	})
	t.Run("empty key rejected", func(t *testing.T) {
		if _, err := DecodeDocument([]byte(sensitiveKeysDocument([]string{""}))); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("error = %v, want ErrInvalidValue for an empty key", err)
		}
	})
	t.Run("key-count bound", func(t *testing.T) {
		if _, err := DecodeDocument([]byte(sensitiveKeysDocument(repeatKeys(256)))); err != nil {
			t.Fatalf("exactly MaxSensitiveKeys (256) keys must decode: %v", err)
		}
		if _, err := DecodeDocument([]byte(sensitiveKeysDocument(repeatKeys(257)))); !errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("error = %v, want ErrBoundExceeded one key over the bound", err)
		}
	})
	t.Run("per-key byte bound", func(t *testing.T) {
		if _, err := DecodeDocument([]byte(sensitiveKeysDocument([]string{strings.Repeat("k", MaxLiteralBytes)}))); err != nil {
			t.Fatalf("a %d-byte key must decode: %v", MaxLiteralBytes, err)
		}
		if _, err := DecodeDocument([]byte(sensitiveKeysDocument([]string{strings.Repeat("k", MaxLiteralBytes+1)}))); !errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("error = %v, want ErrBoundExceeded for a key above the byte bound", err)
		}
	})
}

// TestDecodeMissingSensitiveKeysUnchanged pins that the block is opt-in: a
// document that omits it must create no matcher. The negative baseline (no
// finding) is asserted first; the positive control (the same leaf with the
// block present gates to one finding) is what fails until the schema lands.
func TestDecodeMissingSensitiveKeysUnchanged(t *testing.T) {
	leaves := mustWalkLeaves(t, `{"password":"hunter2"}`)

	baseline := compileDoc(t, `{"rules":[{"id":"kw","type":"keyword","keywords":["hunter2"],"action":"warn"}]}`)
	if got := sensitiveGateFindings(mustEvaluate(t, baseline, leaves, ScopeRequest)); len(got) != 0 {
		t.Fatalf("a document without sensitive_keys must create no matcher, got %+v", got)
	}

	control := compileDoc(t, `{"sensitive_keys":{"keys":["password"]},"rules":[{"id":"kw","type":"keyword","keywords":["hunter2"],"action":"warn"}]}`)
	if got := sensitiveGateFindings(mustEvaluate(t, control, leaves, ScopeRequest)); len(got) != 1 {
		t.Fatalf("the same leaf with sensitive_keys present must gate to one finding, got %+v", got)
	}
}

// TestCompileSensitiveKeysCarriedAndEvaluated pins that CompileWithBudget
// carries the block and evaluation reflects it: one whole-value finding with
// the frozen A-FD2 identity.
func TestCompileSensitiveKeysCarriedAndEvaluated(t *testing.T) {
	set, err := CompileWithBudget(decodeDoc(t, `{"sensitive_keys":{"keys":["password"]}}`), 1<<20)
	if err != nil {
		t.Fatalf("CompileWithBudget: %v", err)
	}
	leaves := mustWalkLeaves(t, `{"password":"hunter2"}`)
	findings := mustEvaluate(t, set, leaves, ScopeRequest)
	got := sensitiveGateFindings(findings)
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want exactly one sensitive_key finding", findings)
	}
	finding := got[0]
	if finding.RuleID != sensitiveKeyTestRuleID || finding.Category != CategoryCustom || finding.Action != ActionRedact {
		t.Errorf("finding = %+v, want id %q, category %q, action %q", finding, sensitiveKeyTestRuleID, CategoryCustom, ActionRedact)
	}
	if finding.LeafIndex != 0 || finding.Start != 0 || finding.End != len("hunter2") {
		t.Errorf("span = leaf %d [%d,%d), want leaf 0 [0,%d)", finding.LeafIndex, finding.Start, finding.End, len("hunter2"))
	}
	if finding.Confidence <= 0 || finding.Confidence > 1 {
		t.Errorf("confidence = %v, want the gate's high confidence in (0,1]", finding.Confidence)
	}
}

// TestSensitiveKeyGateSkipsRedactionRules pins A-FD4: a matched leaf is not
// handed to a Redact-producing rule; the gate yields one whole-value finding.
func TestSensitiveKeyGateSkipsRedactionRules(t *testing.T) {
	set := compileDoc(t, `{
	  "sensitive_keys": {"keys": ["password"]},
	  "rules": [{"id": "leaky", "type": "keyword", "keywords": ["hunter2"], "action": "redact"}]
	}`)
	leaves := mustWalkLeaves(t, `{"password":"hunter2"}`)
	findings := mustEvaluate(t, set, leaves, ScopeRequest)
	for _, finding := range findings {
		if finding.RuleID == "leaky" {
			t.Errorf("a gated leaf must not be handed to a Redact-producing rule, got %+v", finding)
		}
	}
	got := sensitiveGateFindings(findings)
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want exactly one whole-value sensitive finding", findings)
	}
	if got[0].Start != 0 || got[0].End != len("hunter2") {
		t.Errorf("gate span = [%d,%d), want the whole value [0,%d)", got[0].Start, got[0].End, len("hunter2"))
	}
	if len(findings) != 1 {
		t.Errorf("the gate must yield exactly one finding for this document, got %+v", findings)
	}
}

// TestSensitiveKeyGatePreservesBlock pins A-FD4's Block precedence: a
// Block-producing rule is still evaluated on a gated leaf, and the decision is
// Block.
func TestSensitiveKeyGatePreservesBlock(t *testing.T) {
	set := compileDoc(t, `{
	  "sensitive_keys": {"keys": ["password"]},
	  "rules": [{"id": "blocker", "type": "keyword", "keywords": ["hunter2"], "action": "block"}]
	}`)
	leaves := mustWalkLeaves(t, `{"password":"hunter2"}`)
	findings := mustEvaluate(t, set, leaves, ScopeRequest)
	blocked := false
	for _, finding := range findings {
		if finding.RuleID == "blocker" && finding.Action == ActionBlock {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("a keyword-Block rule must still block a sensitive-key leaf, got %+v", findings)
	}

	_, policy := newSensitivePaths(t, set)
	decision, err := policy.Decide(leaves, ScopeRequest)
	if err != nil {
		t.Fatalf("Policy.Decide: %v", err)
	}
	if decision.Action != ActionBlock {
		t.Errorf("decision action = %q, want %q with Block precedence", decision.Action, ActionBlock)
	}
}

// TestSensitiveKeyGateRespectsAllowlist pins A-FD4's allowlist rule: an
// allowlisted literal covering the leaf value suppresses the gate finding.
func TestSensitiveKeyGateRespectsAllowlist(t *testing.T) {
	set := compileDoc(t, `{
	  "allowlist": ["hunter2"],
	  "sensitive_keys": {"keys": ["password"]}
	}`)
	leaves := mustWalkLeaves(t, `{"password":"hunter2"}`)
	findings := mustEvaluate(t, set, leaves, ScopeRequest)
	if got := sensitiveGateFindings(findings); len(got) != 0 {
		t.Fatalf("an allowlisted literal must suppress the gate finding, got %+v", got)
	}
}

// TestSensitiveKeyThreePathParity pins A-FD5: Policy.Decide, Registry.Evaluate
// and Compiled.Evaluate produce identical sensitive-key findings on RuleID,
// category, action, leaf index, span and confidence (origin excluded).
func TestSensitiveKeyThreePathParity(t *testing.T) {
	set := compileDoc(t, `{"sensitive_keys":{"keys":["password"]}}`)
	reg, policy := newSensitivePaths(t, set)
	leaves := mustWalkLeaves(t, `{"password":"hunter2","other":"plain"}`)

	compiled, err := set.Evaluate(leaves, ScopeRequest)
	if err != nil {
		t.Fatalf("Compiled.Evaluate: %v", err)
	}
	attributed, err := reg.Evaluate(leaves, ScopeRequest)
	if err != nil {
		t.Fatalf("Registry.Evaluate: %v", err)
	}
	decision, err := policy.Decide(leaves, ScopeRequest)
	if err != nil {
		t.Fatalf("Policy.Decide: %v", err)
	}

	want := parityRecords(sensitiveGateFindings(compiled))
	fromRegistry := parityRecordsAttributed(sensitiveGateAttributed(attributed))
	fromPolicy := parityRecordsAttributed(sensitiveGateAttributed(decision.Findings))
	if !reflect.DeepEqual(want, fromRegistry) {
		t.Fatalf("Registry findings = %+v, want the Compiled findings %+v", fromRegistry, want)
	}
	if !reflect.DeepEqual(want, fromPolicy) {
		t.Fatalf("Policy findings = %+v, want the Compiled findings %+v", fromPolicy, want)
	}
	if len(want) != 1 || want[0].RuleID != sensitiveKeyTestRuleID || want[0].LeafIndex != 0 {
		t.Fatalf("parity baseline = %+v, want one sensitive_key finding on leaf 0", want)
	}
}

// TestSensitiveKeyBlocklistNeverSuppressed pins A-FD4 on the Compiled.Evaluate
// path only: a blocklist hit inside a gated leaf still blocks, and no allowlist
// suppresses it.
func TestSensitiveKeyBlocklistNeverSuppressed(t *testing.T) {
	set := compileDoc(t, `{
	  "allowlist": ["hunter2"],
	  "blocklist": ["hunter2"],
	  "sensitive_keys": {"keys": ["password"]}
	}`)
	leaves := mustWalkLeaves(t, `{"password":"hunter2"}`)
	findings := mustEvaluate(t, set, leaves, ScopeRequest)
	var blocked *Finding
	for i := range findings {
		if findings[i].RuleID == RuleIDBlocklist {
			blocked = &findings[i]
		}
	}
	if blocked == nil {
		t.Fatalf("a blocklist hit inside a gated leaf must still block, got %+v", findings)
	}
	if blocked.Action != ActionBlock || blocked.Start != 0 || blocked.End != len("hunter2") || blocked.Confidence != 1 {
		t.Errorf("blocklist finding = %+v, want Block [0,%d) at confidence 1", *blocked, len("hunter2"))
	}
}

// TestSensitiveKeyResponsePhaseNoSubstitution pins the direction contract: the
// gate is request-phase only, so the response phase mints no placeholder and
// emits no sensitive-key finding.
func TestSensitiveKeyResponsePhaseNoSubstitution(t *testing.T) {
	set := compileDoc(t, `{"sensitive_keys":{"keys":["password"]}}`)
	_, policy := newSensitivePaths(t, set)
	leaves := mustWalkLeaves(t, `{"password":"hunter2"}`)

	decision, err := policy.Decide(leaves, ScopeResponse)
	if err != nil {
		t.Fatalf("Policy.Decide(response): %v", err)
	}
	if len(decision.Substitutions) != 0 {
		t.Fatalf("response phase must never carry a substitution, got %+v", decision.Substitutions)
	}
	if got := sensitiveGateAttributed(decision.Findings); len(got) != 0 {
		t.Errorf("the gate is request-phase only; response findings = %+v, want none", got)
	}
	compiled, err := set.Evaluate(leaves, ScopeResponse)
	if err != nil {
		t.Fatalf("Compiled.Evaluate(response): %v", err)
	}
	if got := sensitiveGateFindings(compiled); len(got) != 0 {
		t.Errorf("Compiled.Evaluate(response) sensitive findings = %+v, want none", got)
	}
}

// TestSensitiveKeyBoundRespected pins A-FD1's bounds end to end: an over-count
// key list and an over-long key are both rejected with ErrBoundExceeded.
func TestSensitiveKeyBoundRespected(t *testing.T) {
	cases := []struct {
		name string
		keys []string
	}{
		{"over the key-count bound", repeatKeys(257)},
		{"over the per-key byte bound", []string{strings.Repeat("k", MaxLiteralBytes+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeDocument([]byte(sensitiveKeysDocument(tc.keys))); !errors.Is(err, ErrBoundExceeded) {
				t.Fatalf("error = %v, want ErrBoundExceeded", err)
			}
		})
	}
}
