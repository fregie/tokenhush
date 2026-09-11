package extension

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
)

// recordingSink captures the metadata-only audit rows the policy engine emits
// for plugin failures, so a test can assert a failure was never silent. It is
// safe for concurrent use because the policy engine may run plugins in
// goroutines.
type recordingSink struct {
	mu      sync.Mutex
	records []audit.Record
}

func (s *recordingSink) Record(rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

func (s *recordingSink) snapshot() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...)
}

// scriptedInspector is a fake Inspector whose result the test scripts: fixed
// findings, an error, a panic, or a delay that trips the policy timeout. It
// returns a copy of its findings so the policy engine's plugin-id normalisation
// never mutates the fixture or races a reused inspector.
type scriptedInspector struct {
	id       string
	caps     Capabilities
	findings []Finding
	err      error
	panicMsg string
	delay    time.Duration
}

func (s *scriptedInspector) ID() string                 { return s.id }
func (s *scriptedInspector) Capabilities() Capabilities { return s.caps }

func (s *scriptedInspector) Inspect(*Document) ([]Finding, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	if s.panicMsg != "" {
		panic(s.panicMsg)
	}
	if s.err != nil {
		return nil, s.err
	}
	return append([]Finding(nil), s.findings...), nil
}

func policyTestCaps(phases ...Phase) Capabilities {
	return Capabilities{Phases: phases, ReadContent: true, CanBlock: true}
}

func policyTestDoc() *Document {
	const content = "please use fakeContentValue now"
	return &Document{
		Phase:  RequestContent,
		Tool:   "claude-code",
		Leaves: []Leaf{{Path: "/messages/0/content", Content: []byte(content), Len: len(content)}},
	}
}

// TestPolicyPrecedence drives the full precedence table over every combination
// of four inspector verdicts: the aggregated action must always be the
// highest-precedence finding (Block > Redact > Warn > Allow), independent of
// registration order, and the returned findings must be exactly the winners.
func TestPolicyPrecedence(t *testing.T) {
	actions := []Action{Allow, Warn, Redact, Block}

	t.Run("cartesian_combination_table", func(t *testing.T) {
		t.Logf("precedence ranking: Allow=%d Warn=%d Redact=%d Block=%d unknown=%d",
			Allow.Precedence(), Warn.Precedence(), Redact.Precedence(), Block.Precedence(), Action("bogus").Precedence())
		logged := map[Action]bool{}
		combos := 0
		for _, a0 := range actions {
			for _, a1 := range actions {
				for _, a2 := range actions {
					for _, a3 := range actions {
						combos++
						combo := []Action{a0, a1, a2, a3}
						want := Allow
						for _, a := range combo {
							if a.Precedence() > want.Precedence() {
								want = a
							}
						}
						wantCount := 0
						var wantIDs []string
						for i, a := range combo {
							if a == want {
								wantCount++
								wantIDs = append(wantIDs, fmt.Sprintf("p%d", i))
							}
						}

						reg := NewRegistry()
						for i, a := range combo {
							insp := &scriptedInspector{
								id:   fmt.Sprintf("p%d", i),
								caps: policyTestCaps(RequestContent),
								findings: []Finding{{
									LeafIndex:  0,
									Type:       "t",
									Confidence: 0.5,
									Action:     a,
								}},
							}
							if err := reg.Register(insp); err != nil {
								t.Fatalf("Register(p%d) error = %v", i, err)
							}
						}

						got, err := NewPolicy(reg, PolicyConfig{}).Evaluate(policyTestDoc())
						if err != nil {
							t.Fatalf("Evaluate() error = %v", err)
						}
						if got.Action != want {
							t.Fatalf("combo %v: Action = %s, want %s", combo, got.Action, want)
						}
						if len(got.Findings) != wantCount {
							t.Fatalf("combo %v: %d selected findings, want %d", combo, len(got.Findings), wantCount)
						}
						if !logged[want] {
							logged[want] = true
							t.Logf("sample combo %v -> action=%s selected=%d", combo, got.Action, len(got.Findings))
						}
						for i, f := range got.Findings {
							if f.Action != want {
								t.Fatalf("combo %v: selected[%d].Action = %s, want %s", combo, i, f.Action, want)
							}
							if f.PluginID != wantIDs[i] {
								t.Fatalf("combo %v: selected[%d].PluginID = %q, want %q (deterministic plugin order)", combo, i, f.PluginID, wantIDs[i])
							}
						}
					}
				}
			}
		}
		if combos != 256 {
			t.Fatalf("exercised %d combinations, want 256", combos)
		}
	})

	t.Run("registry_aggregation_is_order_independent", func(t *testing.T) {
		build := func(order []Action) Decision {
			reg := NewRegistry()
			for i, a := range order {
				insp := &scriptedInspector{
					id:       fmt.Sprintf("p%d", i),
					caps:     policyTestCaps(RequestContent),
					findings: []Finding{{Type: "t", Confidence: 0.5, Action: a}},
				}
				if err := reg.Register(insp); err != nil {
					t.Fatalf("Register(p%d) error = %v", i, err)
				}
			}
			got, err := NewPolicy(reg, PolicyConfig{}).Evaluate(policyTestDoc())
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			return got
		}
		if got := build([]Action{Allow, Warn, Redact, Block}); got.Action != Block || len(got.Findings) != 1 {
			t.Fatalf("forward order: Action = %s (%d findings), want Block (1)", got.Action, len(got.Findings))
		}
		if got := build([]Action{Block, Redact, Warn, Allow}); got.Action != Block || len(got.Findings) != 1 {
			t.Fatalf("reverse order: Action = %s (%d findings), want Block (1)", got.Action, len(got.Findings))
		}
		if got := build([]Action{Allow, Warn, Warn, Redact}); got.Action != Redact || len(got.Findings) != 1 {
			t.Fatalf("mixed order: Action = %s (%d findings), want Redact (1)", got.Action, len(got.Findings))
		}
	})
}

// TestPolicyPanicDegradesPerFailurePolicy locks the "a plugin panic is never
// silent" rule: the panic is recovered, the plugin degrades exactly per its
// configured FailurePolicy, and an audit warning is recorded through the
// injected sink.
func TestPolicyPanicDegradesPerFailurePolicy(t *testing.T) {
	t.Run("fail_open_warn_continues_and_audits", func(t *testing.T) {
		sink := &recordingSink{}
		reg := NewRegistry()
		if err := reg.Register(&scriptedInspector{
			id:       "boom",
			caps:     policyTestCaps(RequestContent),
			panicMsg: "inspector exploded",
		}); err != nil {
			t.Fatalf("Register(boom) error = %v", err)
		}
		if err := reg.Register(&scriptedInspector{
			id:       "ok",
			caps:     policyTestCaps(RequestContent),
			findings: []Finding{{Type: "prefix", Confidence: 0.99, Action: Redact}},
		}); err != nil {
			t.Fatalf("Register(ok) error = %v", err)
		}

		got, err := NewPolicy(reg, PolicyConfig{Sink: sink}).Evaluate(policyTestDoc())
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if got.Action != Redact {
			t.Fatalf("Action = %s, want Redact (panic must not block under FailOpenWarn)", got.Action)
		}

		recs := sink.snapshot()
		if len(recs) != 1 {
			t.Fatalf("audit rows = %d, want exactly 1 warning for the panic", len(recs))
		}
		assertPolicyWarning(t, recs[0], "boom", FailureReasonPanic)
		t.Logf("decision: action=%s findings=%d; audit reason=%q plugin=%q", got.Action, len(got.Findings), recs[0].Detectors[2], recs[0].Detectors[1])
	})

	t.Run("fail_closed_blocks_and_audits", func(t *testing.T) {
		sink := &recordingSink{}
		reg := NewRegistry()
		if err := reg.Register(&scriptedInspector{
			id:       "critical",
			caps:     policyTestCaps(RequestContent),
			panicMsg: "critical inspector exploded",
		}); err != nil {
			t.Fatalf("Register(critical) error = %v", err)
		}

		got, err := NewPolicy(reg, PolicyConfig{
			Sink:     sink,
			Failures: map[string]FailurePolicy{"critical": FailClosed},
		}).Evaluate(policyTestDoc())
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if got.Action != Block {
			t.Fatalf("Action = %s, want Block (FailClosed panic must reject)", got.Action)
		}
		if !got.Blocks() {
			t.Fatal("Decision.Blocks() = false, want true")
		}
		if len(got.Findings) != 1 || got.Findings[0].Action != Block || got.Findings[0].PluginID != "critical" {
			t.Fatalf("selected findings = %+v, want one synthetic Block from critical", got.Findings)
		}

		recs := sink.snapshot()
		if len(recs) != 1 {
			t.Fatalf("audit rows = %d, want exactly 1 warning for the panic", len(recs))
		}
		assertPolicyWarning(t, recs[0], "critical", FailureReasonPanic)
		t.Logf("decision: action=%s blocks=%v findings=%+v; audit reason=%q", got.Action, got.Blocks(), got.Findings, recs[0].Detectors[2])
	})
}

// TestPolicyFailClosedErrorBlocks proves an erroring critical inspector rejects
// the request instead of silently forwarding it, and that the failure is
// audited.
func TestPolicyFailClosedErrorBlocks(t *testing.T) {
	sink := &recordingSink{}
	reg := NewRegistry()
	if err := reg.Register(&scriptedInspector{
		id:   "critical",
		caps: policyTestCaps(RequestContent),
		err:  errors.New("detector unavailable"),
	}); err != nil {
		t.Fatalf("Register(critical) error = %v", err)
	}
	// A permissive inspector must not be able to outvote the fail-closed block.
	if err := reg.Register(&scriptedInspector{
		id:   "ok",
		caps: policyTestCaps(RequestContent),
	}); err != nil {
		t.Fatalf("Register(ok) error = %v", err)
	}

	got, err := NewPolicy(reg, PolicyConfig{
		Sink:     sink,
		Failures: map[string]FailurePolicy{"critical": FailClosed},
	}).Evaluate(policyTestDoc())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Action != Block {
		t.Fatalf("Action = %s, want Block (FailClosed error must not silently forward)", got.Action)
	}
	if !got.Blocks() {
		t.Fatal("Decision.Blocks() = false, want true")
	}

	recs := sink.snapshot()
	if len(recs) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1", len(recs))
	}
	assertPolicyWarning(t, recs[0], "critical", FailureReasonError)
	t.Logf("decision: action=%s blocks=%v findings=%+v", got.Action, got.Blocks(), got.Findings)
	t.Logf("audit warning: provider=%q method=%q path=%q client=%q detectors=%v", recs[0].Provider, recs[0].Method, recs[0].Path, recs[0].Client, recs[0].Detectors)
}

// TestPolicyFailOpenErrorContinues is the contrast to the fail-closed case: an
// advisory inspector that errors is dropped, audited, and does not stop the
// request, while other inspectors' findings still apply.
func TestPolicyFailOpenErrorContinues(t *testing.T) {
	sink := &recordingSink{}
	reg := NewRegistry()
	if err := reg.Register(&scriptedInspector{
		id:   "advisory",
		caps: policyTestCaps(RequestContent),
		err:  errors.New("advisory detector unavailable"),
	}); err != nil {
		t.Fatalf("Register(advisory) error = %v", err)
	}
	if err := reg.Register(&scriptedInspector{
		id:       "ok",
		caps:     policyTestCaps(RequestContent),
		findings: []Finding{{Type: "prefix", Confidence: 0.9, Action: Redact}},
	}); err != nil {
		t.Fatalf("Register(ok) error = %v", err)
	}

	got, err := NewPolicy(reg, PolicyConfig{Sink: sink}).Evaluate(policyTestDoc())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Action != Redact {
		t.Fatalf("Action = %s, want Redact (advisory error must fail open)", got.Action)
	}
	if got.Blocks() {
		t.Fatal("Decision.Blocks() = true, want false for an advisory error")
	}
	recs := sink.snapshot()
	if len(recs) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1", len(recs))
	}
	assertPolicyWarning(t, recs[0], "advisory", FailureReasonError)
	t.Logf("decision: action=%s blocks=%v; audit reason=%q plugin=%q", got.Action, got.Blocks(), recs[0].Detectors[2], recs[0].Detectors[1])
}

// TestPolicyTimeoutDegrades proves a hung plugin stops the wait, degrades per
// its FailurePolicy, and is audited, so a timeout is never silent.
func TestPolicyTimeoutDegrades(t *testing.T) {
	const timeout = 20 * time.Millisecond

	t.Run("fail_open_warn_continues", func(t *testing.T) {
		sink := &recordingSink{}
		reg := NewRegistry()
		if err := reg.Register(&scriptedInspector{
			id:    "slow",
			caps:  policyTestCaps(RequestContent),
			delay: 200 * time.Millisecond,
		}); err != nil {
			t.Fatalf("Register(slow) error = %v", err)
		}
		if err := reg.Register(&scriptedInspector{
			id:       "ok",
			caps:     policyTestCaps(RequestContent),
			findings: []Finding{{Type: "prefix", Confidence: 0.9, Action: Redact}},
		}); err != nil {
			t.Fatalf("Register(ok) error = %v", err)
		}

		start := time.Now()
		got, err := NewPolicy(reg, PolicyConfig{Sink: sink, Timeout: timeout}).Evaluate(policyTestDoc())
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
			t.Fatalf("Evaluate() waited %s, want the %s timeout to cut it short", elapsed, timeout)
		}
		if got.Action != Redact {
			t.Fatalf("Action = %s, want Redact (timeout must not block under FailOpenWarn)", got.Action)
		}
		recs := sink.snapshot()
		if len(recs) != 1 {
			t.Fatalf("audit rows = %d, want exactly 1", len(recs))
		}
		assertPolicyWarning(t, recs[0], "slow", FailureReasonTimeout)
		t.Logf("decision: action=%s; audit reason=%q elapsed-bounded=%v", got.Action, recs[0].Detectors[2], true)
	})

	t.Run("fail_closed_blocks", func(t *testing.T) {
		sink := &recordingSink{}
		reg := NewRegistry()
		if err := reg.Register(&scriptedInspector{
			id:    "slow",
			caps:  policyTestCaps(RequestContent),
			delay: 200 * time.Millisecond,
		}); err != nil {
			t.Fatalf("Register(slow) error = %v", err)
		}

		got, err := NewPolicy(reg, PolicyConfig{
			Sink:     sink,
			Timeout:  timeout,
			Failures: map[string]FailurePolicy{"slow": FailClosed},
		}).Evaluate(policyTestDoc())
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if got.Action != Block {
			t.Fatalf("Action = %s, want Block (FailClosed timeout must reject)", got.Action)
		}
		recs := sink.snapshot()
		if len(recs) != 1 {
			t.Fatalf("audit rows = %d, want exactly 1", len(recs))
		}
		assertPolicyWarning(t, recs[0], "slow", FailureReasonTimeout)
		t.Logf("decision: action=%s blocks=%v; audit reason=%q", got.Action, got.Blocks(), recs[0].Detectors[2])
	})
}

// TestPolicyMalformedFindings drives the malformed_input adversarial class: an
// inspector that returns nil findings is clean, while an unknown action,
// out-of-range confidence, negative offsets, or a block without the capability
// invalidates the plugin's whole result and degrades per its FailurePolicy.
func TestPolicyMalformedFindings(t *testing.T) {
	withCaps := policyTestCaps(RequestContent)
	noBlock := Capabilities{Phases: []Phase{RequestContent}, ReadContent: true}

	cases := []struct {
		name     string
		findings []Finding
		caps     Capabilities
		wantWarn bool
	}{
		{name: "nil_findings_is_clean", findings: nil, caps: withCaps, wantWarn: false},
		{name: "unknown_action", findings: []Finding{{Type: "t", Confidence: 0.5, Action: Action("bogus")}}, caps: withCaps, wantWarn: true},
		{name: "confidence_above_range", findings: []Finding{{Type: "t", Confidence: 1.5, Action: Warn}}, caps: withCaps, wantWarn: true},
		{name: "confidence_negative", findings: []Finding{{Type: "t", Confidence: -0.1, Action: Warn}}, caps: withCaps, wantWarn: true},
		{name: "confidence_nan", findings: []Finding{{Type: "t", Confidence: math.NaN(), Action: Warn}}, caps: withCaps, wantWarn: true},
		{name: "negative_leaf_index", findings: []Finding{{Type: "t", Confidence: 0.5, Action: Warn, LeafIndex: -1}}, caps: withCaps, wantWarn: true},
		{name: "negative_start", findings: []Finding{{Type: "t", Confidence: 0.5, Action: Warn, Start: -1, End: 0}}, caps: withCaps, wantWarn: true},
		{name: "end_before_start", findings: []Finding{{Type: "t", Confidence: 0.5, Action: Warn, Start: 5, End: 2}}, caps: withCaps, wantWarn: true},
		{name: "block_without_capability", findings: []Finding{{Type: "t", Confidence: 0.5, Action: Block}}, caps: noBlock, wantWarn: true},
		{name: "valid_finding", findings: []Finding{{Type: "t", Confidence: 0.5, Action: Redact}}, caps: withCaps, wantWarn: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recordingSink{}
			reg := NewRegistry()
			if err := reg.Register(&scriptedInspector{id: "suspect", caps: tc.caps, findings: tc.findings}); err != nil {
				t.Fatalf("Register(suspect) error = %v", err)
			}
			// A healthy lower-precedence inspector proves a malformed plugin
			// fails open without discarding valid findings elsewhere.
			if err := reg.Register(&scriptedInspector{
				id:       "ok",
				caps:     policyTestCaps(RequestContent),
				findings: []Finding{{Type: "email", Confidence: 0.5, Action: Warn}},
			}); err != nil {
				t.Fatalf("Register(ok) error = %v", err)
			}

			got, err := NewPolicy(reg, PolicyConfig{Sink: sink}).Evaluate(policyTestDoc())
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			recs := sink.snapshot()
			if tc.wantWarn {
				if got.Action != Warn {
					t.Fatalf("Action = %s, want Warn (malformed plugin must fail open)", got.Action)
				}
				if len(recs) != 1 {
					t.Fatalf("audit rows = %d, want exactly 1 for the malformed plugin", len(recs))
				}
				assertPolicyWarning(t, recs[0], "suspect", FailureReasonMalformed)
				t.Logf("decision: action=%s (malformed plugin dropped); audit reason=%q plugin=%q", got.Action, recs[0].Detectors[2], recs[0].Detectors[1])
				for _, f := range got.Findings {
					if f.PluginID == "suspect" {
						t.Fatalf("malformed plugin finding leaked into Decision: %+v", f)
					}
				}
				return
			}
			if len(recs) != 0 {
				t.Fatalf("audit rows = %d, want 0 for a clean plugin", len(recs))
			}
			if got.Action != Redact && got.Action != Warn {
				t.Fatalf("Action = %s, want the valid verdict", got.Action)
			}
		})
	}
}

// TestPolicyInputValidation locks the error contract: a nil engine or document
// is a programming error, and a document with an unknown phase must never be
// treated as a silent Allow.
func TestPolicyInputValidation(t *testing.T) {
	var nilPolicy *Policy
	if _, err := nilPolicy.Evaluate(policyTestDoc()); !errors.Is(err, ErrNilPolicy) {
		t.Fatalf("nil policy Evaluate() error = %v, want ErrNilPolicy", err)
	}
	if _, err := NewPolicy(nil, PolicyConfig{}).Evaluate(nil); !errors.Is(err, ErrNilDocument) {
		t.Fatalf("nil document Evaluate() error = %v, want ErrNilDocument", err)
	}
	if _, err := NewPolicy(nil, PolicyConfig{}).Evaluate(&Document{Phase: Phase("bogus")}); !errors.Is(err, ErrInvalidPhase) {
		t.Fatalf("invalid phase Evaluate() error = %v, want ErrInvalidPhase", err)
	}
}

// TestPolicyRefusesMaliciousRequestTransformer is the W4.2 security gate: a
// RequestContent Transformer is refused at registration, and even when forced
// into an internal harness past the registry, the policy path never invokes
// Transform and never hands it request content. With a legitimate redaction
// finding selected, a fake upstream receives only redacted bytes.
func TestPolicyRefusesMaliciousRequestTransformer(t *testing.T) {
	const secret = "fakeContentValue"
	const prefix = "please use "
	malicious := &maliciousRequestTransformer{}

	t.Run("registration_is_refused", func(t *testing.T) {
		reg := NewRegistry()
		err := reg.Register(malicious)
		if !errors.Is(err, ErrTransformerPhase) {
			t.Fatalf("Register(malicious RequestContent transformer) error = %v, want ErrTransformerPhase", err)
		}
		if n := len(reg.Inspectors(RequestContent)); n != 0 {
			t.Fatalf("Inspectors(RequestContent) = %d, want 0 after refusal", n)
		}
		if n := len(reg.Transformers(RequestContent)); n != 0 {
			t.Fatalf("Transformers(RequestContent) = %d, want 0 after refusal", n)
		}
	})

	t.Run("forced_harness_never_hands_request_content_to_transformer", func(t *testing.T) {
		doc := &Document{
			Phase:  RequestContent,
			Tool:   "claude-code",
			Leaves: []Leaf{{Path: "/messages/0/content", Content: []byte(prefix + secret), Len: len(prefix + secret)}},
		}
		legit := &scriptedInspector{
			id:   "prefix-detector",
			caps: policyTestCaps(RequestContent),
			findings: []Finding{{
				LeafIndex:  0,
				Start:      len(prefix),
				End:        len(prefix) + len(secret),
				Type:       "prefix",
				Confidence: 0.99,
				Action:     Redact,
			}},
		}
		sink := &recordingSink{}

		// Bypass the registry on purpose: pass the malicious dual
		// Inspector+Transformer straight to the engine's inner path.
		got := NewPolicy(nil, PolicyConfig{Sink: sink}).evaluate(doc, []Inspector{malicious, legit})

		if got.Action != Redact {
			t.Fatalf("Action = %s, want Redact", got.Action)
		}
		if calls := malicious.transformCount(); calls != 0 {
			t.Fatalf("Transform() called %d times, want 0; the policy path must never transform request content", calls)
		}
		if saw := malicious.seen(); len(saw) != 0 {
			t.Fatalf("policy handed request content to a Transformer: saw %d leaf(s), first %q", len(saw), saw[0])
		}

		recs := sink.snapshot()
		if len(recs) != 1 {
			t.Fatalf("audit rows = %d, want exactly 1 for the refused transformer", len(recs))
		}
		assertPolicyWarning(t, recs[0], malicious.ID(), FailureReasonTransformPhase)
		t.Logf("decision: action=%s; malicious Transform calls=%d, leaves seen=%d; audit reason=%q", got.Action, malicious.transformCount(), len(malicious.seen()), recs[0].Detectors[2])

		// The caller applies the decision; a stand-in fake upstream must never
		// observe the original secret bytes.
		forwarded := redactSelected(t, doc, got.Findings)
		upstream := &recordingUpstream{}
		upstream.forward(forwarded)
		if bytes.Contains(upstream.body(), []byte(secret)) {
			t.Fatalf("fake upstream received the original secret bytes: %q", upstream.body())
		}
		if !bytes.Contains(upstream.body(), []byte("[REDACTED]")) {
			t.Fatalf("fake upstream body = %q, want the redaction to have been applied", upstream.body())
		}
		t.Logf("fake upstream body = %q (secret present=%v)", upstream.body(), bytes.Contains(upstream.body(), []byte(secret)))
	})
}

// maliciousRequestTransformer implements both Inspector and Transformer on a
// phase a Transformer may never hold. If the policy path were to invoke Inspect
// on it with content, it would record the bytes; if it invoked Transform, it
// would count the call. Neither may ever happen.
type maliciousRequestTransformer struct {
	mu             sync.Mutex
	transformCalls int
	saw            [][]byte
}

func (m *maliciousRequestTransformer) ID() string { return "malicious-request-transformer" }

func (m *maliciousRequestTransformer) Capabilities() Capabilities {
	return Capabilities{
		Phases:       []Phase{RequestContent},
		ReadContent:  true,
		CanTransform: true,
		CanBlock:     true,
	}
}

func (m *maliciousRequestTransformer) Inspect(doc *Document) ([]Finding, error) {
	m.mu.Lock()
	for _, leaf := range doc.Leaves {
		if leaf.Content != nil {
			m.saw = append(m.saw, append([]byte(nil), leaf.Content...))
		}
	}
	m.mu.Unlock()
	if len(doc.Leaves) == 0 {
		return nil, nil
	}
	return []Finding{{
		LeafIndex:  0,
		Start:      0,
		End:        len(doc.Leaves[0].Content),
		Type:       "exfiltrate",
		Confidence: 0.9,
		Action:     Redact,
	}}, nil
}

func (m *maliciousRequestTransformer) Transform(doc *Document) (*Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transformCalls++
	return doc, nil
}

func (m *maliciousRequestTransformer) transformCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.transformCalls
}

func (m *maliciousRequestTransformer) seen() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte(nil), m.saw...)
}

// recordingUpstream is the test's fake forwarding target.
type recordingUpstream struct {
	mu   sync.Mutex
	data []byte
}

func (u *recordingUpstream) forward(body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.data = append([]byte(nil), body...)
}

func (u *recordingUpstream) body() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]byte(nil), u.data...)
}

// redactSelected is a test-only stand-in for the W4.4 core applier: it replaces
// each selected Redact span of the first leaf, proving the decision the policy
// returns contains enough information to remove the original bytes.
func redactSelected(t *testing.T, doc *Document, findings []Finding) []byte {
	t.Helper()
	leaf := doc.Leaves[0]
	out := make([]byte, 0, len(leaf.Content)+len("[REDACTED]"))
	last := 0
	for _, f := range findings {
		if f.Action != Redact || f.LeafIndex != 0 {
			continue
		}
		if f.Start < last || f.End < f.Start || f.End > len(leaf.Content) {
			t.Fatalf("invalid redaction span %+v for leaf length %d", f, len(leaf.Content))
		}
		out = append(out, leaf.Content[last:f.Start]...)
		out = append(out, "[REDACTED]"...)
		last = f.End
	}
	out = append(out, leaf.Content[last:]...)
	return out
}

// assertPolicyWarning locks the audit-row encoding for a plugin failure.
func assertPolicyWarning(t *testing.T, rec audit.Record, pluginID, reason string) {
	t.Helper()
	if rec.Provider != AuditProviderPolicy {
		t.Errorf("audit Provider = %q, want %q", rec.Provider, AuditProviderPolicy)
	}
	if rec.Method != AuditMethodPolicy {
		t.Errorf("audit Method = %q, want %q", rec.Method, AuditMethodPolicy)
	}
	if rec.Path != RequestContent.String() {
		t.Errorf("audit Path = %q, want %q", rec.Path, RequestContent)
	}
	if rec.TS <= 0 {
		t.Errorf("audit TS = %d, want a positive unix-millis timestamp", rec.TS)
	}
	if len(rec.Detectors) != 3 || rec.Detectors[0] != "plugin_failure" || rec.Detectors[1] != pluginID || rec.Detectors[2] != reason {
		t.Errorf("audit Detectors = %v, want [plugin_failure %s %s]", rec.Detectors, pluginID, reason)
	}
	if len(rec.PrevHash) != 0 || len(rec.Hash) != 0 {
		t.Errorf("policy warning must not fabricate hash-chain fields: PrevHash=%x Hash=%x", rec.PrevHash, rec.Hash)
	}
}
