package extension

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
)

// FailurePolicy declares how the core degrades when a content plugin panics,
// times out, or returns an invalid result. It is a per-plugin property of the
// core's policy, not something a plugin self-certifies: the core owns the
// decision, so the compiled-in critical tier can be marked FailClosed without
// changing any plugin code.
type FailurePolicy string

const (
	// FailOpenWarn drops a failed plugin's findings, records an audit warning
	// through the injected audit.AuditSink, and lets the request continue. It
	// is the default and is appropriate for advisory inspectors whose failure
	// must never block a request.
	FailOpenWarn FailurePolicy = "fail_open_warn"

	// FailClosed rejects the request when a critical plugin fails: the decision
	// is Block, never a silent forward. Use it for inspectors whose verdict the
	// request must not proceed without.
	FailClosed FailurePolicy = "fail_closed"
)

// DefaultPluginTimeout is the wall-clock backstop that bounds a single
// Inspector.Inspect call when PolicyConfig.Timeout is unset. It is deliberately
// generous: the built-in detectors are configured FailClosed, so a short timing
// bound would turn a large but legitimate request into a refusal on any machine
// whose CPU is merely slow or loaded (a 16 MB body scanned by the high_entropy
// detector was measured at ~5.5 s on an idle machine). Normal operation must
// never reach it.
//
// It is a backstop only. The deterministic limit on how much content is scanned
// is the byte budget (pkg/proxy's scan budget), which depends only on the input
// size, never on CPU speed or load: a body at or below the budget is scanned
// whatever the machine, and a body above it is refused before any detector runs.
// A plugin that exceeds this backstop is treated as failed under its
// FailurePolicy. Go cannot kill a runaway goroutine, so the timeout stops the
// wait, not the work, and the core never observes the abandoned result.
const DefaultPluginTimeout = 30 * time.Second

// Audit metadata encoding for plugin-failure warnings. The audit seam is
// metadata-only, so a warning row carries Provider = AuditProviderPolicy,
// Method = AuditMethodPolicy, Path = the phase, Client = the tool, and
// Detectors = {"plugin_failure", <plugin id>, <reason>}.
const (
	// AuditProviderPolicy is the audit provider for core policy warnings.
	AuditProviderPolicy = "extension"
	// AuditMethodPolicy is the audit method for core policy warnings.
	AuditMethodPolicy = "policy"
)

// Failure reasons recorded in the third Detectors entry of an audit warning.
const (
	// FailureReasonError is a plugin that returned a non-nil error.
	FailureReasonError = "error"
	// FailureReasonPanic is a plugin that panicked during capability lookup or
	// inspection.
	FailureReasonPanic = "panic"
	// FailureReasonTimeout is a plugin that exceeded the policy timeout.
	FailureReasonTimeout = "timeout"
	// FailureReasonMalformed is a plugin that returned a finding the core
	// rejects (unknown action, out-of-range confidence, negative offsets, or a
	// block without CanBlock).
	FailureReasonMalformed = "malformed"
	// FailureReasonTransformPhase is a Transformer that tried to act on request
	// content or headers, which it may never receive.
	FailureReasonTransformPhase = "transform_phase"
)

// ErrNilPolicy means a Policy method was called on a nil receiver.
var ErrNilPolicy = errors.New("extension: nil policy")

// PolicyConfig configures a Policy. The zero value is valid: a no-op sink, the
// default timeout, and every plugin FailOpenWarn.
type PolicyConfig struct {
	// Sink receives plugin-failure audit warnings. A nil Sink means
	// audit.NoopSink{}, the seam default; the private Pro layer injects the
	// concrete store.
	Sink audit.AuditSink
	// Timeout bounds each plugin invocation. A value <= 0 means
	// DefaultPluginTimeout.
	Timeout time.Duration
	// Failures overrides the failure policy by plugin id. A plugin absent from
	// the map is FailOpenWarn; any value other than FailClosed is also treated
	// as FailOpenWarn. The map is copied, so later caller mutation cannot
	// change the engine.
	Failures map[string]FailurePolicy
}

// Policy is the core's content policy engine. It runs the Inspectors registered
// for a document's phase, aggregates their Findings under the fixed precedence
// Allow < Warn < Redact < Block, and returns a Decision for the caller to
// apply. The engine never rewrites content and never invokes a Transformer:
// redaction and every other content write are core-only (W4.4/W4.5).
//
// A plugin failure is never silent. A panic, a timeout, an error, or a
// malformed finding degrades per the plugin's FailurePolicy and always records
// an audit warning through the injected audit.AuditSink.
//
// A Policy is safe for concurrent use once constructed; the injected sink must
// be too.
type Policy struct {
	registry *Registry
	sink     audit.AuditSink
	timeout  time.Duration
	failures map[string]FailurePolicy
}

// NewPolicy returns a policy engine over reg. A nil reg means no inspectors and
// therefore always Allow. The returned engine is immutable.
func NewPolicy(reg *Registry, cfg PolicyConfig) *Policy {
	sink := cfg.Sink
	if sink == nil {
		sink = audit.NoopSink{}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultPluginTimeout
	}
	failures := make(map[string]FailurePolicy, len(cfg.Failures))
	maps.Copy(failures, cfg.Failures)
	return &Policy{registry: reg, sink: sink, timeout: timeout, failures: failures}
}

// Decision is the core's aggregated verdict for one document phase. Action is
// the highest-precedence Finding action; Findings holds exactly the findings
// that back Action, in deterministic plugin order. The caller applies it: Block
// rejects the request, Redact replaces the selected spans (W4.4), Warn records
// without rewriting, and Allow forwards untouched. The engine itself never
// mutates content.
type Decision struct {
	Phase    Phase
	Action   Action
	Findings []Finding
}

// Blocks reports whether the caller must reject the request.
func (d Decision) Blocks() bool { return d.Action == Block }

// Evaluate runs every Inspector registered for doc.Phase and returns the
// aggregated Decision. It returns an error only for a nil policy, a nil
// document, or a document whose phase is undefined; a failing plugin is folded
// into the Decision per its FailurePolicy and is never surfaced as an error the
// caller could mistake for "allow".
func (p *Policy) Evaluate(doc *Document) (Decision, error) {
	if p == nil {
		return Decision{}, ErrNilPolicy
	}
	if doc == nil {
		return Decision{}, ErrNilDocument
	}
	if !doc.Phase.Valid() {
		return Decision{}, fmt.Errorf("%w: document phase %q", ErrInvalidPhase, doc.Phase)
	}
	return p.evaluate(doc, p.registry.Inspectors(doc.Phase)), nil
}

// evaluate is the registry-independent core so a unit harness can drive the
// engine with an explicit inspector list (used by the security tests).
func (p *Policy) evaluate(doc *Document, inspectors []Inspector) Decision {
	decision := Decision{Phase: doc.Phase, Action: Allow}
	var all []Finding
	for _, insp := range inspectors {
		all = append(all, p.inspect(doc, insp)...)
	}
	if len(all) > 0 {
		decision.Action = aggregateAction(all)
	}
	for _, f := range all {
		if f.Action == decision.Action {
			decision.Findings = append(decision.Findings, f)
		}
	}
	return decision
}

// inspect runs one Inspector and returns its normalized findings, or the
// block-forcing finding when a FailClosed plugin fails. It guards against a
// plugin that panics in Capabilities/ID as well as one that panics in Inspect.
func (p *Policy) inspect(doc *Document, insp Inspector) (findings []Finding) {
	id := "unknown"
	defer func() {
		if r := recover(); r != nil {
			findings = p.fail(doc, id, FailureReasonPanic)
		}
	}()

	id = insp.ID()
	caps := insp.Capabilities()

	// Defense in depth: a Transformer may never receive request content or raw
	// headers, even when a dual Inspector+Transformer slips past registration
	// or a harness forces it in. Transform is never called here.
	if _, isTransformer := insp.(Transformer); isTransformer && transformerForbidden(doc.Phase) {
		return p.fail(doc, id, FailureReasonTransformPhase)
	}

	view, err := Gate(doc, caps)
	if err != nil {
		return p.fail(doc, id, FailureReasonError)
	}
	findings, reason := runInspector(insp, view, p.timeout)
	if reason != "" {
		return p.fail(doc, id, reason)
	}
	for i := range findings {
		if invalidFinding(findings[i], caps) {
			return p.fail(doc, id, FailureReasonMalformed)
		}
	}
	// The core is authoritative about provenance: a plugin cannot spoof another
	// plugin's id in its findings.
	for i := range findings {
		findings[i].PluginID = id
	}
	return findings
}

// fail records one audit warning and returns the block-forcing finding when the
// plugin's FailurePolicy is FailClosed, or nil when the request may continue.
func (p *Policy) fail(doc *Document, id, reason string) []Finding {
	p.warn(doc, id, reason)
	if p.policyFor(id) != FailClosed {
		return nil
	}
	return []Finding{{
		Type:       "plugin_failure",
		Confidence: 1,
		Action:     Block,
		PluginID:   id,
		Meta:       map[string]any{"reason": reason},
	}}
}

// warn writes one metadata-only warning row for a plugin failure. A sink error
// is deliberately ignored: an audit-write failure must not mask or block the
// policy decision, and the sink is the only channel the core has.
func (p *Policy) warn(doc *Document, pluginID, reason string) {
	if p.sink == nil {
		return
	}
	rec := audit.Record{
		TS:        time.Now().UnixMilli(),
		Provider:  AuditProviderPolicy,
		Method:    AuditMethodPolicy,
		Path:      doc.Phase.String(),
		Client:    doc.Tool,
		Detectors: []string{"plugin_failure", pluginID, reason},
	}
	_ = p.sink.Record(rec)
}

// policyFor returns the configured failure policy for a plugin id, defaulting
// to FailOpenWarn for anything that is not exactly FailClosed.
func (p *Policy) policyFor(id string) FailurePolicy {
	if p.failures[id] == FailClosed {
		return FailClosed
	}
	return FailOpenWarn
}

// aggregateAction returns the highest-precedence action among valid findings,
// or Allow when there are none.
func aggregateAction(findings []Finding) Action {
	best := Allow
	for _, f := range findings {
		if f.Action.Precedence() > best.Precedence() {
			best = f.Action
		}
	}
	return best
}

// invalidFinding reports whether a finding violates the core's contract. The
// core fails the whole plugin on any violation rather than dropping just the
// bad finding, so a plugin cannot hide a real verdict behind malformed output.
func invalidFinding(f Finding, caps Capabilities) bool {
	if f.Action.Precedence() < 0 {
		return true
	}
	if math.IsNaN(f.Confidence) || f.Confidence < 0 || f.Confidence > 1 {
		return true
	}
	if f.LeafIndex < 0 || f.Start < 0 || f.End < f.Start {
		return true
	}
	if f.Action == Block && !caps.CanBlock {
		return true
	}
	return false
}

// transformerForbidden reports whether phase carries request content or raw
// headers, which a Transformer may never receive.
func transformerForbidden(phase Phase) bool {
	return phase == RequestContent || phase == Header
}

// runInspector invokes Inspect under panic recovery and a timeout, returning a
// non-empty reason on failure. The result channel is buffered so a late or
// abandoned goroutine never blocks.
func runInspector(insp Inspector, doc *Document, timeout time.Duration) ([]Finding, string) {
	type outcome struct {
		findings []Finding
		reason   string
	}
	ch := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- outcome{reason: FailureReasonPanic}
			}
		}()
		findings, err := insp.Inspect(doc)
		if err != nil {
			ch <- outcome{reason: FailureReasonError}
			return
		}
		ch <- outcome{findings: findings}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res.findings, res.reason
	case <-timer.C:
		return nil, FailureReasonTimeout
	}
}
