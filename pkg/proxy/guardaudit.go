package proxy

import (
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
)

// Audit metadata for the C8 mutation-channel guard rows. Every refusal writes
// exactly one metadata-only row through the audit.AuditSink seam; core passes
// audit.NoopSink{} in production, so the row is a no-op there while Pro's store
// persists it. A row carries the channel class, the source identifier and the
// refusal result — never the arguments, a matched candidate or any body byte.
const (
	// auditProviderSelfProtection labels every C8 refusal row. It follows the
	// metadata-only row convention: Provider names the subsystem, Path names
	// the surface, Method names the action, Client names the source and
	// Detectors carries the channel/result/reason tags.
	auditProviderSelfProtection = "self-protection"
	// auditSurfaceBuffered is the W6.3 full-buffered response path.
	auditSurfaceBuffered = "response_buffered"
	// auditSurfaceStream is the W6.4 SSE response path.
	auditSurfaceStream = "response_stream"
	// auditSourceModel identifies a model-originated mutation attempt. The
	// control plane's allowlist mutations are human-originated and record
	// ControlAllowlistSource instead.
	auditSourceModel = "model"
	// auditChannelUnmatched tags a refusal with no matched pattern: the SSE cap
	// and undecided releases, where the guard failed closed without a class.
	auditChannelUnmatched = "none"
	// auditResultRefused is the frozen result tag of every guard refusal.
	auditResultRefused = "refused"
)

// recordGuardRefusal writes one metadata-only audit row for a tool call the C8
// guard refused. class is the matched channel class ("" when the refusal came
// from the fail-closed SSE paths), surface distinguishes the buffered from the
// streamed path and reason is one of the sseGuardReason* values. A nil
// pipeline or a nil sink (no sink wired) is a no-op, and a sink error is
// ignored: an audit failure must never change the request outcome, mirroring
// recordWarn.
func (p *Pipeline) recordGuardRefusal(class, surface, reason string) {
	if p == nil || p.sink == nil {
		return
	}
	channel := class
	if channel == "" {
		channel = auditChannelUnmatched
	}
	_ = p.sink.Record(audit.Record{
		TS:        time.Now().UnixMilli(),
		Provider:  auditProviderSelfProtection,
		Method:    RedactionActionMutationChannelBlocked,
		Path:      surface,
		Client:    auditSourceModel,
		Detectors: []string{"channel:" + channel, "result:" + auditResultRefused, "reason:" + reason},
	})
}

// noteBufferedGuardRefusal records one W6.3 interception on the full-buffered
// response path: it increments the counter /status exposes, emits the
// metadata-only reporter event and writes the audit row. The streaming path
// has its own hook (noteStreamingGuardRefusal), so the two counters never
// conflate the paths.
func (p *Pipeline) noteBufferedGuardRefusal(class string) {
	if p == nil {
		return
	}
	p.selfProtectionInterceptions.Add(1)
	p.reportMutationChannelBlock(class)
	p.recordGuardRefusal(class, auditSurfaceBuffered, sseGuardReasonMatch)
}

// SelfProtectionInterceptions reports how many tool calls the W6.3
// full-buffered response guard refused since the pipeline was built. It is
// metadata only — it counts refusals, never content — and is safe to expose
// (for example on the status endpoint). The streaming path reports separately
// through StreamGuardRefusals/StreamGuardFailClosed. A nil receiver returns 0.
func (p *Pipeline) SelfProtectionInterceptions() uint64 {
	if p == nil {
		return 0
	}
	return p.selfProtectionInterceptions.Load()
}
