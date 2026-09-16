package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// ErrNilPipeline means a Pipeline method was called on a nil receiver.
var ErrNilPipeline = errors.New("proxy: nil pipeline")

// ErrNilEngine means NewPipeline was called without a placeholder engine. The
// engine is core-owned session state; a pipeline without it could not redact
// outbound or backfill inbound data.
var ErrNilEngine = errors.New("proxy: pipeline requires a placeholder engine")

// ErrUnwalkableBody reports that the outbound request body is not a JSON
// document this build can leaf-walk (non-JSON text, invalid UTF-8, malformed
// or over-nested JSON). transformRequest returns the original body unchanged
// together with this sentinel, wrapping the walker's own error so errors.Is
// still reaches protocol.ErrMalformedJSON, protocol.ErrNestingDepth or
// protocol.ErrEncodedDepth.
//
// The sentinel is deliberately not a decision. BodyTransform receives only
// []byte and cannot see the request headers, so whether an unparseable body is
// a client error (declared JSON) or legitimate non-JSON traffic (passthrough)
// is decided by the HTTP layer in pkg/gateway/dataplane.go, the only layer
// that can read Content-Type — the same reasoning Forwarder.ServeHTTP
// documents for its Content-Encoding guard.
var ErrUnwalkableBody = errors.New("proxy: request body is not a JSON document the walker can parse")

// Audit metadata for content-policy warnings written by the pipeline.
const (
	auditProviderPipeline = "pipeline"
	auditMethodPipeline   = "pipeline"
)

// PipelineConfig assembles the W4.5 content pipeline.
type PipelineConfig struct {
	// Registry holds the compiled-in Inspectors and Transformers (W4.1). A nil
	// Registry is replaced by an empty one, so a pipeline can be built without
	// plugins (used by the redaction-disabled regression control).
	Registry *extension.Registry
	// Policy is the W4.2 decision engine over Registry. A nil Policy is built
	// from Registry with default settings.
	Policy *extension.Policy
	// Engine is the W4.4 placeholder/backfill engine. Required: it owns the
	// outbound substitution and the inbound-only restore mapping.
	Engine *redact.PlaceholderEngine
	// Sink receives a metadata-only audit row for a Warn decision. Nil means no
	// recording until W5.3 wires the real store.
	Sink audit.AuditSink
	// Tool labels the content Document (for example "claude-code").
	Tool string
	// The fields below carry the C8 self-protection seam only: NewPipeline
	// stores them for W6.1–W6.4, which own every interception, force-redaction,
	// pattern-match and SSE-guard behaviour. Every zero value is a complete
	// no-op (identical bytes on the wire as before the seam existed).
	//
	// SelfProtectionEnabled arms the C8 mutation-channel interception (W6.1+).
	SelfProtectionEnabled bool
	// SelfProtectionModes lists the enabled interception categories (W6.2+).
	SelfProtectionModes []string
	// Exclusions carries the narrow exclusion set force-redacted and never
	// restored by C8 (W6.1+). Nil is a no-op.
	Exclusions [][]byte
	// ControlToken is the session control-token value consumed by C8 (W6.1+).
	// Empty is a no-op.
	ControlToken string
}

// Pipeline composes the W4.1 registry, W4.2 policy, W4.3 detectors, W4.4
// placeholder engine and W3.4 leaf walker into the request and response paths
// (docs/architecture.md and docs/plugins.md).
//
// Outbound (client to upstream): the fully-read request body is leaf-walked,
// inspected and, on Redact, rewritten core-only to placeholders before it is
// forwarded. The rewrite never consults the reverse mapping, so a placeholder
// already present in the client body is forwarded verbatim (docs/security.md).
// Block aborts locally; upstream is never dialed.
//
// Inbound (upstream to client): a fully-buffered response is inspected,
// ResponseContent transformers run, and core backfill runs last. An SSE
// (text/event-stream) response streams through an SSE-aware backfiller that
// reassembles a placeholder split across several `data:` events: it holds a
// bounded window of decoded leaf content (sseBackfillMaxHoldbackBytes) and
// rewrites the contributing events in place, so the client sees the restored
// secret with the event count and the `data:`/blank-line framing unchanged.
//
// A Pipeline is safe for concurrent use once built: the registry and policy are
// immutable, and the engine is internally synchronised.
type Pipeline struct {
	registry *extension.Registry
	policy   *extension.Policy
	engine   *redact.PlaceholderEngine
	sink     audit.AuditSink
	tool     string

	// C8 self-protection seam copied from PipelineConfig at construction time.
	// W6.1–W6.4 consume these fields; W0.3 only carries them, and their zero
	// values are a complete no-op.
	selfProtectionEnabled bool
	selfProtectionModes   []string
	exclusions            [][]byte
	controlToken          string

	// reporter, when set, receives one masked event per replaced span and per
	// policy block. It is an atomic pointer so a reporter installed before Run
	// is read race-free by every request goroutine. See SetRedactionReporter.
	reporter atomic.Pointer[RedactionReporter]
}

// NewPipeline builds the pipeline. It fails when cfg.Engine is nil, because no
// redaction or backfill could run without it.
func NewPipeline(cfg PipelineConfig) (*Pipeline, error) {
	if cfg.Engine == nil {
		return nil, ErrNilEngine
	}
	registry := cfg.Registry
	if registry == nil {
		registry = extension.NewRegistry()
	}
	policy := cfg.Policy
	if policy == nil {
		policy = extension.NewPolicy(registry, extension.PolicyConfig{})
	}
	return &Pipeline{
		registry: registry,
		policy:   policy,
		engine:   cfg.Engine,
		sink:     cfg.Sink,
		tool:     cfg.Tool,

		selfProtectionEnabled: cfg.SelfProtectionEnabled,
		selfProtectionModes:   cfg.SelfProtectionModes,
		exclusions:            cfg.Exclusions,
		controlToken:          cfg.ControlToken,
	}, nil
}

// BlockedError reports that a content policy decision rejected the request or
// response. It is returned by the request transform (mapped to 403 by
// TransformErrorHandler) and by the response path (mapped to 403 by the
// response middleware). Findings carry the detector types and spans, never the
// matched bytes.
type BlockedError struct {
	Phase    extension.Phase
	Findings []extension.Finding
}

// Error implements the error interface without embedding content or secrets.
func (e *BlockedError) Error() string {
	return fmt.Sprintf("proxy: %s blocked by content policy", e.Phase)
}

// RequestTransform returns the BodyTransform for the W3.3 Forwarder seam. The
// forwarder reads the whole body, calls this once, and only then dispatches, so
// a redaction can never miss a tail fragment (docs/architecture.md).
func (p *Pipeline) RequestTransform() BodyTransform {
	return p.transformRequest
}

// TransformErrorHandler maps a BlockedError produced by RequestTransform to a
// 403, so a policy block is a clear client error instead of the forwarder's
// default 500. Any other transform error returns false and keeps the default
// fail-closed 500.
func (p *Pipeline) TransformErrorHandler() TransformErrorFunc {
	return func(w http.ResponseWriter, err error) bool {
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			return false
		}
		http.Error(w, "blocked by content policy", http.StatusForbidden)
		return true
	}
}

// transformRequest is the outbound path: Walk -> inspect -> policy -> redact.
//
// An empty body returns (body, nil): there is nothing to inspect.
//
// A body that is not a JSON document this build can leaf-walk (non-JSON text,
// invalid UTF-8, malformed or over-nested JSON) is returned byte-identical
// together with ErrUnwalkableBody, which wraps the walker's own error.
// This transform decides nothing about such a body and never corrupts it:
// whether it is a client error or legitimate non-JSON traffic depends on the
// request headers, which only the HTTP layer can read (BodyTransform takes
// only []byte). pkg/gateway/dataplane.go matches the sentinel with errors.Is
// and fails closed with 400 when the request declares JSON (Content-Type:
// application/json* or, absent a Content-Type, a body with JSON symptoms);
// otherwise it forwards the returned body unchanged, preserving the
// long-documented non-JSON passthrough (V1 routes known JSON API paths, and
// the resolver rejects unknown paths before they reach the pipeline).
//
// A Forwarder built with a non-nil transform (production does not do this:
// pkg/gateway/dataplane.go passes a nil transform and runs this transform at
// the HTTP layer instead) maps the sentinel through the generic
// transform-failure chain to a 500 with zero upstream bytes. That path is
// intentionally unchanged: it is already fail-closed.
func (p *Pipeline) transformRequest(body []byte) ([]byte, error) {
	if p == nil {
		return nil, ErrNilPipeline
	}
	if len(body) == 0 {
		return body, nil
	}
	walked, err := protocol.Walk(body)
	if err != nil {
		return body, fmt.Errorf("%w: %w", ErrUnwalkableBody, err)
	}
	decision, err := p.policy.Evaluate(contentDocument(extension.RequestContent, p.tool, walked))
	if err != nil {
		return nil, fmt.Errorf("proxy: evaluate request content: %w", err)
	}
	// Key-position fail-closed (W1.2) runs after the value evaluation but
	// before the value decision is applied, so a key hit can never be masked by
	// a successful value redact. Keys are never rewritten: a surviving finding
	// blocks fail-closed, otherwise the value decision below applies unchanged.
	// See keyguard.go for the frozen post-filter mechanism, the allowlist
	// interaction and the recorded pure-hex limitation.
	keyFindings, err := p.keyFindings(body)
	if err != nil {
		return nil, err
	}
	if len(keyFindings) > 0 {
		keyDecision := extension.Decision{
			Phase:    extension.RequestContent,
			Action:   extension.Block,
			Findings: keyFindings,
		}
		p.reportBlock(keyDecision)
		return nil, &BlockedError{Phase: extension.RequestContent, Findings: keyFindings}
	}
	switch decision.Action {
	case extension.Block:
		p.reportBlock(decision)
		return nil, &BlockedError{Phase: decision.Phase, Findings: decision.Findings}
	case extension.Redact:
		return p.redactBody(body, walked, decision.Findings)
	case extension.Warn:
		p.recordWarn(decision)
		return body, nil
	default:
		return body, nil
	}
}

// redactBody rewrites the detected spans of every terminal leaf to core
// placeholders and returns the rewritten document. With no usable finding the
// body is returned byte-identical.
func (p *Pipeline) redactBody(body []byte, walked []protocol.Leaf, findings []extension.Finding) ([]byte, error) {
	spans := redactionSpans(walked, findings)
	if len(spans) == 0 {
		return body, nil
	}
	p.reportSpans(walked, spans)
	rewriter := &leafRewriter{
		walked: walked,
		edit: func(terminalIdx int, _ string, content []byte) ([]byte, bool) {
			spans := spans[terminalIdx]
			if len(spans) == 0 {
				return content, false
			}
			out := p.engine.ApplyPlaceholders(content, spans)
			return out, !bytes.Equal(out, content)
		},
	}
	out, changed, err := rewriter.rewrite(body, "")
	if err != nil {
		return nil, err
	}
	if !changed {
		return body, nil
	}
	return out, nil
}

// redactionSpans groups findings into per-terminal-leaf spans. It skips
// findings that index an encoded parent or carry an invalid range, mirroring
// the walker's own guidance to scan only terminal leaves.
func redactionSpans(walked []protocol.Leaf, findings []extension.Finding) map[int][]redact.Redaction {
	terminal := terminalLeaves(walked)
	spans := make(map[int][]redact.Redaction)
	for _, f := range findings {
		if f.LeafIndex < 0 || f.LeafIndex >= len(terminal) {
			continue
		}
		if f.Start < 0 || f.Start >= f.End {
			continue
		}
		spans[f.LeafIndex] = append(spans[f.LeafIndex], redact.Redaction{
			Start: f.Start,
			End:   f.End,
			Type:  f.Type,
		})
	}
	return spans
}

// transformResponse is the inbound path for a fully-buffered response:
// inspect -> policy -> ResponseContent transformers -> core backfill last. A
// non-JSON response skips inspection and transformers but still gets backfill,
// because a placeholder can appear in a plain-text error or non-JSON body.
func (p *Pipeline) transformResponse(body []byte, tool string) ([]byte, error) {
	if p == nil {
		return nil, ErrNilPipeline
	}
	if len(body) == 0 {
		return body, nil
	}
	if walked, err := protocol.Walk(body); err == nil {
		decision, evalErr := p.policy.Evaluate(contentDocument(extension.ResponseContent, tool, walked))
		if evalErr != nil {
			return nil, fmt.Errorf("proxy: evaluate response content: %w", evalErr)
		}
		if decision.Action == extension.Block {
			return nil, &BlockedError{Phase: decision.Phase, Findings: decision.Findings}
		}
		if decision.Action == extension.Warn {
			p.recordWarn(decision)
		}
		body, err = p.applyResponseTransformers(body, walked, tool)
		if err != nil {
			return nil, err
		}
	}
	return p.backfill(body), nil
}

// applyResponseTransformers runs every ResponseContent transformer in priority
// order, chaining each on the previous document, then writes the final document
// back into the body. Transformers see the body before backfill, so their
// output cannot contain a secret that only backfill would restore.
func (p *Pipeline) applyResponseTransformers(body []byte, walked []protocol.Leaf, tool string) ([]byte, error) {
	transformers := p.registry.Transformers(extension.ResponseContent)
	if len(transformers) == 0 {
		return body, nil
	}
	doc := contentDocument(extension.ResponseContent, tool, walked)
	for _, tr := range transformers {
		view, err := extension.Gate(doc, tr.Capabilities())
		if err != nil {
			return nil, fmt.Errorf("proxy: gate response transformer %q: %w", tr.ID(), err)
		}
		out, err := runTransformer(tr, view)
		if err != nil {
			return nil, fmt.Errorf("proxy: response transformer %q: %w", tr.ID(), err)
		}
		if out != nil {
			doc = out
		}
	}
	return applyLeafContents(body, walked, doc)
}

// runTransformer invokes one Transformer under panic recovery. A panic is an
// error, never a silently skipped transform.
func runTransformer(tr extension.Transformer, doc *extension.Document) (out *extension.Document, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, errors.New("transformer panicked")
		}
	}()
	return tr.Transform(doc)
}

// applyLeafContents splices a transformer's returned leaf contents back into
// the body. Leaves are matched by ordinal first (the common, structure-
// preserving case) and by path as a fallback. A nil Content, or content equal
// to the original, leaves the raw token untouched.
func applyLeafContents(body []byte, walked []protocol.Leaf, doc *extension.Document) ([]byte, error) {
	byIndex := make(map[int][]byte, len(doc.Leaves))
	byPath := make(map[string][]byte, len(doc.Leaves))
	for i, leaf := range doc.Leaves {
		if leaf.Content == nil {
			continue
		}
		content := append([]byte(nil), leaf.Content...)
		byIndex[i] = content
		if _, ok := byPath[leaf.Path]; !ok {
			byPath[leaf.Path] = content
		}
	}
	rewriter := &leafRewriter{
		walked: walked,
		edit: func(terminalIdx int, path string, content []byte) ([]byte, bool) {
			if replacement, ok := byIndex[terminalIdx]; ok {
				return replacement, !bytes.Equal(replacement, content)
			}
			if replacement, ok := byPath[path]; ok {
				return replacement, !bytes.Equal(replacement, content)
			}
			return content, false
		},
	}
	out, _, err := rewriter.rewrite(body, "")
	if err != nil {
		return nil, err
	}
	return out, nil
}

// backfill restores this session's placeholders in a fully-buffered,
// client-bound body. It is the only inbound whole-body substitution and is
// always the last response step.
func (p *Pipeline) backfill(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	var buf bytes.Buffer
	writer := protocol.NewBackfillWriter(&buf, p.engine.MaxPlaceholderLen(), p.engine.BackfillFunc())
	if _, err := writer.Write(body); err != nil {
		return body
	}
	if err := writer.Flush(); err != nil {
		return body
	}
	return buf.Bytes()
}

// recordWarn writes one metadata-only audit row for a Warn decision. A sink
// error is ignored: an audit failure must never change the policy outcome.
func (p *Pipeline) recordWarn(decision extension.Decision) {
	if p.sink == nil || len(decision.Findings) == 0 {
		return
	}
	detectors := detectorTypes(decision.Findings)
	if len(detectors) == 0 {
		return
	}
	_ = p.sink.Record(audit.Record{
		TS:        time.Now().UnixMilli(),
		Provider:  auditProviderPipeline,
		Method:    auditMethodPipeline,
		Path:      decision.Phase.String(),
		Detectors: detectors,
		Client:    p.tool,
	})
}

// detectorTypes returns the distinct finding types in stable first-seen order.
func detectorTypes(findings []extension.Finding) []string {
	seen := make(map[string]struct{}, len(findings))
	types := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Type == "" {
			continue
		}
		if _, ok := seen[f.Type]; ok {
			continue
		}
		seen[f.Type] = struct{}{}
		types = append(types, f.Type)
	}
	return types
}

// terminalLeaves drops the double-encoded parents protocol.Walk emits, leaving
// the terminal string leaves in document order. Scanning only terminal leaves
// avoids flagging the same bytes twice and keeps finding offsets meaningful:
// a byte offset into an encoded parent's JSON syntax cannot be mapped back to
// an inner string value.
func terminalLeaves(walked []protocol.Leaf) []protocol.Leaf {
	terminal := make([]protocol.Leaf, 0, len(walked))
	for _, leaf := range walked {
		if leaf.Encoded {
			continue
		}
		terminal = append(terminal, leaf)
	}
	return terminal
}

// contentDocument builds the phase-scoped Document from the terminal leaves of
// walked. Leaf ordinals here match the LeafIndex a detector reports and the
// ordinal the rewriter edits.
func contentDocument(phase extension.Phase, tool string, walked []protocol.Leaf) *extension.Document {
	terminal := terminalLeaves(walked)
	leaves := make([]extension.Leaf, len(terminal))
	for i, leaf := range terminal {
		leaves[i] = extension.Leaf{Path: leaf.Path, Content: []byte(leaf.Content), Len: leaf.Len}
	}
	return &extension.Document{Phase: phase, Tool: tool, Leaves: leaves}
}

// ResponseMiddleware wraps next so every client-bound response gets the inbound
// path. An SSE (text/event-stream) response streams through an SSE-aware
// backfill writer that reassembles placeholders spanning several events; any
// other body is buffered, inspected and transformed, then backfilled as one
// unit. A response that a Block inspector rejects is answered with 403 before
// any body is written.
func (p *Pipeline) ResponseMiddleware(next http.Handler) http.Handler {
	if next == nil {
		next = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p == nil {
			next.ServeHTTP(w, r)
			return
		}
		writer := &pipelineResponseWriter{pipeline: p, dst: w, status: http.StatusOK}
		next.ServeHTTP(writer, r)
		writer.finish()
	})
}

// responseMode selects how a pipelineResponseWriter handles the body.
type responseMode int

const (
	// modeBuffered holds the whole body so it can be inspected, transformed and
	// backfilled before anything is written to the client. It is used for an
	// identity body and for a decodable (gzip/deflate) body, which is
	// decompressed here before any status code is committed.
	modeBuffered responseMode = iota
	// modeStreaming passes an identity-encoded SSE body through an SSE-aware
	// backfiller that reassembles a placeholder split across several events.
	modeStreaming
	// modeDiscard drops every upstream byte after a fail-closed decision. The
	// error status has already been committed, so nothing else may be sent.
	modeDiscard
)

// pipelineResponseWriter buffers a non-streaming response so the pipeline can
// process it before the client sees a byte, and streams an identity SSE
// response through an SSE-aware backfiller. A content-encoded response is
// never passed through uninspected: a decodable body is buffered and
// decompressed before commit, and an unsupported body is answered 502 with the
// upstream bytes discarded.
type pipelineResponseWriter struct {
	pipeline *Pipeline
	dst      http.ResponseWriter
	header   http.Header
	status   int
	buf      bytes.Buffer
	backfill *sseBackfiller
	mode     responseMode
	decided  bool
	// encodings holds the ordered, lower-cased Content-Encoding tokens of a
	// decodable response (for example ["deflate"], or ["gzip","deflate"] for a
	// doubly-encoded body). It is empty for an identity body.
	encodings []string
}

// Header implements http.ResponseWriter; it returns the real header map so the
// forwarder's header copy lands where the server reads it.
func (w *pipelineResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = w.dst.Header()
	}
	return w.header
}

// WriteHeader implements http.ResponseWriter. The decision is driven by the
// Content-Encoding state:
//
//   - identity — buffered, or streamed when the Content-Type is SSE.
//   - decodable — buffered; the body is decompressed in finishBuffered before
//     any status code is committed, so a decode failure can still become a 502.
//     WriteHeader only records the status here.
//   - decodable + text/event-stream — fail closed (decision D5: the pipeline
//     does not implement streaming decompression).
//   - unsupported — fail closed immediately; the upstream body is discarded.
//
// Reachability: after the outbound Accept-Encoding strip, the Go transport
// transparently decompresses a gzip response and removes its Content-Encoding,
// so the decodable branch is reached mainly for `deflate` or a custom
// WithHTTPClient. It is kept as defence and is never assumed unreachable.
func (w *pipelineResponseWriter) WriteHeader(status int) {
	if w.decided {
		return
	}
	w.decided = true
	w.status = status
	switch classifyContentEncoding(w.Header()) {
	case encodingUnsupported:
		w.failClosed()
	case encodingDecodable:
		if isEventStream(w.Header().Get("Content-Type")) {
			w.failClosed()
			return
		}
		w.mode = modeBuffered
		w.encodings = contentEncodingTokens(w.Header())
	default:
		if isEventStream(w.Header().Get("Content-Type")) {
			w.mode = modeStreaming
			w.Header().Del("Content-Length")
			w.dst.WriteHeader(status)
			w.backfill = newSSEBackfiller(w.dst, w.pipeline.engine.MaxPlaceholderLen(), w.pipeline.engine.BackfillFunc())
		} else {
			w.mode = modeBuffered
		}
	}
}

// Write implements http.ResponseWriter.
func (w *pipelineResponseWriter) Write(p []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	switch w.mode {
	case modeStreaming:
		return w.backfill.Write(p)
	case modeDiscard:
		// The fail-closed status is already committed; drop the bytes but
		// report them consumed so the upstream copy terminates normally.
		return len(p), nil
	default:
		return w.buf.Write(p)
	}
}

// Flush implements http.Flusher for streaming bodies so SSE frames are
// delivered immediately. A buffered body cannot be flushed early: the
// transform needs the complete body, and flushing would commit the status
// before the pipeline has inspected it. A discarded body has nothing to flush.
func (w *pipelineResponseWriter) Flush() {
	if w.mode != modeStreaming {
		return
	}
	if flusher, ok := w.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

// finish completes the response after next returns: flush the streaming
// backfill writer, transform and write the buffered body, or do nothing for a
// discarded body whose error status is already committed.
func (w *pipelineResponseWriter) finish() {
	switch w.mode {
	case modeStreaming:
		// Exactly one Flush ends the stream (it also closes the decoder and
		// drains held events). A sticky write error was already returned by
		// Write to the body copier, and the status is committed by now, so
		// there is no second channel to re-raise it on.
		if w.backfill != nil {
			_ = w.backfill.Flush()
		}
	case modeDiscard:
		return
	default:
		w.finishBuffered()
	}
}

// finishBuffered runs the inbound pipeline over the buffered body and writes
// the header, status and transformed body. A decodable body is decompressed
// first, before any status code is committed, so a decode failure can still
// become a 502. A Block becomes 403 and any other failure becomes 502; neither
// leaks body content, and every error path drops Content-Encoding.
func (w *pipelineResponseWriter) finishBuffered() {
	if !w.decided {
		w.decided = true
		w.status = http.StatusOK
	}
	if w.mode == modeDiscard {
		return
	}
	body := w.buf.Bytes()
	if len(w.encodings) > 0 {
		decoded, err := decodeContentEncoding(body, w.encodings)
		if err != nil {
			w.writeError(err)
			return
		}
		body = decoded
	}
	body, err := w.pipeline.transformResponse(body, w.pipeline.tool)
	if err != nil {
		w.writeError(err)
		return
	}
	w.Header().Del("Content-Length")
	w.Header().Del("Transfer-Encoding")
	w.Header().Del("Content-Encoding")
	w.dst.WriteHeader(w.status)
	_, _ = w.dst.Write(body)
}

// failClosed commits a 502 and switches to modeDiscard so no upstream byte
// reaches the client. It is used for an unsupported Content-Encoding and for a
// decodable encoding on an SSE response (decision D5). Content-Encoding is
// removed so the client never sees an encoding claim that no longer matches
// the body.
func (w *pipelineResponseWriter) failClosed() {
	w.mode = modeDiscard
	w.Header().Del("Content-Length")
	w.Header().Del("Transfer-Encoding")
	w.Header().Del("Content-Encoding")
	http.Error(w.dst, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
}

// writeError answers a buffered response failure before any body byte is sent.
func (w *pipelineResponseWriter) writeError(err error) {
	w.Header().Del("Content-Length")
	w.Header().Del("Transfer-Encoding")
	w.Header().Del("Content-Encoding")
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		http.Error(w.dst, "blocked by content policy", http.StatusForbidden)
		return
	}
	http.Error(w.dst, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
}

// isEventStream reports whether a Content-Type designates an SSE stream, whose
// body must be backfilled incrementally rather than buffered.
func isEventStream(contentType string) bool {
	mediaType := strings.TrimSpace(contentType)
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), "text/event-stream")
}

// contentEncoding classifies a message's Content-Encoding into the three
// states the pipeline handles: identity, decodable, or unsupported.
type contentEncoding int

const (
	// encodingIdentity means the body is uncompressed: no Content-Encoding, or
	// only `identity` tokens (any case).
	encodingIdentity contentEncoding = iota
	// encodingDecodable means every coding is `gzip` or `deflate`, so the core
	// can decompress the body and inspect it.
	encodingDecodable
	// encodingUnsupported means at least one coding (for example `br` or
	// `zstd`) cannot be decoded, so the body must fail closed.
	encodingUnsupported
)

// classifyContentEncoding classifies all Content-Encoding header lines. It
// iterates header.Values (not Header.Get, which returns only the first line)
// and splits each line on commas, so `Content-Encoding: gzip, br` and a second
// header line are both seen. Empty/whitespace lines are ignored.
func classifyContentEncoding(header http.Header) contentEncoding {
	tokens := contentEncodingTokens(header)
	if len(tokens) == 0 {
		return encodingIdentity
	}
	allIdentity := true
	allDecodable := true
	for _, token := range tokens {
		if token != "identity" {
			allIdentity = false
		}
		if token != "gzip" && token != "deflate" {
			allDecodable = false
		}
	}
	switch {
	case allIdentity:
		return encodingIdentity
	case allDecodable:
		return encodingDecodable
	default:
		return encodingUnsupported
	}
}

// contentEncodingTokens returns the lower-cased, comma-split codings from every
// Content-Encoding header line, in order, with empty parts dropped.
func contentEncodingTokens(header http.Header) []string {
	values := header.Values("Content-Encoding")
	tokens := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if token := strings.ToLower(strings.TrimSpace(part)); token != "" {
				tokens = append(tokens, token)
			}
		}
	}
	return tokens
}

// decodeContentEncoding decompresses body according to tokens, which are the
// Content-Encoding codings in the order they were applied. Decoding therefore
// walks them in reverse: the last coding applied is the first removed. Every
// token must be gzip or deflate (enforced by classifyContentEncoding).
func decodeContentEncoding(body []byte, tokens []string) ([]byte, error) {
	decoded := body
	for i := len(tokens) - 1; i >= 0; i-- {
		out, err := decodeOneEncoding(decoded, tokens[i])
		if err != nil {
			return nil, err
		}
		decoded = out
	}
	return decoded, nil
}

// decodeOneEncoding decodes a single gzip or deflate layer. `deflate` is
// first tried as a zlib stream (RFC 1950, what Go's compress/zlib writes) and
// then as raw DEFLATE (RFC 1951), because both framings are seen in the wild.
func decodeOneEncoding(body []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("proxy: gzip decode: %w", err)
		}
		defer func() { _ = zr.Close() }()
		return io.ReadAll(zr)
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			out, readErr := io.ReadAll(zr)
			_ = zr.Close()
			if readErr == nil {
				return out, nil
			}
		}
		fr := flate.NewReader(bytes.NewReader(body))
		defer func() { _ = fr.Close() }()
		return io.ReadAll(fr)
	default:
		return nil, fmt.Errorf("proxy: unsupported content encoding %q", encoding)
	}
}
