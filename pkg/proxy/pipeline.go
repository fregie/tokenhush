package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
}

// Pipeline composes the W4.1 registry, W4.2 policy, W4.3 detectors, W4.4
// placeholder engine and W3.4 leaf walker into the request and response paths
// (docs/13 §4/§5).
//
// Outbound (client to upstream): the fully-read request body is leaf-walked,
// inspected and, on Redact, rewritten core-only to placeholders before it is
// forwarded. The rewrite never consults the reverse mapping, so a placeholder
// already present in the client body is forwarded verbatim (docs/13 §9.1).
// Block aborts locally; upstream is never dialed.
//
// Inbound (upstream to client): a fully-buffered response is inspected,
// ResponseContent transformers run, and core backfill runs last. An SSE
// (text/event-stream) response streams through a protocol.BackfillWriter so a
// placeholder split across chunks is restored without buffering the stream.
//
// A Pipeline is safe for concurrent use once built: the registry and policy are
// immutable, and the engine is internally synchronised.
type Pipeline struct {
	registry *extension.Registry
	policy   *extension.Policy
	engine   *redact.PlaceholderEngine
	sink     audit.AuditSink
	tool     string
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
// a redaction can never miss a tail fragment (docs/13 §4.1).
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
// A body that is not a JSON document this build can leaf-walk (empty, non-JSON,
// invalid UTF-8, malformed or over-nested) is forwarded unchanged. V1 routes
// only known JSON API paths, and the resolver rejects unknown paths before they
// reach the pipeline; passing non-JSON through keeps legitimate non-JSON
// traffic working instead of breaking it. The limitation is recorded in the
// W4.5 learnings.
func (p *Pipeline) transformRequest(body []byte) ([]byte, error) {
	if p == nil {
		return nil, ErrNilPipeline
	}
	if len(body) == 0 {
		return body, nil
	}
	walked, err := protocol.Walk(body)
	if err != nil {
		return body, nil
	}
	decision, err := p.policy.Evaluate(contentDocument(extension.RequestContent, p.tool, walked))
	if err != nil {
		return nil, fmt.Errorf("proxy: evaluate request content: %w", err)
	}
	switch decision.Action {
	case extension.Block:
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
// path. An SSE (text/event-stream) response streams through an incremental
// backfill writer; any other body is buffered, inspected and transformed, then
// backfilled as one unit. A response that a Block inspector rejects is answered
// with 403 before any body is written.
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
	// backfilled before anything is written to the client.
	modeBuffered responseMode = iota
	// modeStreaming passes an SSE body through an incremental backfill writer.
	modeStreaming
	// modeOpaque passes a content-encoded body through unchanged, because
	// scanning or rewriting compressed bytes would corrupt them.
	modeOpaque
)

// pipelineResponseWriter buffers a non-streaming response so the pipeline can
// process it before the client sees a byte, and streams an SSE response through
// a protocol.BackfillWriter.
type pipelineResponseWriter struct {
	pipeline *Pipeline
	dst      http.ResponseWriter
	header   http.Header
	status   int
	buf      bytes.Buffer
	backfill *protocol.BackfillWriter
	mode     responseMode
	decided  bool
}

// Header implements http.ResponseWriter; it returns the real header map so the
// forwarder's header copy lands where the server reads it.
func (w *pipelineResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = w.dst.Header()
	}
	return w.header
}

// WriteHeader implements http.ResponseWriter. For a buffered body it only
// records the status; the header and status are written by finish after the
// body is transformed. An SSE body and an opaque body commit immediately.
func (w *pipelineResponseWriter) WriteHeader(status int) {
	if w.decided {
		return
	}
	w.decided = true
	w.status = status
	switch {
	case !identityContentEncoding(w.Header()):
		w.mode = modeOpaque
		w.dst.WriteHeader(status)
	case isEventStream(w.Header().Get("Content-Type")):
		w.mode = modeStreaming
		w.Header().Del("Content-Length")
		w.dst.WriteHeader(status)
		w.backfill = protocol.NewBackfillWriter(w.dst, w.pipeline.engine.MaxPlaceholderLen(), w.pipeline.engine.BackfillFunc())
	default:
		w.mode = modeBuffered
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
	case modeOpaque:
		return w.dst.Write(p)
	default:
		return w.buf.Write(p)
	}
}

// Flush implements http.Flusher for streaming bodies so SSE frames are
// delivered immediately. A buffered body cannot be flushed early: the
// transform needs the complete body, and flushing would commit the status
// before the pipeline has inspected it.
func (w *pipelineResponseWriter) Flush() {
	if w.mode != modeStreaming && w.mode != modeOpaque {
		return
	}
	if flusher, ok := w.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

// finish completes the response after next returns: flush the streaming
// backfill writer, or transform and write the buffered body. It is a no-op for
// an opaque body.
func (w *pipelineResponseWriter) finish() {
	switch w.mode {
	case modeStreaming:
		if w.backfill != nil {
			_ = w.backfill.Flush()
		}
	case modeOpaque:
		return
	default:
		w.finishBuffered()
	}
}

// finishBuffered runs the inbound pipeline over the buffered body and writes
// the header, status and transformed body. A Block becomes 403 and any other
// failure becomes 502; neither leaks body content.
func (w *pipelineResponseWriter) finishBuffered() {
	if !w.decided {
		w.decided = true
		w.status = http.StatusOK
	}
	body, err := w.pipeline.transformResponse(w.buf.Bytes(), w.pipeline.tool)
	if err != nil {
		w.writeError(err)
		return
	}
	w.Header().Del("Content-Length")
	w.Header().Del("Transfer-Encoding")
	w.dst.WriteHeader(w.status)
	_, _ = w.dst.Write(body)
}

// writeError answers a buffered response failure before any body byte is sent.
func (w *pipelineResponseWriter) writeError(err error) {
	w.Header().Del("Content-Length")
	w.Header().Del("Transfer-Encoding")
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

// identityContentEncoding reports whether a response body is uncompressed.
// Any other encoding is opaque: the pipeline must not scan or rewrite
// compressed bytes.
func identityContentEncoding(header http.Header) bool {
	encoding := strings.TrimSpace(header.Get("Content-Encoding"))
	return encoding == "" || strings.EqualFold(encoding, "identity")
}
