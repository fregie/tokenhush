// Package cli assembles the tokenhush command line: it is the only place that
// wires pkg/proxy, pkg/filter, pkg/redact and pkg/supply into a running
// product. cli.go holds the dispatcher, the content-policy glue that turns
// rule decisions into proxy verdicts, and the client-bound response writer;
// the run command and the HTTP surface live in run.go.
package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/supply"
)

// Frozen exit codes: scripts observe them, so they never change. A success is
// 0, a failed check or operation is 1, and a usage error (an unknown command
// or tool, a bad flag value) is 2.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// logLevels is the closed set of accepted log levels, mirroring the config
// schema.
var logLevels = []string{"debug", "info", "warn", "error"}

// command is one CLI verb: it receives its own arguments and the two streams
// and returns the process exit code.
type command func(args []string, stdout, stderr io.Writer) int

// commands is the command registry. Every command file registers itself from
// its init, so adding a command never edits the dispatcher.
var commands = map[string]command{}

// register installs one command under its verb.
func register(name string, run command) { commands[name] = run }

// Main dispatches the process arguments and returns the exit code.
func Main(args []string) int { return dispatch(args, os.Stdout, os.Stderr) }

// dispatch runs one command. An unknown command, or no command at all, is a
// usage error listing the registered commands in sorted order, so the help
// text can never advertise a command that does not exist.
func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		if run, ok := commands[args[0]]; ok {
			return run(args[1:], stdout, stderr)
		}
		fmt.Fprintf(stderr, "tokenhush: unknown command %q\n", args[0])
	}
	fmt.Fprintf(stderr, "usage: tokenhush <%s>\n", strings.Join(slices.Sorted(maps.Keys(commands)), "|"))
	return exitUsage
}

// errBlocked is the transform error for a request-scoped Block. It is never
// client-visible: the data plane answers 403 before the body reaches the
// forwarder, so this only fires if a transform is invoked outside the plane.
var errBlocked = fmt.Errorf("cli: request blocked by content policy")

// EvaluateRequest implements proxy.RequestEvaluator: the request-phase policy
// verdict. A rule failure is a labelled detector failure, so the data plane
// refuses it with plugin_failure; a Block names the rule ids.
func (g *gateway) EvaluateRequest(_ context.Context, leaves []protocol.Leaf) (proxy.RequestDecision, error) {
	decision, err := g.policy.Decide(leaves, filter.ScopeRequest)
	if err != nil {
		return proxy.RequestDecision{}, err
	}
	if decision.Refusal != nil {
		return proxy.RequestDecision{}, &proxy.DetectorFailure{RuleID: decision.Refusal.RuleID, Reason: proxy.FailureReason(decision.Refusal.Reason)}
	}
	if decision.Action == filter.ActionBlock {
		return proxy.RequestDecision{Action: proxy.RequestBlock, RuleIDs: ruleIDs(decision.Findings)}, nil
	}
	return proxy.RequestDecision{Action: proxy.RequestAllow}, nil
}

// EvaluateResponse implements proxy.Evaluator: the response-phase policy
// verdict. A body that cannot be walked is an error, which the response paths
// treat as the documented walk skip; a rule failure fails closed as a block,
// and the direction contract admits exactly allow, warn and block here.
func (g *gateway) EvaluateResponse(_ context.Context, body []byte) (proxy.ResponseDecision, error) {
	leaves, err := protocol.Walk(body)
	if err != nil {
		return proxy.ResponseDecision{}, err
	}
	decision, err := g.policy.Decide(leaves, filter.ScopeResponse)
	if err != nil {
		return proxy.ResponseDecision{}, err
	}
	if decision.Refusal != nil {
		return proxy.ResponseDecision{Action: proxy.ResponseBlock, RuleIDs: []string{decision.Refusal.RuleID}}, nil
	}
	if decision.Action == filter.ActionAllow {
		return proxy.ResponseDecision{Action: proxy.ResponseAllow}, nil
	}
	ids := ruleIDs(decision.Findings)
	action := proxy.ResponseWarn
	if decision.Action != filter.ActionWarn {
		action = proxy.ResponseBlock
	}
	return proxy.ResponseDecision{Action: action, RuleIDs: ids}, nil
}

// ruleIDs extracts the rule ids of a decision's backing findings.
func ruleIDs(findings []filter.AttributedFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}

// redactRequest is the outbound substitution seam: it walks the request body,
// takes the request-phase decision and rewrites every redact span to this
// session's placeholder. A body the walker cannot read is returned unchanged,
// because the data plane has already refused a declared-JSON body that fails
// to walk; here it can only be legitimate non-JSON traffic. Each substitution
// is logged masked (stderr only) and recorded in the session backfiller, the
// only place the reverse mapping exists.
func (g *gateway) redactRequest(body []byte) ([]byte, error) {
	leaves, err := protocol.Walk(body)
	if err != nil {
		return body, nil
	}
	decision, err := g.policy.Decide(leaves, filter.ScopeRequest)
	if err != nil {
		return nil, err
	}
	if decision.Refusal != nil || decision.Action == filter.ActionBlock {
		// Never client-visible: the data plane answers 403 before the body
		// reaches the forwarder, so this only fires outside the plane.
		return nil, fmt.Errorf("cli: request blocked by content policy")
	}
	if decision.Action != filter.ActionRedact {
		return body, nil
	}
	out := body
	for _, substitution := range decision.Substitutions {
		if substitution.LeafIndex < 0 || substitution.LeafIndex >= len(leaves) {
			continue
		}
		value := leaves[substitution.LeafIndex].Value
		if substitution.Start < 0 || substitution.Start >= substitution.End || substitution.End > len(value) {
			continue
		}
		secret := value[substitution.Start:substitution.End]
		placeholder, err := g.backfiller.Mint(g.writer, secret, substitution.Category)
		if err != nil {
			return nil, err
		}
		out = bytes.ReplaceAll(out, secret, []byte(placeholder))
		if g.logRedactions && g.stderr != nil {
			fmt.Fprintf(g.stderr, "tokenhush: redacted request %s (len=%d) %s\n", substitution.Category, len(secret), maskSecret(string(secret), substitution.Category))
		}
	}
	return out, nil
}

// Masking policy of the redaction log: an opaque credential type reveals a
// bounded prefix and suffix, every other type reveals nothing, and the result
// can never equal the secret. A literal value equal to the no-reveal form
// becomes the distinct fallback.
var maskEdgeTypes = map[string]bool{"api_key": true, "high_entropy": true}

// maskSecret returns the masked, human-readable form of one redacted value for
// the frozen redaction-log format. It works on runes, so a multi-byte value is
// never split mid-character.
func maskSecret(value, kind string) string {
	if runes := []rune(value); maskEdgeTypes[kind] && len(runes) >= 16 && len(runes)-6 >= 8 {
		return string(runes[:4]) + "…" + string(runes[len(runes)-2:])
	}
	if value == "****" {
		return "[redacted]"
	}
	return "****"
}

// responseWriter intercepts the forwarder's client-bound response so the
// buffered and SSE response paths inspect it before the client sees a byte.
// An identity-encoded event stream is streamed through the SSE handler (a nil
// sse means buffered); everything else is buffered and handed to the response
// handler, which decodes the body before any status is committed (invariants 7
// and 8).
type responseWriter struct {
	dst    http.ResponseWriter
	gate   *gateway
	req    *http.Request
	sse    *proxy.SSEHandler
	buf    bytes.Buffer
	status int
	sent   bool
}

// Header implements http.ResponseWriter.
func (w *responseWriter) Header() http.Header { return w.dst.Header() }

// WriteHeader implements http.ResponseWriter. A buffered status is recorded,
// never committed, so decoding can still fail closed with a 502; a stream is
// committed here because the SSE framing must flow.
func (w *responseWriter) WriteHeader(status int) {
	if w.sent {
		return
	}
	w.sent, w.status = true, status
	if !streamingSSE(w.Header()) {
		return
	}
	w.Header().Del("Content-Length")
	w.dst.WriteHeader(status)
	w.sse = proxy.NewSSEHandler(proxy.SSEResponseConfig{
		Context: w.req.Context(), Evaluator: w.gate, Backfiller: w.gate.backfiller, Counters: w.gate.counters, Warnings: w.gate,
	})
}

// Write implements http.ResponseWriter: a buffered body accumulates; a stream
// is backfilled and written through, flushed per chunk so SSE events arrive
// without waiting for the write buffer to fill.
func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.sent {
		w.WriteHeader(http.StatusOK)
	}
	if w.sse == nil {
		return w.buf.Write(p)
	}
	out, err := w.sse.Write(p)
	if err != nil {
		return 0, err
	}
	if _, err := w.dst.Write(out); err != nil {
		return 0, err
	}
	w.flush()
	return len(p), nil
}

// flush forwards a flush to the client when the writer supports it, so SSE
// events arrive without waiting for the write buffer to fill.
func (w *responseWriter) flush() {
	if flusher, ok := w.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

// finish completes the response after the forwarder returns: flush the SSE
// stream, or run the buffered response path and commit its verdict. A 415 is
// generated locally before any upstream byte is read, so it is a transport
// refusal and must not move a content counter.
func (w *responseWriter) finish() {
	if w.sse != nil {
		if out, err := w.sse.Flush(); err == nil && len(out) > 0 {
			_, _ = w.dst.Write(out)
			w.flush()
		}
		return
	}
	if !w.sent {
		w.sent, w.status = true, http.StatusOK
	}
	status, header, body := w.status, w.Header(), w.buf.Bytes()
	if status != http.StatusUnsupportedMediaType {
		processed, processedHeader, processedBody, err := w.gate.responses.Handle(&http.Response{
			StatusCode: status, Header: header.Clone(), Body: io.NopCloser(&w.buf), Request: w.req,
		})
		if err != nil {
			http.Error(w.dst, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		status, header, body = processed, processedHeader, processedBody
	}
	dst := w.dst.Header()
	clear(dst)
	for key, values := range header {
		dst[key] = values
	}
	w.dst.WriteHeader(status)
	_, _ = w.dst.Write(body)
}

// streamingSSE reports whether a response is an identity-encoded
// text/event-stream: the one body the client-bound writer streams instead of
// buffering. Any other encoding is buffered and decoded by the response path.
func streamingSSE(header http.Header) bool {
	media := strings.TrimSpace(strings.SplitN(header.Get("Content-Type"), ";", 2)[0])
	return strings.EqualFold(media, "text/event-stream") && !slices.ContainsFunc(header.Values("Content-Encoding"), func(value string) bool {
		return !strings.EqualFold(strings.TrimSpace(value), "identity")
	})
}

// Warn implements proxy.WarningWriter: the proxy's metadata-only response
// warning lines go to stderr and nowhere else.
func (g *gateway) Warn(line string) {
	if g.stderr != nil {
		fmt.Fprintln(g.stderr, line)
	}
}

// selectBuiltins maps the operator's detector switches onto the frozen
// built-in rule table, preserving the table's order.
func selectBuiltins(detectors config.Detectors) []filter.Rule {
	enabled := map[string]bool{
		filter.DetectorPrefix: detectors.Prefix, filter.DetectorEmail: detectors.Email, filter.DetectorLuhn: detectors.Luhn,
		filter.DetectorJWT: detectors.JWT, filter.DetectorPrivateKey: detectors.PEM, filter.DetectorHighEntropy: detectors.Entropy,
	}
	rules := make([]filter.Rule, 0, len(enabled))
	for _, rule := range filter.BuiltinDetectors() {
		if enabled[rule.ID()] {
			rules = append(rules, rule)
		}
	}
	return rules
}

// loadCachedPack activates the verified pack the rules cache holds. A missing
// cache is normal (the built-ins stay active); a corrupt one is reported and
// the built-ins stay, because a cache read failure must never block startup.
// Every warning the activation carries (for example the OD-2 command-rule
// warning) is written to stderr, so it is never silently dropped.
func loadCachedPack(registry *filter.Registry, dataDir string, stderr io.Writer) error {
	sync, err := supply.NewRulesSync(supply.RulesSyncConfig{
		DataDir: dataDir, Verifier: supply.NewStaticVerifier(),
		Fetcher: supply.NewBoundedHTTPFetcher(30*time.Second, supply.MaxRulesDocBytes),
	})
	if err != nil {
		return err
	}
	if err := sync.Startup(); err != nil {
		fmt.Fprintf(stderr, "tokenhush: rules cache: %v (using the built-in detectors)\n", err)
		return nil
	}
	state := sync.Active()
	for _, warning := range state.Warnings {
		fmt.Fprintf(stderr, "tokenhush: %s\n", warning)
	}
	if state.Pack == nil {
		return nil
	}
	return registry.RegisterCompiled(state.Pack)
}
