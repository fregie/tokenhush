package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// w45Secret assembles a synthetic, obviously fake credential at runtime. The
// fragments are concatenated so no contiguous key-shaped literal is committed;
// the assembled value still matches the built-in `sk-` prefix detector.
const (
	w45SecretHead = "sk"
	w45SecretA    = "A1b2C3d4"
	w45SecretB    = "E5f6G7h8"
	w45SecretC    = "I9j0K1l2"
)

// w45Secret returns the runtime-assembled fake credential.
func w45Secret() string {
	return w45SecretHead + "-" + "proj" + "-" + w45SecretA + w45SecretB + w45SecretC
}

// w45PlaceholderRe matches a complete placeholder token. The grammar is fixed
// by pkg/redact.
var w45PlaceholderRe = regexp.MustCompile(`__PII_[a-z][a-z0-9_]*_[0-9a-f]{8,}__`)

// w45Engine builds a fresh placeholder engine for one test session.
func w45Engine(t *testing.T) *redact.PlaceholderEngine {
	t.Helper()
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		t.Fatalf("NewPlaceholderEngine: %v", err)
	}
	return engine
}

// w45Registry registers the given plugins, failing the test on rejection.
func w45Registry(t *testing.T, plugins ...extension.Plugin) *extension.Registry {
	t.Helper()
	reg := extension.NewRegistry()
	for _, p := range plugins {
		if err := reg.Register(p); err != nil {
			t.Fatalf("Register(%T): %v", p, err)
		}
	}
	return reg
}

// w45Pipeline builds a pipeline from the config, failing the test on error.
func w45Pipeline(t *testing.T, cfg PipelineConfig) *Pipeline {
	t.Helper()
	pipe, err := NewPipeline(cfg)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	return pipe
}

// w45Forwarder builds the W3.3 forwarder wired to the pipeline's request
// transform and block responder, exactly as `run` will assemble it.
func w45Forwarder(t *testing.T, upstream string, pipe *Pipeline, opts ...ForwardOption) *Forwarder {
	t.Helper()
	opts = append([]ForwardOption{WithTransformErrorHandler(pipe.TransformErrorHandler())}, opts...)
	fwd, err := NewForwarder(upstream, pipe.RequestTransform(), opts...)
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	return fwd
}

// w45EchoUpstream is a fake provider that records the request body it received
// and echoes the first placeholder it saw back in a small JSON response, so a
// client round-trip proves inbound backfill.
type w45EchoUpstream struct {
	mu   sync.Mutex
	body []byte
	hits atomic.Int64
}

func (u *w45EchoUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.body = body
	u.mu.Unlock()

	placeholders := w45PlaceholderRe.FindAll(body, -1)
	echo := ""
	if len(placeholders) > 0 {
		echo = string(placeholders[0])
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"echo":%q,"nested":{"x":%q}}`, echo, echo)
}

func (u *w45EchoUpstream) received() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]byte(nil), u.body...)
}

// w45RequestBody builds a request whose secret appears in a top-level string, a
// deeply nested string and a double-encoded JSON string.
func w45RequestBody(secret string) []byte {
	inner, err := json.Marshal(map[string]any{"args": map[string]any{"api_key": secret}})
	if err != nil {
		panic(err) // marshalling fixed maps cannot fail
	}
	body, err := json.Marshal(map[string]any{
		"model":     "claude-test",
		"input":     "please use " + secret,
		"meta":      map[string]any{"deep": map[string]any{"value": secret}},
		"tool_call": string(inner),
	})
	if err != nil {
		panic(err)
	}
	return body
}

// TestPipelineE2E is the W4.5 acceptance test: a request secret is replaced by
// a placeholder upstream, the upstream echo is restored to the client, and a
// nested/double-encoded leaf is handled.
func TestPipelineE2E(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	reg := w45Registry(t, redact.NewPrefixDetector(), redact.NewHighEntropyDetector())
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine, Tool: "w4.5-e2e"})

	upstream := &w45EchoUpstream{}
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstreamServer.URL, pipe)))
	t.Cleanup(srv.Close)

	body := w45RequestBody(secret)
	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	clientBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %q", resp.StatusCode, clientBody)
	}

	sent := upstream.received()

	// (1) The upstream received a placeholder, never the secret.
	if bytes.Contains(sent, []byte(secret)) {
		t.Fatalf("upstream received the raw secret: %s", sent)
	}
	placeholders := w45PlaceholderRe.FindAll(sent, -1)
	if len(placeholders) == 0 {
		t.Fatalf("upstream received no placeholder: %s", sent)
	}

	// Exact upstream bytes (guards against misleading success output): the
	// top-level input leaf must be exactly the placeholder substituted in.
	var sentObj struct {
		Input    string `json:"input"`
		ToolCall string `json:"tool_call"`
	}
	if err := json.Unmarshal(sent, &sentObj); err != nil {
		t.Fatalf("decode upstream body: %v\n%s", err, sent)
	}
	if want := "please use " + string(placeholders[0]); sentObj.Input != want {
		t.Errorf("upstream input = %q, want %q", sentObj.Input, want)
	}

	// (2) The client received the original secret after inbound backfill.
	if !bytes.Contains(clientBody, []byte(secret)) {
		t.Errorf("client response lost the secret after backfill: %s", clientBody)
	}
	if bytes.Contains(clientBody, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("client response still contains a placeholder: %s", clientBody)
	}

	// (3) The double-encoded leaf was rewritten: decoding tool_call yields JSON
	// whose inner value is a placeholder, not the secret.
	if !strings.Contains(sentObj.ToolCall, protocol.PlaceholderPrefix) {
		t.Errorf("double-encoded leaf carries no placeholder: %q", sentObj.ToolCall)
	}
	if strings.Contains(sentObj.ToolCall, secret) {
		t.Errorf("double-encoded leaf still carries the secret: %q", sentObj.ToolCall)
	}

	t.Logf("upstream body: %s", sent)
	t.Logf("client body:   %s", clientBody)
}

// w45BlockInspector is a synthetic critical Inspector that blocks request
// content. It never reads content, so it only needs CanBlock.
type w45BlockInspector struct{}

func (w45BlockInspector) ID() string { return "w45-blocker" }

func (w45BlockInspector) Capabilities() extension.Capabilities {
	return extension.Capabilities{Phases: []extension.Phase{extension.RequestContent}, CanBlock: true}
}

func (w45BlockInspector) Inspect(*extension.Document) ([]extension.Finding, error) {
	return []extension.Finding{{
		LeafIndex: 0, Start: 0, End: 1, Type: "blocked",
		Confidence: 1, Action: extension.Block, PluginID: "w45-blocker",
	}}, nil
}

// TestPipelineBlockRejectsWithoutForwarding proves a Block inspector answers a
// clear client error and the upstream is never dialed.
func TestPipelineBlockRejectsWithoutForwarding(t *testing.T) {
	engine := w45Engine(t)
	reg := w45Registry(t, w45BlockInspector{})
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine, Tool: "w4.5-block"})

	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"input":"anything"}`))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body %q", resp.StatusCode, body)
	}
	if hits.Load() != 0 {
		t.Errorf("upstream was dialed %d time(s) after a Block", hits.Load())
	}
}

// w45RecordingTransformer records every leaf it is shown and returns the
// document unchanged, so a test can prove the transformer ran before backfill.
type w45RecordingTransformer struct {
	mu   sync.Mutex
	seen [][]byte
}

func (t *w45RecordingTransformer) ID() string { return "w45-recorder" }

func (t *w45RecordingTransformer) Capabilities() extension.Capabilities {
	return extension.Capabilities{
		Phases:       []extension.Phase{extension.ResponseContent},
		ReadContent:  true,
		CanTransform: true,
	}
}

func (t *w45RecordingTransformer) Transform(doc *extension.Document) (*extension.Document, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, leaf := range doc.Leaves {
		t.seen = append(t.seen, append([]byte(nil), leaf.Content...))
	}
	return doc, nil
}

func (t *w45RecordingTransformer) observed() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([][]byte, len(t.seen))
	copy(out, t.seen)
	return out
}

// TestPipelineResponseTransformerRunsBeforeBackfill locks the ordering rule:
// the transformer sees the placeholder (not the secret), and only the final
// core backfill restores the secret to the client.
func TestPipelineResponseTransformerRunsBeforeBackfill(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	recorder := &w45RecordingTransformer{}
	reg := w45Registry(t, redact.NewPrefixDetector(), recorder)
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine, Tool: "w4.5-transform"})

	upstream := &w45EchoUpstream{}
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstreamServer.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json",
		bytes.NewReader(w45RequestBody(secret)))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	clientBody, _ := io.ReadAll(resp.Body)

	observed := recorder.observed()
	if len(observed) == 0 {
		t.Fatal("ResponseContent transformer never ran")
	}
	joined := bytes.Join(observed, nil)
	if bytes.Contains(joined, []byte(secret)) {
		t.Errorf("transformer saw the raw secret before backfill: %q", joined)
	}
	if !bytes.Contains(joined, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("transformer input carried no placeholder: %q", joined)
	}
	// The transformer's output is the same document: no original secret.
	if !bytes.Contains(clientBody, []byte(secret)) {
		t.Errorf("client did not receive the backfilled secret: %s", clientBody)
	}
}

// TestPipelineRedactionDisabledForwardsSecret is the negative control: with no
// detectors registered the secret reaches the upstream verbatim, proving the
// E2E redaction assertions can catch a regression.
func TestPipelineRedactionDisabledForwardsSecret(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	reg := w45Registry(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine, Tool: "w4.5-negative"})

	upstream := &w45EchoUpstream{}
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstreamServer.URL, pipe)))
	t.Cleanup(srv.Close)

	body := w45RequestBody(secret)
	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	sent := upstream.received()
	if !bytes.Contains(sent, []byte(secret)) {
		t.Errorf("redaction disabled: secret did not reach upstream, so the E2E cannot catch a regression: %s", sent)
	}
	if bytes.Contains(sent, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("redaction disabled: upstream unexpectedly received a placeholder: %s", sent)
	}
	t.Logf("redaction-disabled upstream body (contains the raw secret): %s", sent)
}

// TestPipelineMalformedInputPassthrough proves a body the walker cannot parse
// is forwarded byte-for-byte instead of being corrupted or blocking traffic.
func TestPipelineMalformedInputPassthrough(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	cases := []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"plain_text", []byte("just some text, not JSON at all")},
		{"truncated", []byte(`{"input":"abc"`)},
		{"array_fragment", []byte(`[1,2,`)},
		{"invalid_utf8", []byte{0xff, 0xfe, 0x00, 0x01}},
		{"huge_plain", bytes.Repeat([]byte("a"), 1<<20)},
	}
	transform := pipe.RequestTransform()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transform(tc.body)
			if err != nil {
				t.Fatalf("transform(%d bytes): %v", len(tc.body), err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Errorf("body changed: got %d bytes, want %d", len(got), len(tc.body))
			}
		})
	}
}

// TestPipelineHugeJSONRedactsTail proves a secret at the very end of a large
// JSON body is still redacted (the transform sees the whole body).
func TestPipelineHugeJSONRedactsTail(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	reg := w45Registry(t, redact.NewPrefixDetector())
	// A generous plugin timeout isolates rewrite correctness from W4.2's
	// default 2s bound, which a 1 MiB body can exceed under instrumentation
	// (see the W4.5 notepad note on FailOpenWarn dropping findings).
	policy := extension.NewPolicy(reg, extension.PolicyConfig{Timeout: 30 * time.Second})
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Policy: policy, Engine: engine})

	padding := strings.Repeat("x", 1<<20)
	body := fmt.Appendf(nil, `{"pad":%q,"tail":%q}`, padding, secret)

	got, err := pipe.RequestTransform()(body)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if bytes.Contains(got, []byte(secret)) {
		t.Fatal("secret at the tail of a large body survived redaction")
	}
	if !bytes.Contains(got, []byte(protocol.PlaceholderPrefix)) {
		t.Fatal("no placeholder in the rewritten large body")
	}
}

// TestPipelinePlaceholderLiteralNotBackfilled proves the outbound direction
// never consults the reverse mapping: a client body that already contains a
// known placeholder is forwarded verbatim, not restored upstream.
func TestPipelinePlaceholderLiteralNotBackfilled(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	placeholder := engine.Placeholder(secret, "api_key")

	// Only the prefix detector: the placeholder itself is not a credential
	// shape, so the literal token passes through untouched.
	reg := w45Registry(t, redact.NewPrefixDetector())
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine})

	body := fmt.Appendf(nil, `{"input":%q}`, placeholder)
	got, err := pipe.RequestTransform()(body)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !bytes.Contains(got, []byte(placeholder)) {
		t.Errorf("outbound placeholder was not forwarded verbatim: %s", got)
	}
	if bytes.Contains(got, []byte(secret)) {
		t.Fatalf("outbound direction backfilled a placeholder into the secret: %s", got)
	}
}

// TestPipelineSSEBackfillAcrossChunks proves an SSE response streams through
// the incremental backfill writer and a placeholder split across chunks is
// restored without corrupting the SSE framing.
func TestPipelineSSEBackfillAcrossChunks(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	placeholder := engine.Placeholder(secret, "api_key")
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream writer is not a Flusher")
			return
		}
		// Split the placeholder across three chunks, each flushed.
		_, _ = io.WriteString(w, "data: "+placeholder[:7])
		flusher.Flush()
		_, _ = io.WriteString(w, placeholder[7:len(placeholder)-4])
		flusher.Flush()
		_, _ = io.WriteString(w, placeholder[len(placeholder)-4:]+"\n\n")
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if !bytes.Contains(body, []byte(secret)) {
		t.Errorf("stream did not restore the secret across chunk boundaries: %q", body)
	}
	if bytes.Contains(body, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("stream still contains a placeholder: %q", body)
	}
	if !bytes.HasPrefix(body, []byte("data: ")) || !bytes.HasSuffix(body, []byte("\n\n")) {
		t.Errorf("SSE framing was not preserved: %q", body)
	}
}

// TestPipelineUpstreamTimeoutBounded proves the forwarder's bounded client
// still bounds a stalled upstream when driven through the pipeline.
func TestPipelineUpstreamTimeoutBounded(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	upstream, handlerDone := hangingUpstream(t)
	client := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 150 * time.Millisecond}}
	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe, WithHTTPClient(client))))
	t.Cleanup(srv.Close)

	start := time.Now()
	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("proxy dropped the connection instead of answering: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", resp.StatusCode)
	}
	if elapsed > 3*time.Second {
		t.Errorf("forward took %v, want it bounded by the 150ms timeout", elapsed)
	}
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Error("timed-out upstream handler leaked")
	}
}

// TestPipelineRejectsNilEngine pins the construction guard.
func TestPipelineRejectsNilEngine(t *testing.T) {
	if _, err := NewPipeline(PipelineConfig{}); err == nil {
		t.Fatal("NewPipeline without an engine succeeded, want an error")
	}
}

// TestEscapedJSONStringLeafRoundTrip locks the rewriter's escape handling: a
// secret that contains characters requiring JSON escaping is re-encoded
// correctly and round-trips.
func TestEscapedJSONStringLeafRoundTrip(t *testing.T) {
	engine := w45Engine(t)
	reg := w45Registry(t, redact.NewPrefixDetector())
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine})

	secret := w45Secret()
	// The secret sits next to characters that json.Marshal escapes.
	body := fmt.Appendf(nil, `{"note":"quote:\" path:\\ %s","plain":"tail"}`, secret)
	got, err := pipe.RequestTransform()(body)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if bytes.Contains(got, []byte(secret)) {
		t.Fatalf("secret survived redaction: %s", got)
	}
	// The untouched sibling string keeps its exact escaping and position.
	if !bytes.Contains(got, []byte(`quote:\" path:\\`)) {
		t.Errorf("untouched escaped bytes were altered: %s", got)
	}
	if !bytes.HasSuffix(got, []byte(`,"plain":"tail"}`)) {
		t.Errorf("untouched trailing bytes were altered: %s", got)
	}
}
