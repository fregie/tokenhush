package proxy

// W2.4 pins the whole F2 attack chain as blocked, in one named end-to-end test:
// TestEgressEncodingBypassBlocked.
//
// The chain the audit draft describes is:
//
//  1. the session maps a real secret to a placeholder (the engine learns it,
//     here through the pipeline's own redaction leg);
//  2. a client-bound response carries that placeholder and the real inbound
//     backfill materialises the plaintext for the client — the F1 risk the
//     project accepted (W1.4/W7.1) and W2.4 reproduces instead of "fixing";
//  3. the materialised plaintext is re-encoded in each of the 13 frozen forms
//     (W2.2 table ①–⑬) and sent outbound;
//  4. W2.3's outbound re-check must block every form: 403, the upstream is
//     never dialed and receives zero bytes, and EgressBlocks moves.
//
// Both response paths the plan names are driven: the buffered path
// (transformResponse via ResponseMiddleware) and the streaming path
// (newSSEBackfiller, selected by a text/event-stream response), and every one
// of the 13 forms is a named subtest so a single regression is attributable.
//
// The placeholder is derived at runtime with engine.Placeholder (a hardcoded
// token could never be recognised by this engine: the digest is HMAC'd with a
// per-session salt). The secret is assembled from fragments — never a
// committed literal.
//
// This test is load-bearing, not tautological: the plan's falsification gate
// short-circuits egressRecheck (W2.3) and this test must then fail with the
// encoded body reaching the upstream (status 200, non-zero captured bytes).
// It passing today is expected — W2.3 is already implemented, so the pin's
// strength comes from the gate, not from a red-first run.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// egressChainSecret assembles the chain's synthetic credential at runtime from
// fragments, so no contiguous key-shaped literal is committed. Its shape is
// deliberate on two axes:
//
//   - it matches the built-in prefix detector's `AIza...` alternative and is
//     exactly as long as that alternative expects, so the pipeline's REAL
//     redaction leg maps it to the same placeholder the test derives with
//     engine.Placeholder — the chain therefore exercises redaction, not just
//     the explicit engine call;
//   - it is entirely alphanumeric (no `-`/`_` separator bytes), because the
//     separator-stripping decoder of form ① would otherwise corrupt the
//     secret's own separator and that form would stop being a fair negative
//     case (the W2.2 fixture is alphanumeric for the same reason).
func egressChainSecret() string {
	return "AIza" + strings.Join([]string{
		"Xk9", "Qw2", "Zr7", "Lm4", "Tb8", "Hn5",
		"Vc1", "Js6", "Pd3", "Fg0", "Yw2", "Kv",
	}, "")
}

// TestEgressEncodingBypassBlocked reproduces the complete
// placeholder -> plaintext -> encode -> outbound chain in one session:
//
//   - link 1 derives the placeholder at runtime;
//   - link 2 materialises the plaintext through both real inbound response
//     paths (buffered and SSE) and extracts it back off the client wire;
//   - link 3 encodes that materialised plaintext in each covered form and sends
//     it outbound through the same pipeline, expecting a block every time.
func TestEgressEncodingBypassBlocked(t *testing.T) {
	secret := egressChainSecret()
	engine := w45Engine(t)
	reg := w45Registry(t, redact.NewPrefixDetector())
	policy := extension.NewPolicy(reg, extension.PolicyConfig{})
	pipe := w45Pipeline(t, PipelineConfig{
		Registry: reg,
		Policy:   policy,
		Engine:   engine,
		Tool:     "w2.4-egress-chain",
	})

	// Link 1: derive the placeholder at runtime. engine.Placeholder creates the
	// same (type, secret) mapping the redaction leg will use below, so the
	// derived token must be non-empty and must never embed the plaintext.
	placeholder := engine.Placeholder(secret, "api_key")
	if placeholder == "" {
		t.Fatal("engine.Placeholder returned an empty token")
	}
	if strings.Contains(placeholder, secret) {
		t.Fatal("the derived placeholder embeds the plaintext")
	}
	if !strings.HasPrefix(placeholder, protocol.PlaceholderPrefix) {
		t.Fatalf("derived token %q does not carry the placeholder prefix", placeholder)
	}
	if len(placeholder) < 20 {
		t.Fatalf("derived placeholder is only %d bytes: too short to split across SSE events", len(placeholder))
	}

	// Link 2: materialise the plaintext through both real response paths. Each
	// helper returns the plaintext it extracted from the client-bound bytes, so
	// the encoding step below consumes bytes that really crossed the backfill.
	var buffered, streamed string
	t.Run("materialise_buffered_response_path", func(t *testing.T) {
		buffered = egressChainMaterialiseBuffered(t, pipe, placeholder, secret)
	})
	t.Run("materialise_sse_response_path", func(t *testing.T) {
		streamed = egressChainMaterialiseSSE(t, pipe, placeholder, secret)
	})
	if buffered != secret || streamed != secret {
		t.Fatalf("materialised plaintext mismatch: buffered_ok=%v sse_ok=%v",
			buffered == secret, streamed == secret)
	}
	t.Logf("materialised the plaintext through both response paths (buffered and SSE), placeholders restored client-side")

	// Link 3: encode the materialised plaintext in every frozen W2.2 form ①–⑬
	// and attempt egress through the same session. Every variant must be
	// blocked before the forwarder dials the upstream.
	for _, form := range egressForms(t, buffered) {
		form := form
		t.Run(form.name, func(t *testing.T) {
			for _, variant := range form.variants {
				variant := variant
				t.Run(variant.name, func(t *testing.T) {
					if bytes.Contains(variant.payload, []byte(secret)) {
						t.Fatalf("fixture error: form %s variant %s carries the plaintext verbatim",
							form.name, variant.name)
					}
					before := pipe.EgressBlocks()
					status, upstream := egressE2E(t, pipe, egressEncodedBody(t, variant.payload))
					sent := upstream.received()

					if status != http.StatusForbidden {
						t.Errorf("status = %d, want %d", status, http.StatusForbidden)
					}
					if got := upstream.hits.Load(); got != 0 {
						t.Errorf("upstream dialed %d time(s), want 0", got)
					}
					if len(sent) != 0 {
						t.Errorf("upstream received %d bytes, want 0", len(sent))
					}
					if got := pipe.EgressBlocks(); got != before+1 {
						t.Errorf("EgressBlocks = %d, want %d", got, before+1)
					}
					t.Logf("chain form=%s variant=%s status=%d upstream_hits=%d upstream_bytes=%d egress_blocks=%d",
						form.name, variant.name, status, upstream.hits.Load(), len(sent), pipe.EgressBlocks())
				})
			}
		})
	}
}

// egressChainMaterialiseBuffered drives the placeholder through the buffered
// response path: the request carries the plaintext, the pipeline's own
// redaction leg turns it into the placeholder upstream (asserted byte-for-byte
// against the runtime-derived token), the upstream echoes the token in a JSON
// body, and the real transformResponse + core backfill restores the plaintext
// to the client. The returned plaintext is parsed back off the client-bound
// JSON rather than assumed.
func egressChainMaterialiseBuffered(t *testing.T, pipe *Pipeline, placeholder, secret string) string {
	t.Helper()

	upstream := &w45EchoUpstream{}
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)
	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstreamServer.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json",
		bytes.NewReader(egressEncodedBody(t, []byte(secret))))
	if err != nil {
		t.Fatalf("buffered chain request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	clientBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read buffered chain response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("buffered chain status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Outbound leg: the pipeline redacted the plaintext, so the upstream saw
	// exactly the derived placeholder and never the plaintext.
	sent := upstream.received()
	if bytes.Contains(sent, []byte(secret)) {
		t.Fatal("outbound leg leaked the plaintext to the upstream")
	}
	token := w45PlaceholderRe.Find(sent)
	if token == nil {
		t.Fatal("upstream received no placeholder to echo back")
	}
	if string(token) != placeholder {
		t.Fatal("upstream received a placeholder other than the runtime-derived one")
	}

	// Inbound leg: the real response path materialised the plaintext.
	if !bytes.Contains(clientBody, []byte(secret)) {
		t.Fatal("buffered response path did not materialise the plaintext for the client")
	}
	if bytes.Contains(clientBody, []byte(protocol.PlaceholderPrefix)) {
		t.Fatal("buffered client body still carries a placeholder")
	}
	var echoed struct {
		Echo   string `json:"echo"`
		Nested struct {
			X string `json:"x"`
		} `json:"nested"`
	}
	if err := json.Unmarshal(clientBody, &echoed); err != nil {
		t.Fatalf("decode buffered client body: %v", err)
	}
	if echoed.Echo != secret || echoed.Nested.X != secret {
		t.Fatalf("buffered materialisation mismatch: echo_ok=%v nested_ok=%v",
			echoed.Echo == secret, echoed.Nested.X == secret)
	}
	return echoed.Echo
}

// egressChainMaterialiseSSE drives the placeholder through the streaming
// response path: a text/event-stream upstream emits the runtime-derived
// placeholder split across four delta.content events (plus a [DONE] frame), the
// SSE backfiller restores it, and the plaintext is extracted by concatenating
// the delta fragments of the client-bound stream. Framing (event count,
// `data: ` prefixes, [DONE] tail) must survive the rewrite.
func egressChainMaterialiseSSE(t *testing.T, pipe *Pipeline, placeholder, secret string) string {
	t.Helper()

	// Split by byte offset (the first cut lands inside the `__PII_` opening), so
	// the raw stream never contains a contiguous placeholder the naive backfill
	// could match: only the SSE-aware accumulated backfill can restore it.
	fragments := []string{
		placeholder[:4],
		placeholder[4:12],
		placeholder[12:20],
		placeholder[20:],
	}
	events := make([]string, 0, len(fragments)+1)
	for _, fragment := range fragments {
		events = append(events, w45DeltaEvent(t, fragment))
	}
	events = append(events, "data: [DONE]\n\n")
	wantEvents := len(events)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		for _, event := range events {
			_, _ = io.WriteString(w, event)
			_ = rc.Flush()
		}
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("SSE chain request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	clientBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read SSE chain stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE chain status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !bytes.Contains(clientBody, []byte(secret)) {
		t.Fatal("SSE response path did not materialise the plaintext for the client")
	}
	if bytes.Contains(clientBody, []byte(protocol.PlaceholderPrefix)) {
		t.Fatal("SSE client stream still carries a placeholder")
	}
	if got := strings.Count(string(clientBody), "\n\n"); got != wantEvents {
		t.Fatalf("SSE event count = %d, want %d (framing changed)", got, wantEvents)
	}

	// Extract the plaintext off the client-bound stream by concatenating the
	// delta fragments, exactly as an SDK reassembling deltas would.
	segments := strings.Split(strings.TrimSuffix(string(clientBody), "\n\n"), "\n\n")
	var restored strings.Builder
	for i, segment := range segments {
		if !strings.HasPrefix(segment, "data: ") {
			t.Fatalf("SSE event %d lost its `data: ` prefix", i)
		}
		payload := strings.TrimPrefix(segment, "data: ")
		if payload == "[DONE]" {
			continue
		}
		var chunk w45DeltaChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			t.Fatalf("decode SSE event %d: %v", i, err)
		}
		restored.WriteString(chunk.Delta.Content)
	}
	if restored.String() != secret {
		t.Fatalf("SSE materialisation mismatch: restored %d bytes, want %d",
			restored.Len(), len(secret))
	}
	return restored.String()
}
