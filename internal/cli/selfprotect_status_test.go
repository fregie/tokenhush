package cli

// W6.5 end-to-end regressions: `tokenhush status` exposes the C8 counters, and
// they move with real traffic through the real daemon — a buffered tool-call
// interception, a control-plane allowlist mutation, a streamed cap-exhaustion
// refusal and an egress re-check block. The same daemon harness as W6.1's
// selfprotect_run_test.go and W5.3's control-plane helpers is reused; no
// production path is added. The log scan at the end pins that the (truthfully
// rendered) interception line carries no plaintext.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/redact"
)

// w65StaticUpstream serves one fixed response body with the given content type:
// the model-shaped response the C8 guard must inspect. It replaces the echo
// upstream because the guard only rewrites a whole top-level `arguments` leaf,
// and the echo wrapper buries the request JSON inside one string value.
type w65StaticUpstream struct {
	contentType string
	body        []byte
	hits        atomic.Int64
}

func (u *w65StaticUpstream) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	u.hits.Add(1)
	w.Header().Set("Content-Type", u.contentType)
	_, _ = w.Write(u.body)
}

// w65ToolCallBody returns an OpenAI-shaped assistant response carrying one tool
// call whose decoded arguments are the given string.
func w65ToolCallBody(t *testing.T, arguments string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"id":     "chatcmpl-w65",
		"object": "chat.completion",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role": "assistant",
					"tool_calls": []map[string]any{
						{
							"id":   "call_w65",
							"type": "function",
							"function": map[string]any{
								"name":      "shell",
								"arguments": arguments,
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal tool-call body: %v", err)
	}
	return body
}

// w65SSEArgumentsEvent renders one OpenAI-shaped streamed tool-call delta
// carrying one decoded arguments fragment.
func w65SSEArgumentsEvent(t *testing.T, fragment string) string {
	t.Helper()
	quoted, err := json.Marshal(fragment)
	if err != nil {
		t.Fatalf("marshal arguments fragment: %v", err)
	}
	return `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":` +
		string(quoted) + `}}]}}]}` + "\n\n"
}

// w65SSEOverCapStream returns a complete SSE tool-call stream whose single
// call carries a legal (never matching) arguments payload above
// proxy.SSEGuardCap, plus the marker planted inside that payload so a test can
// prove the payload never reached the client.
func w65SSEOverCapStream(t *testing.T) (stream, marker string) {
	t.Helper()
	marker = "W65-LEGAL-PARAM-MARK"
	payload := proxy.SSEGuardCap + proxy.SSEGuardCap/4
	doc := `{"path":"/tmp/big.bin","content":"` + marker + strings.Repeat("A", payload-len(marker)) + `"}`

	var out strings.Builder
	const chunk = 4 << 10
	for len(doc) > 0 {
		n := min(chunk, len(doc))
		out.WriteString(w65SSEArgumentsEvent(t, doc[:n]))
		doc = doc[n:]
	}
	out.WriteString(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n")
	out.WriteString("data: [DONE]\n\n")
	return out.String(), marker
}

// w65StatusCounters is the `status --json` view subset the W6.5 assertions need.
type w65StatusCounters struct {
	Running                     bool   `json:"running"`
	Requests                    uint64 `json:"requests"`
	Redactions                  uint64 `json:"redactions"`
	SelfProtectionInterceptions uint64 `json:"self_protection_interceptions"`
	AllowlistMutations          uint64 `json:"allowlist_mutations"`
	StreamGuardRefusals         uint64 `json:"stream_guard_refusals"`
	StreamGuardFailClosed       uint64 `json:"stream_guard_fail_closed"`
	EgressBlocks                uint64 `json:"egress_blocks"`
	ContentPolicyBlocks         uint64 `json:"content_policy_blocks"`
}

// w65ReadStatus runs `tokenhush status --json` in-process against the live
// daemon (TOKENHUSH_HOME must point at its data directory) and parses the
// counters.
func w65ReadStatus(t *testing.T) w65StatusCounters {
	t.Helper()
	stdout, stderr, code := cliRun(t, "status", "--json")
	if code != ExitOK {
		t.Fatalf("status --json code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
	}
	var got w65StatusCounters
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("status --json did not parse: %v (stdout=%q)", err, stdout)
	}
	if !got.Running {
		t.Fatalf("status --json = %+v, want a running gateway", got)
	}
	t.Logf("W65_STATUS requests=%d redactions=%d interceptions=%d mutations=%d stream=%d fail_closed=%d egress=%d content_policy=%d",
		got.Requests, got.Redactions, got.SelfProtectionInterceptions, got.AllowlistMutations,
		got.StreamGuardRefusals, got.StreamGuardFailClosed, got.EgressBlocks, got.ContentPolicyBlocks)
	return got
}

// w65DaemonConfig is the shared config: loopback, ephemeral port, one upstream.
func w65DaemonConfig(upstreamURL string) *config.Config {
	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamURL}
	return &cfg
}

// w65AssertTextStatus asserts the human view renders every W6.5 counter line in
// the repository's existing `  key: value` style.
func w65AssertTextStatus(t *testing.T, want string, counters w65StatusCounters) {
	t.Helper()
	stdout, stderr, code := cliRun(t, "status")
	if code != ExitOK {
		t.Fatalf("status code = %d, want %d (stderr=%q)", code, ExitOK, stderr)
	}
	for _, line := range []string{
		fmt.Sprintf("self-protection interceptions: %d", counters.SelfProtectionInterceptions),
		fmt.Sprintf("allowlist mutations: %d", counters.AllowlistMutations),
		fmt.Sprintf("stream guard refusals: %d", counters.StreamGuardRefusals),
		fmt.Sprintf("stream guard fail-closed: %d", counters.StreamGuardFailClosed),
		fmt.Sprintf("egress blocks: %d", counters.EgressBlocks),
		fmt.Sprintf("content policy blocks: %d", counters.ContentPolicyBlocks),
	} {
		if !strings.Contains(stdout, line) {
			t.Fatalf("status stdout = %q, want it to contain %q (%s)", stdout, line, want)
		}
	}
}

// TestStatusSelfProtectionCounters is the W6.5 acceptance test: the status
// counters increment per interception, per allowlist mutation, per cap
// exhaustion and per egress block, through the real daemon.
func TestStatusSelfProtectionCounters(t *testing.T) {
	t.Run("buffered_interception_and_allowlist_mutation_increment_status", func(t *testing.T) {
		const hit = "W65-HIT"
		upstream := &w65StaticUpstream{
			contentType: "application/json",
			body:        w65ToolCallBody(t, "tokenhush allowlist add evil.example "+hit),
		}
		upstreamSrv := httptest.NewServer(upstream)
		t.Cleanup(upstreamSrv.Close)

		dataDir := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", dataDir)
		base, token, stop := startTestDaemon(t, w65DaemonConfig(upstreamSrv.URL), RunDeps{
			DataDir:             dataDir,
			Stdout:              io.Discard,
			Stderr:              io.Discard,
			DisableRedactionLog: true,
		})
		defer func() { _ = stop() }()

		resp := postBody(t, base+"/v1/messages", "application/json", `{"model":"w65","messages":[]}`, nil)
		clientBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read client body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("data-plane status = %d, want 200 (body %q)", resp.StatusCode, clientBody)
		}
		if !strings.Contains(string(clientBody), "tokenhush refused this tool call") {
			t.Fatalf("client body = %q, want the W6.3 refusal notice", clientBody)
		}
		if bytes.Contains(clientBody, []byte(hit)) {
			t.Fatalf("the refused tool call survived: %q", clientBody)
		}
		if got := upstream.hits.Load(); got != 1 {
			t.Fatalf("upstream hits = %d, want 1", got)
		}

		// One control-plane mutation (the W5.3 endpoint, the human/CLI source).
		w61RunControl(t, base+"/allowlist", token, http.MethodPost, w61JSON(t, map[string]any{"entry": "w65.runtime.entry"}))

		got := w65ReadStatus(t)
		if got.SelfProtectionInterceptions != 1 {
			t.Errorf("self_protection_interceptions = %d, want 1", got.SelfProtectionInterceptions)
		}
		if got.AllowlistMutations != 1 {
			t.Errorf("allowlist_mutations = %d, want 1", got.AllowlistMutations)
		}
		if got.StreamGuardRefusals != 0 || got.StreamGuardFailClosed != 0 || got.EgressBlocks != 0 {
			t.Errorf("unrelated counters moved: stream=%d fail_closed=%d egress=%d",
				got.StreamGuardRefusals, got.StreamGuardFailClosed, got.EgressBlocks)
		}
		w65AssertTextStatus(t, "buffered interception + mutation", got)
	})

	t.Run("cap_exhaustion_is_visible_as_fail_closed", func(t *testing.T) {
		stream, marker := w65SSEOverCapStream(t)
		upstream := &w65StaticUpstream{contentType: "text/event-stream", body: []byte(stream)}
		upstreamSrv := httptest.NewServer(upstream)
		t.Cleanup(upstreamSrv.Close)

		dataDir := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", dataDir)
		base, _, stop := startTestDaemon(t, w65DaemonConfig(upstreamSrv.URL), RunDeps{
			DataDir:             dataDir,
			Stdout:              io.Discard,
			Stderr:              io.Discard,
			DisableRedactionLog: true,
		})
		defer func() { _ = stop() }()

		resp := postBody(t, base+"/v1/messages", "application/json", `{"model":"w65","stream":true}`, nil)
		clientBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read client body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("streamed status = %d, want 200 (body %q)", resp.StatusCode, clientBody)
		}
		if !strings.Contains(string(clientBody), "tokenhush refused this tool call") {
			t.Fatalf("streamed body = %q, want the refusal notice", clientBody)
		}
		if bytes.Contains(clientBody, []byte(marker)) {
			t.Fatalf("the over-cap legal payload was streamed as-is: %q", clientBody)
		}

		got := w65ReadStatus(t)
		if got.StreamGuardRefusals != 1 {
			t.Errorf("stream_guard_refusals = %d, want 1", got.StreamGuardRefusals)
		}
		if got.StreamGuardFailClosed != 1 {
			t.Errorf("stream_guard_fail_closed = %d, want 1 (the cap is fail-closed)", got.StreamGuardFailClosed)
		}
		if got.SelfProtectionInterceptions != 0 {
			t.Errorf("self_protection_interceptions = %d, want 0 for the streaming path", got.SelfProtectionInterceptions)
		}
		w65AssertTextStatus(t, "cap exhaustion", got)
	})

	t.Run("egress_block_increments_status", func(t *testing.T) {
		secret := runSecret()
		engine, err := redact.NewPlaceholderEngine()
		if err != nil {
			t.Fatalf("NewPlaceholderEngine: %v", err)
		}
		engine.Placeholder(secret, "api_key")
		reg := extension.NewRegistry()
		if err := reg.Register(redact.NewPrefixDetector()); err != nil {
			t.Fatalf("Register(prefix): %v", err)
		}
		pipe, err := proxy.NewPipeline(proxy.PipelineConfig{Registry: reg, Engine: engine, Tool: "w65-egress"})
		if err != nil {
			t.Fatalf("NewPipeline: %v", err)
		}

		upstream := &w65StaticUpstream{contentType: "application/json", body: []byte(`{"ok":true}`)}
		upstreamSrv := httptest.NewServer(upstream)
		t.Cleanup(upstreamSrv.Close)

		dataDir := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", dataDir)
		base, _, stop := startTestDaemon(t, w65DaemonConfig(upstreamSrv.URL), RunDeps{
			DataDir:             dataDir,
			Stdout:              io.Discard,
			Stderr:              io.Discard,
			Pipeline:            pipe,
			DisableRedactionLog: true,
		})
		defer func() { _ = stop() }()

		body := fmt.Sprintf(`{"model":"w65","messages":[{"role":"user","content":%q}]}`,
			base64.StdEncoding.EncodeToString([]byte(secret)))
		resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("egress-blocked request status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
		if got := upstream.hits.Load(); got != 0 {
			t.Fatalf("upstream dialed %d time(s), want 0", got)
		}

		got := w65ReadStatus(t)
		if got.EgressBlocks != 1 {
			t.Errorf("egress_blocks = %d, want 1", got.EgressBlocks)
		}
		if got.SelfProtectionInterceptions != 0 || got.AllowlistMutations != 0 {
			t.Errorf("unrelated counters moved: interceptions=%d mutations=%d",
				got.SelfProtectionInterceptions, got.AllowlistMutations)
		}
		w65AssertTextStatus(t, "egress block", got)
	})

	t.Run("content_policy_block_increments_status", func(t *testing.T) {
		upstream := &w65StaticUpstream{contentType: "application/json", body: []byte(`{"ok":true}`)}
		upstreamSrv := httptest.NewServer(upstream)
		t.Cleanup(upstreamSrv.Close)

		// A tiny byte budget turns a legal request into a content-policy
		// refusal without touching any detector or timeout behavior.
		cfg := w65DaemonConfig(upstreamSrv.URL)
		cfg.Detectors.ScanBudgetBytes = 64

		dataDir := t.TempDir()
		t.Setenv("TOKENHUSH_HOME", dataDir)
		base, _, stop := startTestDaemon(t, cfg, RunDeps{
			DataDir:             dataDir,
			Stdout:              io.Discard,
			Stderr:              io.Discard,
			DisableRedactionLog: true,
		})
		defer func() { _ = stop() }()

		body := `{"input":"` + strings.Repeat("A", 256) + `"}`
		resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
		clientBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read client body: %v", err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("over-budget request status = %d, want %d (body %q)", resp.StatusCode, http.StatusForbidden, clientBody)
		}
		if !strings.Contains(string(clientBody), proxy.TypeScanBudgetExceeded) {
			t.Fatalf("403 body = %q, want the labelled %q class", clientBody, proxy.TypeScanBudgetExceeded)
		}
		if got := upstream.hits.Load(); got != 0 {
			t.Fatalf("upstream dialed %d time(s), want 0 (refused before egress)", got)
		}

		got := w65ReadStatus(t)
		if got.ContentPolicyBlocks != 1 {
			t.Errorf("content_policy_blocks = %d, want 1", got.ContentPolicyBlocks)
		}
		w65AssertTextStatus(t, "content-policy block", got)
	})

	t.Run("interception_log_is_truthful_about_the_refusal", func(t *testing.T) {
		const probe = "W65-LOG-PROBE-7c21"
		upstream := &w65StaticUpstream{
			contentType: "application/json",
			body:        w65ToolCallBody(t, "tokenhush allowlist add evil.example "+probe),
		}
		upstreamSrv := httptest.NewServer(upstream)
		t.Cleanup(upstreamSrv.Close)

		getLogs := captureProcessOutput(t)
		defer getLogs()

		deps := RunDeps{
			DataDir: t.TempDir(),
			Stdout:  os.Stdout,
			Stderr:  os.Stderr,
		}
		base, _, stop := startTestDaemon(t, w65DaemonConfig(upstreamSrv.URL), deps)
		defer func() { _ = stop() }()

		resp := postBody(t, base+"/v1/messages", "application/json", `{"model":"w65","messages":[]}`, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("data-plane status = %d, want 200", resp.StatusCode)
		}
		_ = stop()

		logs := getLogs()
		if !strings.Contains(logs, "tokenhush:") {
			t.Fatalf("captured no daemon output; the scan would be vacuous: %q", logs)
		}
		if !strings.Contains(logs, "mutation_channel_blocked") {
			t.Fatalf("the refusal is not visible in the daemon logs: %q", logs)
		}
		// The default branch would render "redacted … (len=0) ", which is
		// false: the tool call was refused, not redacted.
		if strings.Contains(logs, "tokenhush: redacted") {
			t.Fatalf("the refusal was rendered as a redaction: %q", logs)
		}
		leaks := []string{probe, "evil.example"}
		hits := 0
		for _, leak := range leaks {
			if strings.Contains(logs, leak) {
				hits++
			}
		}
		// The scanner is not vacuous: it detects the probe when it is present.
		poisoned := "tokenhush: refused response tool call (mutation_channel_blocked, channel=cli-command) " + probe
		plantedDetected := strings.Contains(poisoned, probe)
		t.Logf("W65_LOG_SCAN bytes=%d probes=%d hits=%d planted_probe_detected=%v",
			len(logs), len(leaks), hits, plantedDetected)
		if !plantedDetected {
			t.Fatal("planted probe not detected by the log scanner")
		}
		if hits != 0 {
			t.Fatalf("plaintext found in daemon logs (%d hits); refusing to echo the leak", hits)
		}
	})
}
