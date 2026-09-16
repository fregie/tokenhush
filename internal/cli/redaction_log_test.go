package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/redact"
)

// TestRedactionLogRendersEveryAction pins the explicit rendering of every
// action the pipeline reports. A walk-failure event must never be rendered as a
// redaction: the response body was forwarded unchanged, so the line says
// exactly that and prints none of the empty detector fields. A mutation-channel
// refusal likewise refuses a tool call without redacting anything, so it must
// name the action and the channel instead of falling to the default branch's
// "redacted … (len=0) " line. The pre-existing redact and block lines must stay
// byte-identical.
func TestRedactionLogRendersEveryAction(t *testing.T) {
	cases := []struct {
		name          string
		event         proxy.RedactionEvent
		want          string
		walkFailure   bool
		egressBlocked bool
		refused       bool
	}{
		{
			name: "response_walk_failed",
			event: proxy.RedactionEvent{
				Action:    proxy.RedactionActionResponseWalkFailed,
				Direction: proxy.RedactionDirectionResponse,
				Phase:     "response_content",
			},
			want:        "tokenhush: unparseable response body skipped: response_walk_failed (forwarded unchanged)\n",
			walkFailure: true,
		},
		{
			name: "sse_walk_failed",
			event: proxy.RedactionEvent{
				Action:    proxy.RedactionActionSSEWalkFailed,
				Direction: proxy.RedactionDirectionResponse,
				Phase:     "response_content",
			},
			want:        "tokenhush: unparseable response body skipped: sse_walk_failed (forwarded unchanged)\n",
			walkFailure: true,
		},
		{
			name: "egress_blocked",
			event: proxy.RedactionEvent{
				Action:      proxy.RedactionActionEgressBlocked,
				Direction:   proxy.RedactionDirectionRequest,
				Phase:       "request_content",
				Placeholder: "__PII_api_key_0123456789abcdef__",
			},
			want:          "tokenhush: blocked request outbound body still carried a redacted secret (egress_blocked)\n",
			egressBlocked: true,
		},
		{
			name: "mutation_channel_blocked",
			event: proxy.RedactionEvent{
				Action:    proxy.RedactionActionMutationChannelBlocked,
				Direction: proxy.RedactionDirectionResponse,
				Phase:     "response_content",
				Type:      "cli-command",
			},
			want:    "tokenhush: refused response tool call (mutation_channel_blocked, channel=cli-command)\n",
			refused: true,
		},
		{
			name: "mutation_channel_blocked_without_a_matched_class",
			event: proxy.RedactionEvent{
				Action:    proxy.RedactionActionMutationChannelBlocked,
				Direction: proxy.RedactionDirectionResponse,
				Phase:     "response_content",
			},
			want:    "tokenhush: refused response tool call (mutation_channel_blocked, channel=none)\n",
			refused: true,
		},
		{
			name: "redact_line_unchanged",
			event: proxy.RedactionEvent{
				Action:    proxy.RedactionActionRedact,
				Direction: proxy.RedactionDirectionRequest,
				Phase:     "request_content",
				Type:      "api_key",
				Length:    24,
				Masked:    "sk-p<masked>",
			},
			want: "tokenhush: redacted request api_key (len=24) sk-p<masked>\n",
		},
		{
			name: "block_line_unchanged",
			event: proxy.RedactionEvent{
				Action:    proxy.RedactionActionBlock,
				Direction: proxy.RedactionDirectionRequest,
				Phase:     "request_content",
				Type:      "api_key",
			},
			want: "tokenhush: blocked request by content policy: api_key\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			newRedactionLogger(&buf).Report(tc.event)
			line := buf.String()
			if line != tc.want {
				t.Fatalf("rendered line = %q, want %q", line, tc.want)
			}
			if tc.walkFailure {
				if strings.Contains(line, "redacted") {
					t.Fatalf("walk-failure line claims a redaction: %q", line)
				}
				if !strings.Contains(line, tc.event.Action) {
					t.Fatalf("line %q does not name the action constant %q", line, tc.event.Action)
				}
				if !strings.Contains(line, "forwarded unchanged") {
					t.Fatalf("line %q does not state the body was forwarded unchanged", line)
				}
			}
			if tc.egressBlocked {
				// The default branch would render this action as a redaction
				// line ("tokenhush: redacted … (len=0)"), which is false: the
				// body was blocked, not redacted. Pin the truthful rendering.
				if strings.HasPrefix(line, "tokenhush: redacted") {
					t.Fatalf("egress-block line claims a redaction: %q", line)
				}
				if !strings.Contains(line, tc.event.Action) {
					t.Fatalf("line %q does not name the action constant %q", line, tc.event.Action)
				}
				if !strings.Contains(line, "blocked") {
					t.Fatalf("line %q does not say the body was blocked", line)
				}
			}
			if tc.walkFailure || tc.egressBlocked {
				if strings.Contains(line, "(len=") {
					t.Fatalf("line %q prints an empty-field artifact", line)
				}
				if strings.Contains(line, "  ") {
					t.Fatalf("line %q has a stray double space", line)
				}
			}
			if tc.refused {
				// The default branch would render this action as a redaction
				// line ("tokenhush: redacted … (len=0)"), which is false: the
				// tool call was refused, not rewritten to a placeholder.
				if strings.HasPrefix(line, "tokenhush: redacted") {
					t.Fatalf("refusal line claims a redaction: %q", line)
				}
				if !strings.Contains(line, tc.event.Action) {
					t.Fatalf("line %q does not name the action constant %q", line, tc.event.Action)
				}
				if !strings.Contains(line, "refused") {
					t.Fatalf("line %q does not say the tool call was refused", line)
				}
				if strings.Contains(line, "(len=") {
					t.Fatalf("line %q prints an empty-field artifact", line)
				}
			}
		})
	}

	// Verbatim rendering demo for the evidence file (`go test -v`).
	for _, tc := range cases {
		var buf bytes.Buffer
		newRedactionLogger(&buf).Report(tc.event)
		t.Logf("rendered[%s] = %q", tc.name, buf.String())
	}
}

// TestRedactionLogMasksSecret drives the default-on redaction log through the
// real daemon and a captured process stream. It is the counterpart to
// TestNoPlaintextInLogs, which pins the invariant with the log silenced: that
// test leaves Stderr nil, so no reporter is wired. This test asserts the masked
// line appears, that the raw secret never does, and that DisableRedactionLog
// silences it.
func TestRedactionLogMasksSecret(t *testing.T) {
	secret := runSecret()

	cases := []struct {
		name     string
		disable  bool
		wantLine bool
	}{
		{name: "default_on", wantLine: true},
		{name: "disabled", disable: true, wantLine: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := &echoUpstream{}
			upstreamSrv := httptest.NewServer(upstream)
			defer upstreamSrv.Close()

			cfg := config.Default()
			cfg.Listen.Host = "127.0.0.1"
			cfg.Listen.Port = 0
			cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

			getLogs := captureProcessOutput(t)
			defer getLogs()

			deps := RunDeps{
				DataDir:             t.TempDir(),
				Stdout:              os.Stdout,
				Stderr:              os.Stderr,
				DisableRedactionLog: tc.disable,
			}
			base, _, stop := startTestDaemon(t, &cfg, deps)
			defer func() { _ = stop() }()

			body := fmt.Sprintf(`{"model":"log-test","messages":[{"role":"user","content":%q}]}`, secret)
			resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("data-plane status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			_ = stop()

			logs := getLogs()
			if !strings.Contains(logs, "tokenhush:") {
				t.Fatalf("captured no daemon output; the scan would be vacuous: %q", logs)
			}
			if strings.Contains(logs, secret) {
				t.Fatal("redaction log leaked the raw secret; refusing to echo the leak")
			}
			gotLine := strings.Contains(logs, "redacted request api_key")
			if gotLine != tc.wantLine {
				t.Fatalf("masked line present = %v, want %v (logs: %q)", gotLine, tc.wantLine, logs)
			}
			if !tc.wantLine {
				return
			}
			if !strings.Contains(logs, "sk-p") {
				t.Fatalf("masked line is missing the expected prefix reveal: %q", logs)
			}
			if !strings.Contains(logs, fmt.Sprintf("(len=%d)", len(secret))) {
				t.Fatalf("masked line is missing the matched length: %q", logs)
			}
		})
	}
}

// TestRedactionLogEgressBlockedNoPlaintext drives the W2.3 outbound re-check
// through the real daemon and its captured process stream. The engine knows the
// secret (as a prior redaction would have taught it), the request carries only
// a base64 encoding of it, and the daemon must answer 403 without dialing the
// upstream. The scan reuses captureProcessOutput: the block is visible in the
// logs, the plaintext appears nowhere, and the misleading "redacted … (len=)"
// rendering is never produced for this action.
func TestRedactionLogEgressBlockedNoPlaintext(t *testing.T) {
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
	pipe, err := proxy.NewPipeline(proxy.PipelineConfig{Registry: reg, Engine: engine, Tool: "egress-log"})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}

	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

	getLogs := captureProcessOutput(t)
	defer getLogs()

	deps := RunDeps{
		DataDir:  t.TempDir(),
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Pipeline: pipe,
	}
	base, _, stop := startTestDaemon(t, &cfg, deps)
	defer func() { _ = stop() }()

	payload := base64.StdEncoding.EncodeToString([]byte(secret))
	body := fmt.Sprintf(`{"model":"log-test","messages":[{"role":"user","content":%q}]}`, payload)
	resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("data-plane status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := upstream.hits.Load(); got != 0 {
		t.Fatalf("upstream dialed %d time(s), want 0", got)
	}
	if got := pipe.EgressBlocks(); got != 1 {
		t.Fatalf("EgressBlocks = %d, want 1", got)
	}
	_ = stop()

	logs := getLogs()
	if !strings.Contains(logs, "tokenhush:") {
		t.Fatalf("captured no daemon output; the scan would be vacuous: %q", logs)
	}
	if strings.Contains(logs, secret) {
		t.Fatal("egress-block log leaked the raw secret; refusing to echo the leak")
	}
	if !strings.Contains(logs, "egress_blocked") {
		t.Fatalf("the block is not visible in the daemon logs: %q", logs)
	}
	if strings.Contains(logs, "tokenhush: redacted") {
		t.Fatalf("the block was rendered as a redaction: %q", logs)
	}
}
