package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// TestRedactionLogRendersEveryAction pins the four-action rendering. A
// walk-failure event must never be rendered as a redaction: the response body
// was forwarded unchanged, so the line says exactly that and prints none of the
// empty detector fields. The pre-existing redact and block lines must stay
// byte-identical.
func TestRedactionLogRendersEveryAction(t *testing.T) {
	cases := []struct {
		name        string
		event       proxy.RedactionEvent
		want        string
		walkFailure bool
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
			if !tc.walkFailure {
				return
			}
			if strings.Contains(line, "redacted") {
				t.Fatalf("walk-failure line claims a redaction: %q", line)
			}
			if !strings.Contains(line, tc.event.Action) {
				t.Fatalf("line %q does not name the action constant %q", line, tc.event.Action)
			}
			if !strings.Contains(line, "forwarded unchanged") {
				t.Fatalf("line %q does not state the body was forwarded unchanged", line)
			}
			if strings.Contains(line, "(len=") {
				t.Fatalf("line %q prints an empty-field artifact", line)
			}
			if strings.Contains(line, "  ") {
				t.Fatalf("line %q has a stray double space", line)
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
