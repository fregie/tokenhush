package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
)

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
			// Isolation discriminator: the helper-embedded no-pack default must
			// keep startup off the developer's real rule cache, so the captured
			// diagnostics never carry the real-cache fallback warning.
			if strings.Contains(logs, "using built-in defaults") {
				t.Fatal("captured diagnostics carry the rules real-cache fallback; startup is not isolated")
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
