package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/protocol"
)

// w61RunEntry assembles an allowlist entry at runtime. It is `sk-`-shaped so the
// prefix detector flags it and the dynamic allowlist must suppress it, which
// makes the C7 assertion meaningful.
func w61RunEntry() string {
	return "sk" + "-" + "proj" + "-" + "RunAllowEntry7QwErTy123456"
}

func w61JSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return out
}

// w61RunRequest sends one data-plane request and returns the client-bound body.
func w61RunRequest(t *testing.T, url string, body []byte) []byte {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read POST %s response: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, body %s", url, resp.StatusCode, out)
	}
	return out
}

// w61RunControl sends one bearer-authenticated control-plane request.
func w61RunControl(t *testing.T, url, token, method string, body []byte) []byte {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new control request %s %s: %v", method, url, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("control %s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read control %s %s response: %v", method, url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control %s %s status = %d, body %s", method, url, resp.StatusCode, out)
	}
	return out
}

// TestRunInstallsSelfProtectionExclusions is the W6.1 production-path
// acceptance test. It drives the real core assembly (RunServer ->
// gateway.BuildPipeline -> gateway.Run), the only place the session control
// token is generated (ADR-0012 freezes "bind before writing the token", so the
// token cannot exist at pipeline-construction time). It asserts that:
//
//   - a request carrying the session control-token value reaches the upstream
//     as a placeholder, not the token, and the client response keeps the
//     placeholder (never backfilled);
//   - after a control-plane allowlist mutation, the allowlist file's current
//     bytes are force-redacted too (the refresh hook);
//   - C7 is unaffected: an allowlisted entry value is forwarded verbatim, so
//     the exclusion set does not contain allowlist entry values.
//
// cfg.Detectors.HighEntropy is disabled because the generated token is random
// base64 that the high-entropy detector also redacts; turning it off isolates
// the C8 force-redaction path, which is what makes the Run-time install
// load-bearing (a build with the install removed must let the token reach the
// upstream).
func TestRunInstallsSelfProtectionExclusions(t *testing.T) {
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}
	cfg.Detectors.HighEntropy = false

	dataDir := t.TempDir()
	base, token, stop := startTestDaemon(t, &cfg, RunDeps{
		DataDir:             dataDir,
		Stdout:              io.Discard,
		Stderr:              io.Discard,
		DisableRedactionLog: true,
	})
	defer func() { _ = stop() }()
	dataURL := base + "/v1/messages"

	// (1) The session control token is force-redacted outbound and never
	// restored inbound.
	clientBody := w61RunRequest(t, dataURL, w61JSON(t, map[string]any{
		"model": "claude-test",
		"input": "token=" + token,
	}))
	sent := upstream.received()
	if bytes.Contains(sent, []byte(token)) {
		t.Fatalf("control token reached the upstream request body: %s", sent)
	}
	if !bytes.Contains(sent, []byte(protocol.PlaceholderPrefix)) {
		t.Fatalf("upstream received no placeholder for the control token: %s", sent)
	}
	if bytes.Contains(clientBody, []byte(token)) {
		t.Fatalf("client response restored the control token: %s", clientBody)
	}
	if !bytes.Contains(clientBody, []byte(protocol.PlaceholderPrefix)) {
		t.Fatalf("client response lost the exclusion placeholder: %s", clientBody)
	}

	// (2) A real control-plane mutation rewrites <DataDir>/allowlist.json, and
	// the refresh hook must exclude the file's new bytes.
	entry := w61RunEntry()
	w61RunControl(t, base+"/allowlist", token, http.MethodPost,
		w61JSON(t, map[string]any{"entry": entry}))

	// C7 is unaffected: the allowlisted entry value is not in the exclusion set.
	w61RunRequest(t, dataURL, w61JSON(t, map[string]any{"input": "allowed=" + entry}))
	sent = upstream.received()
	if !bytes.Contains(sent, []byte(entry)) {
		t.Fatalf("allowlisted entry value was not forwarded verbatim (C7 regression or entry value wrongly excluded): %s", sent)
	}

	// (3) The allowlist file's current bytes are force-redacted.
	raw, err := os.ReadFile(filepath.Join(dataDir, allowlist.FileName))
	if err != nil {
		t.Fatalf("read %s: %v", allowlist.FileName, err)
	}
	if !bytes.Contains(raw, []byte(entry)) {
		t.Fatalf("test setup: the persisted allowlist does not carry the new entry: %s", raw)
	}
	w61RunRequest(t, dataURL, w61JSON(t, map[string]any{"file": string(raw)}))
	sent = upstream.received()
	if bytes.Contains(sent, raw) {
		t.Fatalf("allowlist file content reached the upstream request body: %s", sent)
	}
	if !bytes.Contains(sent, []byte(protocol.PlaceholderPrefix)) {
		t.Fatalf("upstream received no placeholder for the allowlist file content: %s", sent)
	}

	t.Logf("upstream body carrying the allowlist file: %s", sent)
}
