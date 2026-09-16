package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// W6.1 synthetic credentials are assembled at runtime from fragments so no
// contiguous detector-shaped literal is committed. Every one still matches the
// built-in `sk-` prefix detector, so the allowlist interplay is exercised.
const (
	w61Head      = "sk"
	w61Proj      = "proj"
	w61TokenTail = "ControlToken7AbCdEf123456"
	w61OtherTail = "OtherSecret7GhIjKl765432"
	w61AllowTail = "AllowedValue7MnOpQr987654"
)

func w61Token() string       { return w61Head + "-" + w61Proj + "-" + w61TokenTail }
func w61Other() string       { return w61Head + "-" + w61Proj + "-" + w61OtherTail }
func w61Allowlisted() string { return w61Head + "-" + w61Proj + "-" + w61AllowTail }

// w61AllowlistFile is the full content string of <DataDir>/allowlist.json as
// the C7 store persists it. It is valid JSON, so when it appears as a JSON
// string value in a request body protocol.Walk marks it an Encoded parent leaf
// and drops its nested leaves from the terminal scan.
const w61AllowlistFile = `{"schema_version":1,"entries":["c7-kept-entry"]}`

// w61EchoUpstream records the request it received and echoes that whole body
// back inside a JSON response, so a client round trip proves the inbound
// never-backfill refusal.
type w61EchoUpstream struct {
	mu   sync.Mutex
	body []byte
}

func (u *w61EchoUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.body = body
	u.mu.Unlock()
	payload, err := json.Marshal(map[string]string{"echo": string(body)})
	if err != nil {
		http.Error(w, "encode echo", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}

func (u *w61EchoUpstream) received() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]byte(nil), u.body...)
}

// w61Pipeline builds the W6.1 test pipeline: a prefix detector whose allowlist
// names the control token (and a benign C7 value), and, when selfProtection is
// true, the frozen exclusion set wired through the W0.3 seam.
func w61Pipeline(t *testing.T, selfProtection bool) (*Pipeline, *redact.PlaceholderEngine) {
	t.Helper()
	engine := w45Engine(t)
	det := redact.NewPrefixDetector(redact.WithAllowlist(w61Token(), w61Allowlisted()))
	reg := w45Registry(t, det)
	cfg := PipelineConfig{Registry: reg, Engine: engine, Tool: "w6.1"}
	if selfProtection {
		cfg.SelfProtectionEnabled = true
		cfg.Exclusions = [][]byte{[]byte(w61AllowlistFile)}
		cfg.ControlToken = w61Token()
	}
	return w45Pipeline(t, cfg), engine
}

// w61HasEncodedLeaf reports whether the walk contains an Encoded parent whose
// decoded content is exactly want. The encoded-parent_ subtest uses it to prove
// the test data really lands in the shape the frozen match rule targets.
func w61HasEncodedLeaf(walked []protocol.Leaf, want string) bool {
	for _, leaf := range walked {
		if leaf.Encoded && leaf.Content == want {
			return true
		}
	}
	return false
}

// TestPipelineControlTokenNeverBackfilled is the W6.1 acceptance test: the C8
// narrow exclusion set (control token + <DataDir>/allowlist.json content) is
// force-redacted outbound before any detector or allowlist runs, and is never
// restored inbound, while C7 and the general F1 backfill boundary are intact.
func TestPipelineControlTokenNeverBackfilled(t *testing.T) {
	token := w61Token()
	other := w61Other()
	allowlisted := w61Allowlisted()
	fileContent := w61AllowlistFile

	// Non-vacuity for the "not exemptable" claim: without self-protection the
	// detector allowlist really does let the token through.
	t.Run("allowlist_would_suppress_without_self_protection", func(t *testing.T) {
		pipe, _ := w61Pipeline(t, false)
		body := []byte(fmt.Sprintf(`{"input":%q}`, "use "+token))
		out, err := pipe.RequestTransform()(body)
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		if !bytes.Contains(out, []byte(token)) {
			t.Fatalf("allowlist control: the token was redacted without self-protection, so the not-exemptable assertion would be vacuous: %s", out)
		}
		t.Logf("allowlist=[%s, %s] (the control token is an allowlist entry); without self-protection it survives: %s", token, allowlisted, out)
	})

	t.Run("allowlist_cannot_exempt_the_token", func(t *testing.T) {
		pipe, _ := w61Pipeline(t, true)
		body := []byte(fmt.Sprintf(`{"input":%q}`, "use "+token))
		out, err := pipe.RequestTransform()(body)
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		if bytes.Contains(out, []byte(token)) {
			t.Fatalf("the control token survived force-redaction even though the allowlist suppresses the detector: %s", out)
		}
		if !bytes.Contains(out, []byte(protocol.PlaceholderPrefix)) {
			t.Fatalf("force-redaction produced no placeholder: %s", out)
		}
		t.Logf("same allowlist entry present; with self-protection the token is force-redacted anyway: %s", out)
	})

	t.Run("encoded_parent_allowlist_file_is_force_redacted", func(t *testing.T) {
		pipe, _ := w61Pipeline(t, true)
		body, err := json.Marshal(map[string]any{"file": fileContent})
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		walked, err := protocol.Walk(body)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		if !w61HasEncodedLeaf(walked, fileContent) {
			t.Fatalf("test setup: the allowlist file is not an Encoded parent leaf: %+v", walked)
		}
		out, err := pipe.RequestTransform()(body)
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		if bytes.Contains(out, []byte(fileContent)) {
			t.Fatalf("the allowlist file content survived force-redaction: %s", out)
		}
		if bytes.Contains(out, []byte("c7-kept-entry")) {
			t.Fatalf("a nested leaf of the encoded allowlist file survived: %s", out)
		}
		if !bytes.Contains(out, []byte(protocol.PlaceholderPrefix)) {
			t.Fatalf("encoded parent was dropped instead of replaced: %s", out)
		}
	})

	t.Run("round_trip_hides_plaintext_and_never_restores", func(t *testing.T) {
		pipe, _ := w61Pipeline(t, true)

		upstream := &w61EchoUpstream{}
		upstreamServer := httptest.NewServer(upstream)
		t.Cleanup(upstreamServer.Close)
		srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstreamServer.URL, pipe)))
		t.Cleanup(srv.Close)

		body, err := json.Marshal(map[string]any{
			"model": "claude-test",
			"input": "token=" + token + " other=" + other + " allowed=" + allowlisted,
			"file":  fileContent,
		})
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}

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

		// (1) The model-visible content (the real captured upstream request)
		// carries no exclusion-set plaintext.
		for _, banned := range []string{token, fileContent, other} {
			if bytes.Contains(sent, []byte(banned)) {
				t.Fatalf("upstream request carried plaintext %q: %s", banned, sent)
			}
		}
		if !bytes.Contains(sent, []byte(protocol.PlaceholderPrefix)) {
			t.Fatalf("upstream received no placeholder at all: %s", sent)
		}

		// (2) C7 is unaffected: the allowlisted value is forwarded verbatim.
		if !bytes.Contains(sent, []byte(allowlisted)) {
			t.Fatalf("C7 regression: the allowlisted value did not pass through: %s", sent)
		}

		// (3) Never backfill: the client response still carries the exclusion
		// placeholders, never the token or the allowlist file content.
		if bytes.Contains(clientBody, []byte(token)) {
			t.Fatalf("client response restored the control token: %s", clientBody)
		}
		if bytes.Contains(clientBody, []byte(fileContent)) {
			t.Fatalf("client response restored the allowlist file content: %s", clientBody)
		}
		if !bytes.Contains(clientBody, []byte(protocol.PlaceholderPrefix)) {
			t.Fatalf("client response lost the exclusion placeholders entirely: %s", clientBody)
		}

		// (4) Boundary: a non-excluded secret keeps its byte-identical
		// redact-outbound / restore-inbound behaviour, and the allowlisted
		// value is unchanged.
		if !bytes.Contains(clientBody, []byte(other)) {
			t.Fatalf("client response lost a non-excluded secret (F1 boundary): %s", clientBody)
		}
		if !bytes.Contains(clientBody, []byte(allowlisted)) {
			t.Fatalf("client response lost the allowlisted value: %s", clientBody)
		}

		t.Logf("captured upstream request body: %s", sent)
		t.Logf("client response body: %s", clientBody)
	})
}
