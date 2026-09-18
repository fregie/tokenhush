// redact_request_test.go is the A2 acceptance suite for the outbound
// substitution path. It drives the REAL run gateway over a loopback echo
// upstream and asserts on captured bytes: the exact body the upstream received
// and the exact body the client got back. The PEM, quoted-keyword and
// JSON-in-JSON cases all fail without the decoded-span -> raw-span mapping,
// because JSON string escaping makes the decoded secret a non-substring of the
// raw body. The last case pins invariant 1: a body that already carries a
// session placeholder is forwarded intact, never backfilled.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/supply"
)

// redactLogPrefix is the frozen prefix of the redaction log line.
const redactLogPrefix = "tokenhush: redacted request"

// loggedBytes is a concurrency-safe capture writer for the gateway's stderr,
// which the serving goroutine writes while the test reads.
type loggedBytes struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write implements io.Writer.
func (l *loggedBytes) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// String returns the bytes captured so far.
func (l *loggedBytes) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// count returns how many times substr appears in the captured bytes.
func (l *loggedBytes) count(substr string) int { return strings.Count(l.String(), substr) }

// redactRule is a minimal third-party keyword rule that requests redaction of
// one runtime-chosen literal, so a test can redact a secret shape the built-in
// detectors cannot produce (one containing JSON metacharacters).
type redactRule struct {
	id      string
	trigger string
}

// ID returns the registered rule id.
func (r redactRule) ID() string { return r.id }

// Type returns the rule type the core records.
func (r redactRule) Type() string { return "keyword" }

// Category returns the finding category.
func (r redactRule) Category() string { return "custom" }

// Scope returns the request phase: only requests may substitute a placeholder.
func (r redactRule) Scope() filter.Scope { return filter.ScopeRequest }

// Action returns redact, the direction the rule requests.
func (r redactRule) Action() filter.Action { return filter.ActionRedact }

// Priority returns a priority below the built-ins.
func (r redactRule) Priority() int { return 10 }

// Confidence returns a confidence inside (0,1].
func (r redactRule) Confidence() float64 { return 0.9 }

// Inspect returns the trigger span inside leaf when it is present.
func (r redactRule) Inspect(leaf []byte) []filter.Span {
	at := bytes.Index(leaf, []byte(r.trigger))
	if at < 0 {
		return nil
	}
	return []filter.Span{{Start: at, End: at + len(r.trigger)}}
}

// redactGateway starts the real run server like e2eGateway, but keeps the
// gateway's stderr so the frozen redaction log can be counted. It returns the
// base URL, the captured stderr and the data directory (for the control token).
func redactGateway(t *testing.T, upstream *e2eUpstream, rules ...filter.Rule) (string, *loggedBytes, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")
	logs := &loggedBytes{}

	stop := make(chan struct{})
	seams := defaultRunSeams()
	seams.recoverRun = func(string) (supply.RecoveryResult, error) { return supply.RecoveryNone, nil }
	seams.loadConfig = func(string) (config.Config, error) {
		cfg := config.Default()
		cfg.Listen.Port = 0
		cfg.Upstreams = []config.Upstream{{Match: e2ePath, Target: upstream.server.URL}}
		return cfg, nil
	}
	seams.build = func(cfg config.Config, dir string, stderr io.Writer, logRedactions bool) (*gateway, error) {
		gw, err := buildGateway(cfg, dir, stderr, logRedactions)
		if err != nil {
			return nil, err
		}
		if err := injectTestRules(gw, cfg, rules); err != nil {
			return nil, err
		}
		return gw, nil
	}
	seams.notify = func(signals chan<- os.Signal) {
		<-stop
		signals <- syscall.SIGTERM
	}
	done := make(chan int, 1)
	go func() { done <- runWith(nil, logs, seams) }()
	t.Cleanup(func() {
		close(stop)
		if code := <-done; code != exitOK {
			t.Errorf("runWith = %d, want %d", code, exitOK)
		}
	})

	state := waitForSession(t, dataDir)
	base := fmt.Sprintf("http://127.0.0.1:%d", state.Port)
	e2eWaitReady(t, base)
	return base, logs, dataDir
}

// redactJSONBody builds a chat-completions body with json.Marshal, so JSON
// string escapes in content reach the wire exactly as a real client would send
// them.
func redactJSONBody(t *testing.T, content string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model":    "echo",
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return body
}

// TestRedactRequestSplicesRawSpans is the A2 falsification probe: each case
// sends a secret that JSON escaping hides from the raw spelling, and asserts
// on the upstream-received bytes and the client-bound bytes.
func TestRedactRequestSplicesRawSpans(t *testing.T) {
	upstream := newE2EUpstream(t)
	quoted := "tok-\"quoted\"-\\slash-" + e2eRandomHex(t, 4)
	base, logs, dataDir := redactGateway(t, upstream, redactRule{id: "test-quoted-redact", trigger: quoted})
	token := readControlToken(t, dataDir)

	t.Run("multi-line PEM is spliced at its raw span", func(t *testing.T) {
		pem := strings.Join([]string{
			"-----BEGIN PRIVATE KEY-----",
			"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
			"MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu",
			"NMoSfRZaYDapmCaQsGc6l9C1Cbh5zFvWqK4eS1R5KqZ1F9C0S3o2Rk=",
			"-----END PRIVATE KEY-----",
		}, "\n")
		body := redactJSONBody(t, "please use this key:\n"+pem+"\nthanks")
		if bytes.Contains(body, []byte("\n")) {
			t.Fatalf("the PEM newlines are not JSON-escaped in the request body: %s", body)
		}

		redactionsBefore := readLiveCounters(t, base, token).Redactions
		logsBefore := logs.count(redactLogPrefix)
		status, got := e2ePost(t, base+e2ePath, body, nil)
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		if bytes.Contains(sent, []byte("BEGIN PRIVATE KEY")) {
			t.Errorf("the private key left the process (falsification): %s", sent)
		}
		if !bytes.Contains(sent, []byte("__PII_private_key_")) {
			t.Errorf("no private_key placeholder reached the upstream: %s", sent)
		}
		if delta := readLiveCounters(t, base, token).Redactions - redactionsBefore; delta != 1 {
			t.Errorf("redactions moved by %d, want exactly 1", delta)
		}
		if delta := logs.count(redactLogPrefix) - logsBefore; delta != 1 {
			t.Errorf("frozen log lines emitted = %d, want exactly 1 (stderr: %s)", delta, logs.String())
		}
		if !strings.Contains(logs.String(), redactLogPrefix+" private_key (len=") {
			t.Errorf("the frozen log line does not name the category and length: %s", logs.String())
		}
		if !bytes.Contains(got, []byte(pem)) {
			t.Errorf("the private key did not return to the client: %s", got)
		}
	})

	t.Run("a quoted secret is redacted upstream and restored client-bound", func(t *testing.T) {
		escaped, err := json.Marshal(quoted)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		escaped = escaped[1 : len(escaped)-1]
		status, got := e2ePost(t, base+e2ePath, redactJSONBody(t, "the literal "+quoted+" end"), nil)
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		if bytes.Contains(sent, escaped) {
			t.Errorf("the quoted secret reached the upstream: %s", sent)
		}
		if !bytes.Contains(sent, []byte("__PII_custom_")) {
			t.Errorf("no custom placeholder reached the upstream: %s", sent)
		}
		if !bytes.Contains(got, []byte(quoted)) {
			t.Errorf("the quoted secret did not return to the client: %s", got)
		}
	})

	t.Run("a secret inside a JSON-in-JSON wrapper is redacted", func(t *testing.T) {
		inner := `{"note":"the literal ` + quoted + ` end"}`
		body := redactJSONBody(t, inner)
		if !bytes.Contains(body, []byte(`\"note\"`)) {
			t.Fatalf("the inner JSON is not recursively encoded: %s", body)
		}
		status, got := e2ePost(t, base+e2ePath, body, nil)
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		if bytes.Contains(sent, []byte("tok-")) {
			t.Errorf("the wrapped quoted secret reached the upstream: %s", sent)
		}
		if !bytes.Contains(sent, []byte("__PII_custom_")) {
			t.Errorf("no custom placeholder reached the upstream: %s", sent)
		}
		if !json.Valid(sent) {
			t.Errorf("the splice broke the wrapper JSON: %s", sent)
		}
		if !bytes.Contains(got, []byte(quoted)) {
			t.Errorf("the wrapped secret did not return to the client: %s", got)
		}
	})

	t.Run("a body carrying a session placeholder is forwarded intact", func(t *testing.T) {
		secret := e2eSecret(t)
		if status, got := e2ePost(t, base+e2ePath, e2eBody("mail "+secret), nil); status != http.StatusOK {
			t.Fatalf("first POST = %d, want 200 (body %s)", status, got)
		}
		placeholder := e2ePlaceholder.Find(upstream.recorded())
		if placeholder == nil {
			t.Fatalf("the first request minted no placeholder: %s", upstream.recorded())
		}
		status, got := e2ePost(t, base+e2ePath, e2eBody("note "+string(placeholder)+" here"), nil)
		if status != http.StatusOK {
			t.Fatalf("second POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		if !bytes.Contains(sent, placeholder) {
			t.Errorf("the known placeholder was not forwarded intact: %s", sent)
		}
		if bytes.Contains(sent, []byte(secret)) {
			t.Errorf("the outbound path backfilled the placeholder into its secret: %s", sent)
		}
		if !bytes.Contains(got, []byte(secret)) {
			t.Errorf("the placeholder was not restored on the client-bound path: %s", got)
		}
	})
}
