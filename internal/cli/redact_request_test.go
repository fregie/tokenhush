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
	return redactGatewayTuned(t, upstream, nil, rules...)
}

// redactGatewayTuned is redactGateway with one config tuning hook: a test can
// pin a small scan budget (or any other config field) through the same run
// seams, so the budget path is exercised end to end rather than unit-mocked.
func redactGatewayTuned(t *testing.T, upstream *e2eUpstream, tune func(*config.Config), rules ...filter.Rule) (string, *loggedBytes, string) {
	t.Helper()
	return redactGatewaySeam(t, upstream, tune, func(*gateway) []filter.Rule { return rules })
}

// redactGatewaySeam starts the gateway with a build-time rules hook that sees
// the assembled gateway, so a test can inject a rule over a value only the
// built gateway knows (the session control token).
func redactGatewaySeam(t *testing.T, upstream *e2eUpstream, tune func(*config.Config), rules func(*gateway) []filter.Rule) (string, *loggedBytes, string) {
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
		if tune != nil {
			tune(&cfg)
		}
		return cfg, nil
	}
	seams.build = func(cfg config.Config, dir string, stderr io.Writer, logRedactions bool) (*gateway, error) {
		gw, err := buildGateway(cfg, dir, stderr, logRedactions)
		if err != nil {
			return nil, err
		}
		if err := injectTestRules(gw, cfg, rules(gw)); err != nil {
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

// redactClientContent decodes the client-bound echo of a chat-completions
// request and returns its content value. The escape/depth-aware restore must
// leave a valid JSON document whose decoded content is the original text, so
// every client assertion goes through this helper instead of raw byte
// containment, which a control byte or quote escape would hide.
func redactClientContent(t *testing.T, body []byte) string {
	t.Helper()
	if !json.Valid(body) {
		t.Fatalf("the client body is not valid JSON: %s", body)
	}
	var doc struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal the client body: %v", err)
	}
	if len(doc.Messages) != 1 {
		t.Fatalf("the client body carries %d messages, want 1: %s", len(doc.Messages), body)
	}
	return doc.Messages[0].Content
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
		content := redactClientContent(t, got)
		if want := "please use this key:\n" + pem + "\nthanks"; content != want {
			t.Errorf("the restored client content = %q, want the original text %q", content, want)
		}
		if !strings.Contains(content, pem) {
			t.Errorf("the PEM did not return with its real newlines: %q", content)
		}
		if bytes.Contains(got, []byte("__PII_")) {
			t.Errorf("a placeholder reached the client: %s", got)
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
		content := redactClientContent(t, got)
		if want := "the literal " + quoted + " end"; content != want {
			t.Errorf("the restored client content = %q, want the original text %q", content, want)
		}
		if bytes.Contains(got, []byte("__PII_")) {
			t.Errorf("a placeholder reached the client: %s", got)
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
		if !json.Valid(got) {
			t.Fatalf("the client body is not valid JSON: %s", got)
		}
		decoded := redactClientContent(t, got)
		if !json.Valid([]byte(decoded)) {
			t.Fatalf("the decoded inner JSON is not valid JSON: %q", decoded)
		}
		var note struct {
			Note string `json:"note"`
		}
		if err := json.Unmarshal([]byte(decoded), &note); err != nil {
			t.Fatalf("unmarshal the inner JSON: %v", err)
		}
		if want := "the literal " + quoted + " end"; note.Note != want {
			t.Errorf("the inner note = %q, want the original text %q", note.Note, want)
		}
		if bytes.Contains(got, []byte("__PII_")) {
			t.Errorf("a placeholder reached the client: %s", got)
		}
	})

	t.Run("a markdown body keeps its real newlines in the client JSON", func(t *testing.T) {
		markdown := "# Local development\n\nSet the key before running the agent:\n\n```sh\n" +
			"export OPENAI_API_KEY=sk-AbCdEfGhIjKlMnOpQrStUvWx\n```\n\n" +
			"Or use the shared account dev@example.com.\n"
		body := redactJSONBody(t, markdown)
		status, got := e2ePost(t, base+e2ePath, body, nil)
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		if bytes.Contains(sent, []byte("sk-AbCdEfGhIjKlMnOpQrStUvWx")) {
			t.Errorf("the API key reached the upstream: %s", sent)
		}
		if !bytes.Contains(sent, []byte("__PII_api_key_")) {
			t.Errorf("no api_key placeholder reached the upstream: %s", sent)
		}
		content := redactClientContent(t, got)
		if content != markdown {
			t.Errorf("the restored markdown = %q, want the original %q", content, markdown)
		}
		if want := strings.Count(markdown, "\n"); strings.Count(content, "\n") != want {
			t.Errorf("the restored markdown has %d real newlines, want %d", strings.Count(content, "\n"), want)
		}
		if bytes.Contains(got, []byte("__PII_")) {
			t.Errorf("a placeholder reached the client: %s", got)
		}
	})

	t.Run("a non-JSON text/plain body restores the raw secret byte-identically", func(t *testing.T) {
		if status, got := e2ePost(t, base+e2ePath, redactJSONBody(t, "the literal "+quoted+" end"), nil); status != http.StatusOK {
			t.Fatalf("mint POST = %d, want 200 (body %s)", status, got)
		}
		placeholder := e2ePlaceholder.Find(upstream.recorded())
		if placeholder == nil {
			t.Fatalf("the mint request carried no placeholder: %s", upstream.recorded())
		}
		raw := []byte("the literal " + string(placeholder) + " end")
		status, got := e2ePost(t, base+e2ePath, raw, map[string]string{"Content-Type": "text/plain"})
		if status != http.StatusOK {
			t.Fatalf("text/plain POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		if !bytes.Contains(sent, placeholder) {
			t.Errorf("the known placeholder was not forwarded intact: %s", sent)
		}
		if bytes.Contains(sent, []byte(quoted)) {
			t.Errorf("the outbound path backfilled the placeholder into its secret: %s", sent)
		}
		want := bytes.ReplaceAll(raw, placeholder, []byte(quoted))
		if !bytes.Equal(got, want) {
			t.Errorf("the raw text/plain restore = %q, want the raw splice %q", got, want)
		}
		if !bytes.Contains(got, []byte(quoted)) {
			t.Errorf("the raw secret did not return to the client: %s", got)
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
		request := e2eBody("note " + string(placeholder) + " here")
		want := bytes.ReplaceAll(request, placeholder, []byte(secret))
		status, got := e2ePost(t, base+e2ePath, request, nil)
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
		if !bytes.Equal(got, want) {
			t.Errorf("the placeholder was not restored to its original spelling: got %q, want %q", got, want)
		}
		if !json.Valid(got) {
			t.Errorf("the restored client body is not valid JSON: %s", got)
		}
		againStatus, again := e2ePost(t, base+e2ePath, request, nil)
		if againStatus != http.StatusOK {
			t.Fatalf("third POST = %d, want 200 (body %s)", againStatus, again)
		}
		if !bytes.Equal(again, got) {
			t.Errorf("a repeated turn is not stable: %q vs %q", again, got)
		}
	})
}

// TestRedactRequestExcludedControlTokenIsNotRestored pins the W2.3 exclusion
// end to end: a request carrying the session control token (a value the session
// backfiller excludes) is redacted upstream, but the placeholder is never
// expanded back on the client-bound path, so neither direction carries the
// session credential.
func TestRedactRequestExcludedControlTokenIsNotRestored(t *testing.T) {
	upstream := newE2EUpstream(t)
	base, _, dataDir := redactGatewaySeam(t, upstream, nil, func(gw *gateway) []filter.Rule {
		return []filter.Rule{redactRule{id: "test-control-token-redact", trigger: gw.token.String()}}
	})
	token := readControlToken(t, dataDir)

	body := redactJSONBody(t, "session token "+token+" end")
	status, got := e2ePost(t, base+e2ePath, body, nil)
	if status != http.StatusOK {
		t.Fatalf("POST = %d, want 200 (body %s)", status, got)
	}
	sent := upstream.recorded()
	if bytes.Contains(sent, []byte(token)) {
		t.Errorf("the excluded control token reached the upstream: %s", sent)
	}
	placeholder := e2ePlaceholder.Find(sent)
	if placeholder == nil {
		t.Fatalf("the request minted no placeholder for the token: %s", sent)
	}
	if !bytes.Equal(got, sent) {
		t.Errorf("the excluded placeholder body changed: got %s, want the upstream echo %s", got, sent)
	}
	if !bytes.Contains(got, placeholder) {
		t.Errorf("the excluded placeholder was consumed: the client body must keep it: %s", got)
	}
	if bytes.Contains(got, []byte(token)) {
		t.Errorf("the excluded control token reached the client: %s", got)
	}
	if !json.Valid(got) {
		t.Errorf("the client body is not valid JSON: %s", got)
	}
}
