package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/supply"
)

// runRecorder records the seam invocations of one runWith call, so the startup
// order is asserted on real observations rather than on a comment.
type runRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *runRecorder) add(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *runRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// quietConfigLoader returns the default config with an ephemeral port, so a
// test never depends on a real config file or a fixed port.
func quietConfigLoader(recorder *runRecorder, name string) func(string) (config.Config, error) {
	return func(string) (config.Config, error) {
		recorder.add(name)
		cfg := config.Default()
		cfg.Listen.Port = 0
		return cfg, nil
	}
}

// immediateStop signals a clean shutdown as soon as serving starts.
func immediateStop(recorder *runRecorder, name string) func(chan<- os.Signal) {
	return func(stop chan<- os.Signal) {
		recorder.add(name)
		stop <- syscall.SIGTERM
	}
}

// TestRunStartupOrderAndCleanShutdown pins the frozen startup order: crash
// recovery first (before any update or rules state is read), then config,
// pipeline build, bind, session files and serve. It also proves the session
// files exist while serving and are removed by a clean shutdown.
func TestRunStartupOrderAndCleanShutdown(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")

	recorder := &runRecorder{}
	seams := defaultRunSeams()
	seams.recoverRun = func(target string) (supply.RecoveryResult, error) {
		if target == "" {
			t.Error("recoverRun received an empty target")
		}
		recorder.add("recover")
		return supply.RecoveryNone, nil
	}
	seams.loadConfig = quietConfigLoader(recorder, "config")
	seams.build = func(cfg config.Config, dir string, stderr io.Writer, logRedactions bool) (*gateway, error) {
		recorder.add("build")
		if dir != dataDir {
			t.Errorf("build data dir = %q, want %q", dir, dataDir)
		}
		return buildGateway(cfg, dir, stderr, logRedactions)
	}
	seams.listen = func(host string, port int) (net.Listener, string, error) {
		recorder.add("listen")
		listener, addr, err := proxy.Listen(host, 0)
		if err != nil {
			return nil, "", err
		}
		if _, err := os.Stat(filepath.Join(dataDir, "run.json")); err == nil {
			t.Error("run.json appeared before the listener was bound")
		}
		return listener, addr, nil
	}
	seams.notify = func(stop chan<- os.Signal) {
		recorder.add("serve")
		for _, name := range []string{"run.json", "control.token"} {
			if _, err := os.Stat(filepath.Join(dataDir, name)); err != nil {
				t.Errorf("%s is not present while serving: %v", name, err)
			}
		}
		state, err := proxy.ReadSession(dataDir)
		if err != nil {
			t.Errorf("ReadSession while serving: %v", err)
		} else if state.Port == 0 {
			t.Error("run.json carries port 0 while serving")
		}
		if token, err := os.ReadFile(filepath.Join(dataDir, "control.token")); err != nil || len(token) == 0 {
			t.Errorf("control.token is missing or empty while serving (err %v)", err)
		}
		stop <- syscall.SIGTERM
	}

	if code := runWith(nil, io.Discard, seams); code != exitOK {
		t.Fatalf("runWith = %d, want %d", code, exitOK)
	}
	want := []string{"recover", "config", "build", "listen", "serve"}
	if got := recorder.snapshot(); !equalStrings(got, want) {
		t.Fatalf("startup order = %v, want %v", got, want)
	}
	for _, name := range []string{"run.json", "control.token"} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s survived a clean shutdown (err %v)", name, err)
		}
	}
}

// TestRunBusyPortWritesNoSessionFiles occupies the configured port first and
// proves the run fails fast with exit 1, leaving a pre-existing stale run.json
// byte-identical and no control.token behind.
func TestRunBusyPortWritesNoSessionFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	stale := []byte("{\"pid\":1}\n")
	stalePath := filepath.Join(dataDir, "run.json")
	if err := os.WriteFile(stalePath, stale, 0o600); err != nil {
		t.Fatalf("write stale run.json: %v", err)
	}

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	_, portText, err := net.SplitHostPort(occupied.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	busyPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	seams := defaultRunSeams()
	seams.recoverRun = func(string) (supply.RecoveryResult, error) { return supply.RecoveryNone, nil }
	seams.loadConfig = func(string) (config.Config, error) {
		cfg := config.Default()
		cfg.Listen.Port = busyPort
		return cfg, nil
	}
	var stderr bytes.Buffer
	if code := runWith(nil, &stderr, seams); code != exitFailure {
		t.Fatalf("runWith = %d, want %d (stderr %q)", code, exitFailure, stderr.String())
	}
	if !strings.Contains(stderr.String(), "listen") {
		t.Errorf("stderr = %q, want it to name the listen failure", stderr.String())
	}
	got, err := os.ReadFile(stalePath)
	if err != nil {
		t.Fatalf("stale run.json disappeared: %v", err)
	}
	if !bytes.Equal(got, stale) {
		t.Errorf("stale run.json was rewritten: %q, want %q", got, stale)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "control.token")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a control.token was written despite the busy port (err %v)", err)
	}
}

// TestRunFlagsOverrideConfig pins that every run flag wins over the loaded
// config and that the config path flag selects the loaded file.
func TestRunFlagsOverrideConfig(t *testing.T) {
	recorder := &runRecorder{}
	seams := defaultRunSeams()
	seams.recoverRun = func(string) (supply.RecoveryResult, error) { return supply.RecoveryNone, nil }
	seams.loadConfig = func(path string) (config.Config, error) {
		recorder.add("config:" + path)
		cfg := config.Default()
		cfg.Listen.Port = 1111
		cfg.Log.Level = "warn"
		return cfg, nil
	}
	seams.build = func(cfg config.Config, dir string, stderr io.Writer, logRedactions bool) (*gateway, error) {
		recorder.add(fmt.Sprintf("build:%s:%d:%v", cfg.Log.Level, cfg.Listen.Port, logRedactions))
		return buildGateway(cfg, dir, stderr, logRedactions)
	}
	seams.listen = func(host string, port int) (net.Listener, string, error) {
		recorder.add(fmt.Sprintf("listen:%s:%d", host, port))
		return proxy.Listen(host, 0)
	}
	seams.notify = immediateStop(recorder, "serve")

	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	args := []string{"--config", "/custom/tokenhush.yaml", "--port", "2222", "--log-level", "debug", "--log-redactions=false"}
	if code := runWith(args, io.Discard, seams); code != exitOK {
		t.Fatalf("runWith = %d, want %d", code, exitOK)
	}
	want := []string{"config:/custom/tokenhush.yaml", "build:debug:2222:false", "listen:127.0.0.1:2222", "serve"}
	if got := recorder.snapshot(); !equalStrings(got, want) {
		t.Fatalf("flag resolution = %v, want %v", got, want)
	}
}

// TestRunUsageErrorsTouchNothing pins that an unknown flag, a bad flag value
// and a positional argument are exit-2 usage errors raised before any seam
// runs.
func TestRunUsageErrorsTouchNothing(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"--nope"}},
		{"non-numeric port", []string{"--port", "abc"}},
		{"out-of-range port", []string{"--port", "70000"}},
		{"unknown log level", []string{"--log-level", "verbose"}},
		{"extra argument", []string{"serve"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &runRecorder{}
			seams := defaultRunSeams()
			seams.recoverRun = func(string) (supply.RecoveryResult, error) {
				recorder.add("recover")
				return supply.RecoveryNone, nil
			}
			var stderr bytes.Buffer
			if code := runWith(tc.args, &stderr, seams); code != exitUsage {
				t.Fatalf("runWith(%v) = %d, want %d", tc.args, code, exitUsage)
			}
			if got := recorder.snapshot(); len(got) != 0 {
				t.Fatalf("a usage error ran seams: %v", got)
			}
		})
	}
}

// TestRunRecoveryFailureStopsTheStartup pins D13: a failed crash recovery is a
// hard failure and nothing after it runs.
func TestRunRecoveryFailureStopsTheStartup(t *testing.T) {
	seams := defaultRunSeams()
	seams.recoverRun = func(string) (supply.RecoveryResult, error) {
		return supply.RecoveryNone, errors.New("journal unreadable")
	}
	seams.loadConfig = func(string) (config.Config, error) {
		t.Fatal("config was loaded after a failed recovery")
		return config.Config{}, nil
	}
	var stderr bytes.Buffer
	if code := runWith(nil, &stderr, seams); code != exitFailure {
		t.Fatalf("runWith = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "crash recovery") {
		t.Errorf("stderr = %q, want it to name the recovery failure", stderr.String())
	}
}

// TestRunServesStatusAndShutsDownCleanly is the run-level happy path: the real
// gateway starts, GET /status answers the proxy-owned metadata with the session
// token, an unauthenticated call is refused, and the shutdown removes both
// session files.
func TestRunServesStatusAndShutsDownCleanly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TOKENHUSH_HOME", home)
	dataDir := filepath.Join(home, "data")

	stop := make(chan struct{})
	seams := defaultRunSeams()
	seams.recoverRun = func(string) (supply.RecoveryResult, error) { return supply.RecoveryNone, nil }
	seams.loadConfig = func(string) (config.Config, error) {
		cfg := config.Default()
		cfg.Listen.Port = 0
		return cfg, nil
	}
	seams.notify = func(signals chan<- os.Signal) {
		<-stop
		signals <- syscall.SIGTERM
	}
	done := make(chan int, 1)
	go func() { done <- runWith(nil, io.Discard, seams) }()

	state := waitForSession(t, dataDir)
	token := readControlToken(t, dataDir)
	statusURL := fmt.Sprintf("http://127.0.0.1:%d/status", state.Port)

	request, err := http.NewRequest(http.MethodGet, statusURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read /status: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /status = %d, want 200 (body %s)", response.StatusCode, body)
	}
	for _, key := range []string{`"state":"running"`, `"requests":`, `"redactions":`, `"walk_skips":`} {
		if !strings.Contains(string(body), key) {
			t.Errorf("GET /status body %s is missing %s", body, key)
		}
	}

	unauthenticated, err := http.Get(statusURL)
	if err != nil {
		t.Fatalf("unauthenticated GET /status: %v", err)
	}
	_ = unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /status = %d, want 401", unauthenticated.StatusCode)
	}

	close(stop)
	if code := <-done; code != exitOK {
		t.Fatalf("runWith = %d, want %d", code, exitOK)
	}
	for _, name := range []string{"run.json", "control.token"} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s survived the clean shutdown (err %v)", name, err)
		}
	}
}

// TestRedactionLogGoesToStderrInTheFrozenFormat drives the real transform: the
// secret must leave as a placeholder, the reverse mapping must restore it, and
// the log line must match the frozen format on stderr only.
func TestRedactionLogGoesToStderrInTheFrozenFormat(t *testing.T) {
	secret := "sk-" + strings.Repeat("Ab3", 14)
	body := []byte(`{"messages":[{"role":"user","content":"` + secret + `"}]}`)

	var stderr bytes.Buffer
	gateway, err := buildGateway(config.Default(), t.TempDir(), &stderr, true)
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}
	redacted, substitutions, err := gateway.redactRequest(body)
	if err != nil {
		t.Fatalf("redactRequest: %v", err)
	}
	if substitutions != 1 {
		t.Errorf("redactRequest applied %d substitutions, want 1", substitutions)
	}
	if bytes.Contains(redacted, []byte(secret)) {
		t.Fatalf("the secret survived the outbound transform: %s", redacted)
	}
	if !bytes.Contains(redacted, []byte("__PII_api_key_")) {
		t.Fatalf("no placeholder was minted: %s", redacted)
	}
	runes := []rune(secret)
	want := fmt.Sprintf("tokenhush: redacted request api_key (len=%d) %s\n", len(secret), string(runes[:4])+"…"+string(runes[len(runes)-2:]))
	if got := stderr.String(); got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if restored := gateway.backfiller.Backfill(redacted); !bytes.Equal(restored, body) {
		t.Errorf("backfill = %q, want the original body %q", restored, body)
	}
}

// TestRedactionLogIsSilencedByFlag pins that --log-redactions=false removes the
// line without changing the substitution.
func TestRedactionLogIsSilencedByFlag(t *testing.T) {
	secret := "sk-" + strings.Repeat("Zz9", 14)
	body := []byte(`{"content":"` + secret + `"}`)
	var stderr bytes.Buffer
	gateway, err := buildGateway(config.Default(), t.TempDir(), &stderr, false)
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}
	redacted, _, err := gateway.redactRequest(body)
	if err != nil {
		t.Fatalf("redactRequest: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing with the log disabled", stderr.String())
	}
	if bytes.Contains(redacted, []byte(secret)) {
		t.Fatalf("the secret survived with the log disabled: %s", redacted)
	}
}

// TestMaskSecretNeverRevealsTheValue pins the two masking classes.
func TestMaskSecretNeverRevealsTheValue(t *testing.T) {
	secret := "sk-" + strings.Repeat("Ab3", 14)
	masked := maskSecret(secret, "api_key")
	if masked == secret || strings.Contains(masked, secret) {
		t.Fatalf("maskSecret(%q) = %q leaks the value", secret, masked)
	}
	if masked != "sk-A…b3" {
		t.Fatalf("maskSecret(%q, api_key) = %q, want sk-A…b3", secret, masked)
	}
	if got := maskSecret("alice@example.com", "email"); got != "****" {
		t.Fatalf("maskSecret(email) = %q, want ****", got)
	}
}

// waitForSession polls until both session files the run command writes before
// it serves exist, and fails the test when they never appear. run.json is
// written first, so a reader must wait for the token too before using them.
func waitForSession(t *testing.T, dataDir string) proxy.RunState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := proxy.ReadSession(dataDir)
		if err == nil && state.Port != 0 {
			if _, err := os.Stat(filepath.Join(dataDir, "control.token")); err == nil {
				return state
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the session files never appeared under %s", dataDir)
	return proxy.RunState{}
}

// readControlToken reads the session control token, trimming the trailing
// newline the session writer appends.
func readControlToken(t *testing.T, dataDir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dataDir, "control.token"))
	if err != nil {
		t.Fatalf("read control.token: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// equalStrings compares two string slices element by element.
func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
