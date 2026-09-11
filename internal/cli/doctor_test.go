package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// doctorTestStore is a hermetic platform.SecretStore whose only observable
// behavior is the backend label doctor reports.
type doctorTestStore struct{ backend string }

func (s doctorTestStore) Get(string, string) (string, error) { return "", platform.ErrNotFound }
func (s doctorTestStore) Set(string, string, string) error   { return nil }
func (s doctorTestStore) Delete(string, string) error        { return platform.ErrNotFound }
func (s doctorTestStore) Backend() string {
	if s.backend == "" {
		return platform.BackendKeyring
	}
	return s.backend
}

// doctorNopCloser stands in for a released proxy.Listeners in injected checks.
type doctorNopCloser struct{}

func (doctorNopCloser) Close() error { return nil }

// realDoctorListen is the production proxy.Listen adapter used by tests that
// want real dual-stack binds.
func realDoctorListen(host string, port int) (io.Closer, error) {
	ls, err := proxy.Listen(host, port)
	if err != nil {
		return nil, err
	}
	return ls, nil
}

// doctorTestDeps is a fully injected, hermetic dependency set: temp config/data
// directories, defaults config, a keyring-labeled store, no tools installed and
// an empty environment.
func doctorTestDeps(t *testing.T, stdout, stderr io.Writer) doctorDeps {
	t.Helper()
	home := t.TempDir()
	deps := defaultDoctorDeps(stdout, stderr)
	deps.configDir = func() (string, error) { return filepath.Join(home, "config"), nil }
	deps.dataDir = func() (string, error) { return filepath.Join(home, "data"), nil }
	deps.loadConfig = func(string) (*config.Config, error) {
		cfg := config.Default()
		return &cfg, nil
	}
	deps.openStore = func() (platform.SecretStore, error) { return doctorTestStore{}, nil }
	deps.listen = func(string, int) (io.Closer, error) { return doctorNopCloser{}, nil }
	deps.getenv = func(string) string { return "" }
	deps.lookPath = func(string) (string, error) { return "", errors.New("not found") }
	deps.userHomeDir = func() (string, error) { return home, nil }
	return deps
}

// runDoctorCommand drives doctorCommandWith with the hermetic dependency set;
// tweak may override individual seams.
func runDoctorCommand(t *testing.T, args []string, tweak func(*doctorDeps)) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = doctorCommandWith(args, &out, &errBuf, func(d *doctorDeps) {
		*d = doctorTestDeps(t, &out, &errBuf)
		if tweak != nil {
			tweak(d)
		}
	})
	return code, out.String(), errBuf.String()
}

// doctorFindCheck returns the named check from a parsed report.
func doctorFindCheck(t *testing.T, report DoctorReport, name string) DoctorCheck {
	t.Helper()
	for _, c := range report.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q missing from report: %+v", name, report.Checks)
	return DoctorCheck{}
}

// parseDoctorJSON decodes a --json run and fails on non-JSON output.
func parseDoctorJSON(t *testing.T, stdout string) DoctorReport {
	t.Helper()
	var report DoctorReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("doctor --json is not valid JSON: %v\noutput:\n%s", err, stdout)
	}
	return report
}

func TestDoctorHappyPath(t *testing.T) {
	var configDir, dataDir string
	code, stdout, stderr := runDoctorCommand(t, nil, func(d *doctorDeps) {
		configDir = filepath.Join(t.TempDir(), "config")
		dataDir = filepath.Join(t.TempDir(), "data")
		d.configDir = func() (string, error) { return configDir, nil }
		d.dataDir = func() (string, error) { return dataDir, nil }
	})

	if code != ExitOK {
		t.Fatalf("doctor exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, ExitOK, stdout, stderr)
	}
	for _, want := range []string{
		"tokenhush doctor (", "shell: ",
		"[ok]   config-dir", "[ok]   data-dir", "writable",
		"[ok]   secret-store", "backend keyring",
		"[ok]   loopback", "127.0.0.1 and [::1] bindable",
		"[ok]   port", "127.0.0.1:8787 and [::1]:8787 available",
		"not detected (skipped)",
		"0 failure(s)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "critical problems found") {
		t.Errorf("happy path must not report critical problems:\n%s", stdout)
	}
	// Repair path: doctor creates both directories.
	for _, dir := range []string{configDir, dataDir} {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Errorf("doctor did not create %s: %v", dir, err)
		}
	}
}

func TestDoctorJSONReport(t *testing.T) {
	code, stdout, stderr := runDoctorCommand(t, []string{"--json"}, nil)
	if code != ExitOK {
		t.Fatalf("doctor --json exit = %d, want %d\nstderr:\n%s", code, ExitOK, stderr)
	}
	if strings.Contains(stdout, "tokenhush doctor (") || strings.Contains(stdout, "failure(s)") {
		t.Errorf("--json stdout must be pure JSON:\n%s", stdout)
	}
	report := parseDoctorJSON(t, stdout)
	if !report.OK || report.Status != doctorOK || report.Exit != ExitOK {
		t.Errorf("report ok/status/exit = %v/%q/%d, want true/ok/0", report.OK, report.Status, report.Exit)
	}
	if report.OS != runtime.GOOS || report.Arch != runtime.GOARCH {
		t.Errorf("report os/arch = %s/%s, want %s/%s", report.OS, report.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if report.Shell == "" || report.Port != 8787 {
		t.Errorf("report shell/port = %q/%d, want non-empty/8787", report.Shell, report.Port)
	}
	for _, name := range []string{doctorCheckConfig, doctorCheckConfigDir, doctorCheckDataDir, doctorCheckSecrets, doctorCheckLoopback, doctorCheckPort, doctorCheckProxyEnv} {
		check := doctorFindCheck(t, report, name)
		if check.Status != doctorOK {
			t.Errorf("check %q status = %q, want ok (%s)", name, check.Status, check.Message)
		}
		if check.Message == "" {
			t.Errorf("check %q has an empty message", name)
		}
	}
}

func TestDoctorPlaintextFallbackFailsLoudly(t *testing.T) {
	tweak := func(d *doctorDeps) {
		d.openStore = func() (platform.SecretStore, error) {
			return doctorTestStore{backend: platform.BackendFilePlaintext}, nil
		}
	}

	code, stdout, stderr := runDoctorCommand(t, nil, tweak)
	if code != ExitFailure {
		t.Fatalf("plaintext fallback exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, ExitFailure, stdout, stderr)
	}
	t.Logf("keyring-absent/plaintext world: exit=%d, marker present=%v\n%s",
		code, strings.Contains(stdout, platform.PlaintextWarningMarker), stdout)
	for _, want := range []string{
		platform.PlaintextWarningMarker,
		"[fail] secret-store",
		"[fail]",
		"1 failure(s)",
		"critical problems found",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}

	code, stdout, _ = runDoctorCommand(t, []string{"--json"}, tweak)
	if code != ExitFailure {
		t.Fatalf("plaintext fallback --json exit = %d, want %d", code, ExitFailure)
	}
	report := parseDoctorJSON(t, stdout)
	if report.OK || report.Status != doctorFail || report.Exit != ExitFailure {
		t.Errorf("report ok/status/exit = %v/%q/%d, want false/fail/1", report.OK, report.Status, report.Exit)
	}
	check := doctorFindCheck(t, report, doctorCheckSecrets)
	if check.Status != doctorFail || !strings.Contains(check.Message, platform.PlaintextWarningMarker) {
		t.Errorf("secret-store check = %+v, want fail carrying the plaintext marker", check)
	}
	if check.Fix == "" {
		t.Error("plaintext fallback must carry a repair hint")
	}
	t.Logf("plaintext --json check: status=%s message=%q fix=%q exit=%d",
		check.Status, check.Message, check.Fix, report.Exit)
}

func TestDoctorNoSecretBackend(t *testing.T) {
	code, stdout, _ := runDoctorCommand(t, nil, func(d *doctorDeps) {
		d.openStore = func() (platform.SecretStore, error) { return nil, platform.ErrNoSecretBackend }
	})
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stdout, "no usable secret store") {
		t.Errorf("stdout missing the secret-store failure:\n%s", stdout)
	}
}

func TestDoctorUnwritableDataDir(t *testing.T) {
	code, stdout, _ := runDoctorCommand(t, nil, func(d *doctorDeps) {
		d.probeDir = func(dir string) error {
			if strings.HasSuffix(dir, "data") {
				return errors.New("mkdir ignored: permission denied (injected)")
			}
			return nil
		}
	})
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s", code, ExitFailure, stdout)
	}
	if !strings.Contains(stdout, "[fail] data-dir") || !strings.Contains(stdout, "is not writable") {
		t.Errorf("stdout missing the data-dir failure:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[ok]   config-dir") {
		t.Errorf("config-dir must stay ok:\n%s", stdout)
	}
}

func TestDoctorUnresolvablePath(t *testing.T) {
	code, stdout, _ := runDoctorCommand(t, nil, func(d *doctorDeps) {
		d.configDir = func() (string, error) { return "", platform.ErrPathUnavailable }
	})
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stdout, "[fail] config-dir") || !strings.Contains(stdout, "cannot resolve") {
		t.Errorf("stdout missing the resolution failure:\n%s", stdout)
	}
}

func TestDoctorInvalidConfigSkipsPortChecks(t *testing.T) {
	code, stdout, _ := runDoctorCommand(t, []string{"--json"}, func(d *doctorDeps) {
		d.loadConfig = func(string) (*config.Config, error) {
			return nil, errors.New("yaml: unknown field")
		}
	})
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d", code, ExitFailure)
	}
	report := parseDoctorJSON(t, stdout)
	if check := doctorFindCheck(t, report, doctorCheckConfig); check.Status != doctorFail {
		t.Errorf("config check = %+v, want fail", check)
	}
	for _, name := range []string{doctorCheckPort, doctorCheckLoopback, doctorCheckProxyEnv} {
		for _, c := range report.Checks {
			if c.Name == name {
				t.Errorf("check %q must be skipped when the config is unloadable", name)
			}
		}
	}
}

func TestDoctorConfigFlagReachesLoader(t *testing.T) {
	var got string
	code, _, _ := runDoctorCommand(t, []string{"--config", "/tmp/custom.yaml"}, func(d *doctorDeps) {
		d.loadConfig = func(path string) (*config.Config, error) {
			got = path
			cfg := config.Default()
			return &cfg, nil
		}
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	if got != "/tmp/custom.yaml" {
		t.Errorf("loadConfig path = %q, want /tmp/custom.yaml", got)
	}
}

func TestDoctorBusyPort(t *testing.T) {
	ls, err := proxy.Listen("127.0.0.1", 0)
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer ls.Close()
	port := ls.Port()
	dataDir := t.TempDir()

	args := []string{"--port", strconv.Itoa(port)}
	code, stdout, _ := runDoctorCommand(t, args, func(d *doctorDeps) {
		d.listen = realDoctorListen
		d.dataDir = func() (string, error) { return dataDir, nil }
	})
	if code != ExitFailure {
		t.Fatalf("busy port exit = %d, want %d\nstdout:\n%s", code, ExitFailure, stdout)
	}
	if !strings.Contains(stdout, "already in use") || !strings.Contains(stdout, "[fail] port") {
		t.Errorf("stdout missing the busy-port failure:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[ok]   loopback") {
		t.Errorf("ephemeral dual-stack bind must still pass:\n%s", stdout)
	}

	// A malformed run.json must not turn the failure into a false "session".
	if err := os.WriteFile(filepath.Join(dataDir, RunStateFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runDoctorCommand(t, args, func(d *doctorDeps) {
		d.listen = realDoctorListen
		d.dataDir = func() (string, error) { return dataDir, nil }
	}); code != ExitFailure {
		t.Errorf("malformed run.json: exit = %d, want %d", code, ExitFailure)
	}

	// A matching run.json marks the busy port as the running session.
	if err := os.WriteFile(filepath.Join(dataDir, RunStateFileName), []byte(`{"pid":1234,"port":`+strconv.Itoa(port)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = runDoctorCommand(t, args, func(d *doctorDeps) {
		d.listen = realDoctorListen
		d.dataDir = func() (string, error) { return dataDir, nil }
	})
	if code != ExitOK {
		t.Fatalf("session-held port exit = %d, want %d\nstdout:\n%s", code, ExitOK, stdout)
	}
	if !strings.Contains(stdout, "held by the tokenhush session") {
		t.Errorf("stdout missing the session-held note:\n%s", stdout)
	}
}

func TestDoctorRealDualStackBind(t *testing.T) {
	ls, err := proxy.Listen("127.0.0.1", 0)
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	freePort := ls.Port()
	_ = ls.Close()

	code, stdout, _ := runDoctorCommand(t, []string{"--port", strconv.Itoa(freePort)}, func(d *doctorDeps) {
		d.listen = realDoctorListen
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s", code, ExitOK, stdout)
	}
	for _, want := range []string{
		"[ok]   loopback",
		"[ok]   port",
		"127.0.0.1:" + strconv.Itoa(freePort) + " and [::1]:" + strconv.Itoa(freePort) + " available",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestDoctorToolHints(t *testing.T) {
	home := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// claude is installed on PATH and already points at the gateway.
	// codex is installed but its config.toml points elsewhere.
	// cline is installed as a VS Code extension with no readable base URL.
	writeFile(".codex/config.toml", "base_url = \"https://api.example.com/v1\"\n")
	if err := os.MkdirAll(filepath.Join(home, ".vscode/extensions/saoudrizwan.claude-dev-3.17.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := runDoctorCommand(t, nil, func(d *doctorDeps) {
		d.userHomeDir = func() (string, error) { return home, nil }
		d.lookPath = func(name string) (string, error) {
			if name == "claude" {
				return "/usr/local/bin/claude", nil
			}
			return "", errors.New("not found")
		}
		d.getenv = func(key string) string {
			if key == "ANTHROPIC_BASE_URL" {
				return "http://127.0.0.1:8787"
			}
			return ""
		}
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s", code, ExitOK, stdout)
	}

	claude := "[ok]   tool:claude"
	if !strings.Contains(stdout, claude) || !strings.Contains(stdout, "points at this gateway") {
		t.Errorf("claude check must pass with a gateway base URL:\n%s", stdout)
	}
	codex := "[warn] tool:codex"
	if !strings.Contains(stdout, codex) || !strings.Contains(stdout, "does not point at this gateway") {
		t.Errorf("codex check must warn about the foreign base URL:\n%s", stdout)
	}
	if !strings.Contains(stdout, "http://127.0.0.1:8787/v1") {
		t.Errorf("codex fix must print the expected base URL:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[warn] tool:cline") || !strings.Contains(stdout, "tokenhush env cline") {
		t.Errorf("cline check must warn with the onboarding command:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[ok]   tool:roo") || !strings.Contains(stdout, "not detected") {
		t.Errorf("roo is absent and must be skipped:\n%s", stdout)
	}
}

func TestDoctorProxyEnv(t *testing.T) {
	code, stdout, _ := runDoctorCommand(t, nil, func(d *doctorDeps) {
		d.getenv = func(key string) string {
			if key == "HTTPS_PROXY" {
				return "http://corp-proxy:3128"
			}
			return ""
		}
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (proxy residue is a warning)", code, ExitOK)
	}
	if !strings.Contains(stdout, "[warn] proxy-env") || !strings.Contains(stdout, "add 127.0.0.1,localhost,::1 to NO_PROXY") {
		t.Errorf("stdout missing the proxy warning:\n%s", stdout)
	}

	code, stdout, _ = runDoctorCommand(t, nil, func(d *doctorDeps) {
		d.getenv = func(key string) string {
			switch key {
			case "HTTPS_PROXY":
				return "http://corp-proxy:3128"
			case "NO_PROXY":
				return "127.0.0.1,localhost"
			}
			return ""
		}
	})
	if code != ExitOK || !strings.Contains(stdout, "NO_PROXY covers loopback") {
		t.Errorf("exit = %d, want 0 with NO_PROXY covering loopback:\n%s", code, stdout)
	}

	// Warnings are machine-readable too, and they never flip the exit code.
	code, stdout, _ = runDoctorCommand(t, []string{"--json"}, func(d *doctorDeps) {
		d.getenv = func(key string) string {
			if key == "HTTPS_PROXY" {
				return "http://corp-proxy:3128"
			}
			return ""
		}
	})
	if code != ExitOK {
		t.Fatalf("warnings-only --json exit = %d, want %d", code, ExitOK)
	}
	report := parseDoctorJSON(t, stdout)
	if !report.OK || report.Status != doctorWarn || report.Exit != ExitOK {
		t.Errorf("warnings-only report ok/status/exit = %v/%q/%d, want true/warn/0", report.OK, report.Status, report.Exit)
	}
	if check := doctorFindCheck(t, report, doctorCheckProxyEnv); check.Status != doctorWarn {
		t.Errorf("proxy-env check = %+v, want warn", check)
	}

	code, stdout, _ = runDoctorCommand(t, nil, nil)
	if code != ExitOK || !strings.Contains(stdout, "no proxy environment variables set") {
		t.Errorf("exit = %d, want the no-proxy ok line:\n%s", code, stdout)
	}
}

func TestDoctorUsageErrors(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{"extra argument", []string{"extra"}, "unexpected argument"},
		{"port too large", []string{"--port", "70000"}, "1..65535"},
		{"port zero", []string{"--port", "-1"}, "1..65535"},
		{"unknown flag", []string{"--bogus"}, "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runDoctorCommand(t, tt.args, nil)
			if code != ExitUsage {
				t.Errorf("exit = %d, want %d", code, ExitUsage)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr missing %q:\n%s", tt.wantStderr, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
		})
	}
}

func TestDoctorToolsCoverEnvTools(t *testing.T) {
	if len(doctorToolsConfig) != len(envTools) {
		t.Fatalf("doctorToolsConfig has %d tools, envTools has %d; keep them in sync", len(doctorToolsConfig), len(envTools))
	}
	for _, tool := range envTools {
		found := false
		for _, dt := range doctorToolsConfig {
			if dt.name == tool {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("env tool %q is missing from doctorToolsConfig", tool)
		}
	}
}
