package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// writeConfig writes a temporary tokenhush.yaml fixture and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokenhush.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	return path
}

func TestDefaultExactValues(t *testing.T) {
	cfg := Default()

	if cfg.Listen.Host != "127.0.0.1" {
		t.Errorf("listen.host = %q, want 127.0.0.1", cfg.Listen.Host)
	}
	if cfg.Listen.Port != 8787 {
		t.Errorf("listen.port = %d, want 8787", cfg.Listen.Port)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("log.level = %q, want info", cfg.Log.Level)
	}
	if len(cfg.Allowlist) != 0 {
		t.Errorf("allowlist = %v, want empty", cfg.Allowlist)
	}

	d := cfg.Detectors
	if !d.Prefix || d.HighEntropy || !d.JWT || !d.PrivateKey || !d.Luhn || !d.Email {
		t.Errorf("detectors = %+v, want five enabled and high_entropy off", d)
	}
	if d.ScanBudgetBytes != 32<<20 {
		t.Errorf("detectors.scan_budget_bytes = %d, want 32 MiB", d.ScanBudgetBytes)
	}
	if d.Timeout != 30*time.Second {
		t.Errorf("detectors.timeout = %v, want 30s", d.Timeout)
	}
	wantIDs := []string{
		DetectorPrefix, DetectorJWT,
		DetectorPrivateKey, DetectorLuhn, DetectorEmail,
	}
	if got := d.EnabledIDs(); !reflect.DeepEqual(got, wantIDs) {
		t.Errorf("detector ids = %v, want %v (high_entropy is wired but defaults off; prefixes/private_keys map to prefix/private_key)", got, wantIDs)
	}
}

// TestHighEntropyDefaultsOff locks the deliberate precision decision: the
// high_entropy detector stays compiled in and wired, but it is off unless a
// user explicitly enables it. A regression that flips the default back on is a
// real-traffic false-positive regression (long tool names and session ids were
// redacted as secrets, breaking function calling), so it must fail here.
func TestHighEntropyDefaultsOff(t *testing.T) {
	if Default().Detectors.HighEntropy {
		t.Fatal("Default().Detectors.HighEntropy = true, want false (high_entropy is opt-in)")
	}
	cfg, err := LoadFile(writeConfig(t, "detectors:\n  prefixes: true\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Detectors.HighEntropy {
		t.Fatal("omitting detectors.high_entropy enabled it, want the off default")
	}
	cfg, err = LoadFile(writeConfig(t, "detectors:\n  high_entropy: true\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !cfg.Detectors.HighEntropy {
		t.Fatal("detectors.high_entropy: true did not enable the detector")
	}
}

// TestScanBudgetAndTimeoutKeysAreParsed locks the two tuning keys: the
// deterministic byte budget and the wall-clock backstop are read from YAML and
// default to the documented values.
func TestScanBudgetAndTimeoutKeysAreParsed(t *testing.T) {
	cfg, err := LoadFile(writeConfig(t, "detectors:\n  scan_budget_bytes: 1048576\n  timeout: 7s\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Detectors.ScanBudgetBytes != 1048576 {
		t.Errorf("scan_budget_bytes = %d, want 1048576", cfg.Detectors.ScanBudgetBytes)
	}
	if cfg.Detectors.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want 7s", cfg.Detectors.Timeout)
	}
	if got := Default().Detectors.ScanBudgetBytes; got != 32<<20 {
		t.Errorf("default scan_budget_bytes = %d, want 32 MiB", got)
	}
	if got := Default().Detectors.Timeout; got != 30*time.Second {
		t.Errorf("default timeout = %v, want 30s", got)
	}
}

func TestLoadFileMissingFileIsExactDefaults(t *testing.T) {
	cfg, err := LoadFile(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("LoadFile on missing file: %v", err)
	}
	if want := Default(); !reflect.DeepEqual(*cfg, want) {
		t.Fatalf("missing file config = %+v, want exact defaults %+v", *cfg, want)
	}
}

func TestLoadFileEmptyAndCommentOnlyAreExactDefaults(t *testing.T) {
	for name, body := range map[string]string{
		"empty":      "",
		"comment":    "# tokenhush configuration\n",
		"whitespace": "\n\n",
		"null_doc":   "null\n",
		"empty_objs": "listen: {}\ndetectors: {}\nupstreams: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadFile(writeConfig(t, body))
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			if want := Default(); !reflect.DeepEqual(*cfg, want) {
				t.Fatalf("config = %+v, want exact defaults %+v", *cfg, want)
			}
		})
	}
}

func TestLoadFilePartialConfigKeepsDefaults(t *testing.T) {
	cfg, err := LoadFile(writeConfig(t, "listen:\n  port: 9000\ndetectors:\n  jwt: false\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Listen.Host != "127.0.0.1" {
		t.Errorf("listen.host = %q, want default 127.0.0.1", cfg.Listen.Host)
	}
	if cfg.Listen.Port != 9000 {
		t.Errorf("listen.port = %d, want 9000", cfg.Listen.Port)
	}
	if cfg.Detectors.JWT {
		t.Error("detectors.jwt = true, want explicit false")
	}
	d := cfg.Detectors
	if !d.Prefix || d.HighEntropy || !d.PrivateKey || !d.Luhn || !d.Email {
		t.Errorf("detectors = %+v, want only jwt disabled and high_entropy at its off default", d)
	}
}

func TestLoadFilePortNullKeepsDefault(t *testing.T) {
	cfg, err := LoadFile(writeConfig(t, "listen:\n  port: null\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Listen.Port != 8787 {
		t.Errorf("listen.port = %d, explicit null must keep the default 8787", cfg.Listen.Port)
	}
}

func TestLoadFileReturnsUpstreams(t *testing.T) {
	body := "" +
		"upstreams:\n" +
		"  api.anthropic.com: https://api.anthropic.com\n" +
		"  /v1beta: https://generativelanguage.googleapis.com\n"
	cfg, err := LoadFile(writeConfig(t, body))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	want := map[string]string{
		"api.anthropic.com": "https://api.anthropic.com",
		"/v1beta":           "https://generativelanguage.googleapis.com",
	}
	if !reflect.DeepEqual(map[string]string(cfg.Upstreams), want) {
		t.Fatalf("upstreams = %v, want %v", cfg.Upstreams, want)
	}
}

func TestLoadFileAcceptsLoopbackHosts(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "LocalHost"} {
		t.Run(fmt.Sprintf("%q", host), func(t *testing.T) {
			cfg, err := LoadFile(writeConfig(t, fmt.Sprintf("listen:\n  host: %q\n", host)))
			if err != nil {
				t.Fatalf("host %q: unexpected error: %v", host, err)
			}
			if cfg.Listen.Host != host {
				t.Errorf("listen.host = %q, want %q", cfg.Listen.Host, host)
			}
		})
	}
}

func TestLoadUsesPlatformConfigFile(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "tokenhush.yaml")
	if err := os.WriteFile(path, []byte("listen:\n  port: 9123\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TOKENHUSH_HOME", home)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.Port != 9123 {
		t.Fatalf("listen.port = %d, want 9123 from the platform config file", cfg.Listen.Port)
	}
	if cfg.Listen.Host != "127.0.0.1" {
		t.Fatalf("listen.host = %q, want default 127.0.0.1", cfg.Listen.Host)
	}
}
