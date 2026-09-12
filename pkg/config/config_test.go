package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
	if !d.Prefix || !d.HighEntropy || !d.JWT || !d.PrivateKey || !d.Luhn || !d.Email {
		t.Errorf("detectors = %+v, want all six enabled", d)
	}
	wantIDs := []string{
		DetectorPrefix, DetectorHighEntropy, DetectorJWT,
		DetectorPrivateKey, DetectorLuhn, DetectorEmail,
	}
	if got := d.EnabledIDs(); !reflect.DeepEqual(got, wantIDs) {
		t.Errorf("detector ids = %v, want %v (config key prefixes/private_keys must map to prefix/private_key)", got, wantIDs)
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
	if !d.Prefix || !d.HighEntropy || !d.PrivateKey || !d.Luhn || !d.Email {
		t.Errorf("detectors = %+v, want only jwt disabled", d)
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
