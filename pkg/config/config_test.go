package config

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadMissingFileReturnsDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error = %v, want nil for a missing file", path, err)
	}
	if !reflect.DeepEqual(got, Default()) {
		t.Errorf("Load(%q) = %+v, want Default() %+v", path, got, Default())
	}
}

func TestDefaults(t *testing.T) {
	cfg := Default()

	if cfg.Listen.Host != "127.0.0.1" {
		t.Errorf("Default().Listen.Host = %q, want %q", cfg.Listen.Host, "127.0.0.1")
	}
	if cfg.Listen.Host != DefaultHost {
		t.Errorf("Default().Listen.Host = %q, want DefaultHost %q", cfg.Listen.Host, DefaultHost)
	}
	if cfg.Listen.Port != 8787 {
		t.Errorf("Default().Listen.Port = %d, want 8787", cfg.Listen.Port)
	}
	if cfg.Listen.Port != DefaultPort {
		t.Errorf("Default().Listen.Port = %d, want DefaultPort %d", cfg.Listen.Port, DefaultPort)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Default().Log.Level = %q, want %q", cfg.Log.Level, "info")
	}
	if cfg.Log.Level != DefaultLogLevel {
		t.Errorf("Default().Log.Level = %q, want DefaultLogLevel %q", cfg.Log.Level, DefaultLogLevel)
	}

	want := Detectors{Prefix: true, Email: true, Luhn: true, JWT: true, PEM: true, Entropy: false}
	if cfg.Detectors != want {
		t.Errorf("Default().Detectors = %+v, want %+v", cfg.Detectors, want)
	}
	if len(cfg.Allowlist) != 0 {
		t.Errorf("Default().Allowlist = %v, want an empty allowlist", cfg.Allowlist)
	}
	if len(cfg.Upstreams) != 0 {
		t.Errorf("Default().Upstreams = %v, want no upstreams", cfg.Upstreams)
	}
	if cfg.ScanBudgetBytes != 32<<20 {
		t.Errorf("Default().ScanBudgetBytes = %d, want %d", cfg.ScanBudgetBytes, 32<<20)
	}
	if cfg.ScanBudgetBytes != ScanBudgetBytes {
		t.Errorf("Default().ScanBudgetBytes = %d, want ScanBudgetBytes %d", cfg.ScanBudgetBytes, ScanBudgetBytes)
	}
	if cfg.DetectorTimeout != 30*time.Second {
		t.Errorf("Default().DetectorTimeout = %s, want 30s", cfg.DetectorTimeout)
	}
	if cfg.DetectorTimeout != DetectorTimeout {
		t.Errorf("Default().DetectorTimeout = %s, want DetectorTimeout %s", cfg.DetectorTimeout, DetectorTimeout)
	}
	if cfg.MaxBodyBytes != 64<<20 {
		t.Errorf("Default().MaxBodyBytes = %d, want %d (64 MiB)", cfg.MaxBodyBytes, 64<<20)
	}
	if cfg.MaxBodyBytes != MaxBodyBytes {
		t.Errorf("Default().MaxBodyBytes = %d, want MaxBodyBytes %d", cfg.MaxBodyBytes, MaxBodyBytes)
	}
}

func TestParseEmptyDocumentReturnsDefault(t *testing.T) {
	for _, doc := range []string{"", "\n", "   \n"} {
		got, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("Parse(%q) error = %v, want nil for an empty document", doc, err)
		}
		if !reflect.DeepEqual(got, Default()) {
			t.Errorf("Parse(%q) = %+v, want Default() %+v", doc, got, Default())
		}
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	err := mustReject(t, "unknown_key: 1\n")
	t.Logf("unknown_key rejection: %v", err)

	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("Parse(unknown_key) error = %v, want it to wrap ErrUnknownField", err)
	}
	if !strings.Contains(err.Error(), "unknown_key") {
		t.Errorf("Parse(unknown_key) error = %v, want it to name the offending field", err)
	}
}

func TestParseRejectsNonLoopbackHost(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "192.168.1.10", "::", "example.com", ""} {
		doc := fmt.Sprintf("listen: {host: %q}\n", host)
		err := mustReject(t, doc)
		t.Logf("%s rejection: %v", doc[:len(doc)-1], err)

		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Parse(%q) error = %v, want it to wrap ErrInvalidValue", doc, err)
		}
		if !strings.Contains(err.Error(), "listen.host") {
			t.Errorf("Parse(%q) error = %v, want it to name listen.host", doc, err)
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("Parse(%q) error = %v, want it to mention the loopback rule", doc, err)
		}
	}
}

func TestParseAcceptsLoopbackHosts(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "::1", "localhost"} {
		doc := fmt.Sprintf("listen: {host: %q}\n", host)
		cfg, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("Parse(%q) error = %v, want a loopback host accepted", doc, err)
		}
		if cfg.Listen.Host != host {
			t.Errorf("Parse(%q) host = %q, want %q", doc, cfg.Listen.Host, host)
		}
	}
}

func TestParseRejectsPortOutOfRange(t *testing.T) {
	for _, port := range []int{0, -1, 65536, 70000} {
		doc := fmt.Sprintf("listen: {port: %d}\n", port)
		err := mustReject(t, doc)

		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Parse(%q) error = %v, want it to wrap ErrInvalidValue", doc, err)
		}
		if !strings.Contains(err.Error(), "listen.port") {
			t.Errorf("Parse(%q) error = %v, want it to name listen.port", doc, err)
		}
	}
}

func TestParseAcceptsPortRangeBoundaries(t *testing.T) {
	for _, port := range []int{1, 65535} {
		doc := fmt.Sprintf("listen: {port: %d}\n", port)
		cfg, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("Parse(%q) error = %v, want the port accepted", doc, err)
		}
		if cfg.Listen.Port != port {
			t.Errorf("Parse(%q) port = %d, want %d", doc, cfg.Listen.Port, port)
		}
	}
}

func TestParseRejectsUnknownLogLevel(t *testing.T) {
	for _, level := range []string{"chatty", "verbose", "INFO", ""} {
		doc := fmt.Sprintf("log: {level: %q}\n", level)
		err := mustReject(t, doc)

		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Parse(%q) error = %v, want it to wrap ErrInvalidValue", doc, err)
		}
		if !strings.Contains(err.Error(), "log.level") {
			t.Errorf("Parse(%q) error = %v, want it to name log.level", doc, err)
		}
	}
}

func TestParseAcceptsLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		doc := fmt.Sprintf("log: {level: %q}\n", level)
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("Parse(%q) error = %v, want the level accepted", doc, err)
		}
	}
}

func TestParseRejectsNonPositiveNumbers(t *testing.T) {
	cases := map[string]string{
		"zero scan budget":      "scan_budget_bytes: 0",
		"negative scan budget":  "scan_budget_bytes: -1",
		"zero detector timeout": "detector_timeout: 0s",
		"negative timeout":      "detector_timeout: -1s",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			err := mustReject(t, doc+"\n")
			if !errors.Is(err, ErrInvalidValue) {
				t.Errorf("Parse(%q) error = %v, want it to wrap ErrInvalidValue", doc, err)
			}
		})
	}
}

func TestParseResponseLimits(t *testing.T) {
	doc := "response_buffer_bytes: 1048576\nresponse_timeout: 90s\n"
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse(response limits) error = %v, want nil", err)
	}
	if cfg.ResponseBufferBytes != 1048576 {
		t.Errorf("ResponseBufferBytes = %d, want 1048576", cfg.ResponseBufferBytes)
	}
	if cfg.ResponseTimeout != 90*time.Second {
		t.Errorf("ResponseTimeout = %s, want 90s", cfg.ResponseTimeout)
	}

	partial, err := Parse([]byte("log: {level: warn}\n"))
	if err != nil {
		t.Fatalf("Parse(partial document) error = %v, want nil", err)
	}
	if partial.ResponseBufferBytes != ResponseBufferBytes {
		t.Errorf("absent response_buffer_bytes = %d, want the default %d", partial.ResponseBufferBytes, ResponseBufferBytes)
	}
	if partial.ResponseBufferBytes != 32<<20 {
		t.Errorf("ResponseBufferBytes default = %d, want %d (32 MiB)", partial.ResponseBufferBytes, 32<<20)
	}
	if partial.ResponseTimeout != ResponseTimeout {
		t.Errorf("absent response_timeout = %s, want the default %s", partial.ResponseTimeout, ResponseTimeout)
	}
	if partial.ResponseTimeout != 5*time.Minute {
		t.Errorf("ResponseTimeout default = %s, want 5m", partial.ResponseTimeout)
	}

	rejections := map[string]string{
		"zero response buffer":      "response_buffer_bytes: 0",
		"negative response buffer":  "response_buffer_bytes: -1",
		"zero response timeout":     "response_timeout: 0s",
		"negative response timeout": "response_timeout: -1s",
	}
	for name, bad := range rejections {
		t.Run(name, func(t *testing.T) {
			err := mustReject(t, bad+"\n")
			if !errors.Is(err, ErrInvalidValue) {
				t.Errorf("Parse(%q) error = %v, want it to wrap ErrInvalidValue", bad, err)
			}
		})
	}

	err = mustReject(t, "response_buffer_bytes: 1048576\nunknown_response_key: 1\n")
	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("Parse(unknown key) error = %v, want it to wrap ErrUnknownField", err)
	}
}

func TestParseBodySizeCap(t *testing.T) {
	cfg, err := Parse([]byte("max_body_bytes: 1048576\n"))
	if err != nil {
		t.Fatalf("Parse(max_body_bytes) error = %v, want nil", err)
	}
	if cfg.MaxBodyBytes != 1048576 {
		t.Errorf("MaxBodyBytes = %d, want 1048576", cfg.MaxBodyBytes)
	}

	partial, err := Parse([]byte("log: {level: warn}\n"))
	if err != nil {
		t.Fatalf("Parse(partial document) error = %v, want nil", err)
	}
	if partial.MaxBodyBytes != MaxBodyBytes {
		t.Errorf("absent max_body_bytes = %d, want the default %d", partial.MaxBodyBytes, MaxBodyBytes)
	}
	if partial.MaxBodyBytes != 64<<20 {
		t.Errorf("MaxBodyBytes default = %d, want %d (64 MiB)", partial.MaxBodyBytes, 64<<20)
	}

	rejections := map[string]string{
		"zero body cap":     "max_body_bytes: 0",
		"negative body cap": "max_body_bytes: -1",
	}
	for name, bad := range rejections {
		t.Run(name, func(t *testing.T) {
			err := mustReject(t, bad+"\n")
			if !errors.Is(err, ErrInvalidValue) {
				t.Errorf("Parse(%q) error = %v, want it to wrap ErrInvalidValue", bad, err)
			}
			if !strings.Contains(err.Error(), "max_body_bytes") {
				t.Errorf("Parse(%q) error = %v, want it to name max_body_bytes", bad, err)
			}
			if !strings.Contains(err.Error(), "must be positive") {
				t.Errorf("Parse(%q) error = %v, want it to say the value must be positive", bad, err)
			}
		})
	}
}

func TestParseRejectsUnknownDetectorName(t *testing.T) {
	err := mustReject(t, "detectors: {wat: true}\n")

	if !errors.Is(err, ErrUnknownField) {
		t.Errorf("Parse(detectors.wat) error = %v, want it to wrap ErrUnknownField", err)
	}
	if !strings.Contains(err.Error(), "detectors.wat") {
		t.Errorf("Parse(detectors.wat) error = %v, want it to name detectors.wat", err)
	}
}

func TestParseFullDocument(t *testing.T) {
	const doc = `
listen: {host: "127.0.0.1", port: 9999}
log: {level: debug}
detectors: {prefix: false, email: true, luhn: false, jwt: true, pem: false, entropy: true}
allowlist:
  - literal-one
  - literal-two
upstreams:
  - match: /v1/chat/completions
    target: https://api.openai.com
scan_budget_bytes: 1048576
detector_timeout: 1500ms
`
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse(full document) error = %v, want nil", err)
	}

	if cfg.Listen.Host != "127.0.0.1" || cfg.Listen.Port != 9999 {
		t.Errorf("Listen = %+v, want {127.0.0.1 9999}", cfg.Listen)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}
	wantDetectors := Detectors{Prefix: false, Email: true, Luhn: false, JWT: true, PEM: false, Entropy: true}
	if cfg.Detectors != wantDetectors {
		t.Errorf("Detectors = %+v, want %+v", cfg.Detectors, wantDetectors)
	}
	wantAllowlist := []string{"literal-one", "literal-two"}
	if !reflect.DeepEqual(cfg.Allowlist, wantAllowlist) {
		t.Errorf("Allowlist = %v, want %v", cfg.Allowlist, wantAllowlist)
	}
	wantUpstreams := []Upstream{{Match: "/v1/chat/completions", Target: "https://api.openai.com"}}
	if !reflect.DeepEqual(cfg.Upstreams, wantUpstreams) {
		t.Errorf("Upstreams = %+v, want %+v", cfg.Upstreams, wantUpstreams)
	}
	if cfg.ScanBudgetBytes != 1048576 {
		t.Errorf("ScanBudgetBytes = %d, want 1048576", cfg.ScanBudgetBytes)
	}
	if cfg.DetectorTimeout != 1500*time.Millisecond {
		t.Errorf("DetectorTimeout = %s, want 1500ms", cfg.DetectorTimeout)
	}
}

func TestParseDurationForms(t *testing.T) {
	for doc, want := range map[string]time.Duration{
		"detector_timeout: 30s\n":    30 * time.Second,
		"detector_timeout: 1500ms\n": 1500 * time.Millisecond,
		"detector_timeout: 1m30s\n":  90 * time.Second,
	} {
		cfg, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("Parse(%q) error = %v, want the duration accepted", doc, err)
		}
		if cfg.DetectorTimeout != want {
			t.Errorf("Parse(%q) DetectorTimeout = %s, want %s", doc, cfg.DetectorTimeout, want)
		}
	}
}

func TestParseKeepsDefaultsForAbsentKeys(t *testing.T) {
	cfg, err := Parse([]byte("log: {level: warn}\ndetectors: {entropy: true}\n"))
	if err != nil {
		t.Fatalf("Parse(partial document) error = %v, want nil", err)
	}

	if cfg.Listen.Host != DefaultHost || cfg.Listen.Port != DefaultPort {
		t.Errorf("Listen = %+v, want the defaults preserved", cfg.Listen)
	}
	want := Detectors{Prefix: true, Email: true, Luhn: true, JWT: true, PEM: true, Entropy: true}
	if cfg.Detectors != want {
		t.Errorf("Detectors = %+v, want the defaults with entropy enabled (%+v)", cfg.Detectors, want)
	}
	if cfg.ScanBudgetBytes != ScanBudgetBytes || cfg.DetectorTimeout != DetectorTimeout {
		t.Errorf("numeric knobs = %d/%s, want defaults %d/%s",
			cfg.ScanBudgetBytes, cfg.DetectorTimeout, ScanBudgetBytes, DetectorTimeout)
	}
	if cfg.MaxBodyBytes != MaxBodyBytes {
		t.Errorf("MaxBodyBytes = %d, want the default %d", cfg.MaxBodyBytes, MaxBodyBytes)
	}
	if cfg.Log.Level != "warn" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "warn")
	}
}

func TestLoadReadsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("listen: {port: 9000}\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error = %v, want nil", path, err)
	}
	if cfg.Listen.Port != 9000 {
		t.Errorf("Load(%q) port = %d, want 9000", path, cfg.Listen.Port)
	}
	if cfg.Listen.Host != DefaultHost {
		t.Errorf("Load(%q) host = %q, want the default %q", path, cfg.Listen.Host, DefaultHost)
	}
}

func TestProductionImportsStayOffTheForbiddenStack(t *testing.T) {
	forbidden := map[string]bool{"net/http": true, "net/textproto": true, "crypto/tls": true}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if forbidden[path] {
				t.Errorf("%s imports %q, which pkg/config must never depend on", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no production Go files found in pkg/config")
	}
}

// mustReject parses doc and fails the test when it is accepted or when the
// error is not one of the two schema sentinels.
func mustReject(t *testing.T, doc string) error {
	t.Helper()

	cfg, err := Parse([]byte(doc))
	if err == nil {
		t.Fatalf("Parse(%q) succeeded with %+v, want a rejection", doc, cfg)
	}
	if !errors.Is(err, ErrInvalidValue) && !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Parse(%q) error = %v, want it to wrap ErrInvalidValue or ErrUnknownField", doc, err)
	}
	return err
}
