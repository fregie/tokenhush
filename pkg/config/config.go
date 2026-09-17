// Package config defines tokenhush's strict, fail-fast configuration schema.
//
// The schema is closed: unknown keys are errors rather than warnings, because
// a typo in a security-relevant setting (a detector switch, the listen
// address) must never silently fall back to a permissive default. Strictness
// comes from the single pinned dependency, github.com/goccy/go-yaml, whose
// DisallowUnknownField decode option rejects any key the schema does not
// define.
//
// The YAML surface is:
//
//	listen:            {host: 127.0.0.1, port: 8787}
//	log:               {level: info}
//	detectors:         {prefix: true, email: true, luhn: true, jwt: true, pem: true, entropy: false}
//	allowlist:         ["literal"]
//	upstreams:         [{match: "/v1/chat/completions", target: "https://api.openai.com"}]
//	scan_budget_bytes: 33554432
//	detector_timeout:  30s
//
// A missing file is not an error: Load returns Default(). An existing file is
// parsed strictly, then every value is validated before it is returned.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

const (
	// DefaultHost keeps the listener on the loopback interface. Validate
	// rejects anything else, so exposing the proxy cannot happen by accident.
	DefaultHost = "127.0.0.1"
	// DefaultPort is the listen port used when the file does not set one.
	DefaultPort = 8787
	// DefaultLogLevel is the level used when the file does not set one.
	DefaultLogLevel = "info"
	// ScanBudgetBytes is the default cap on bytes scanned per unit of work.
	ScanBudgetBytes = 32 << 20
	// DetectorTimeout is the default time budget for one detector pass.
	DetectorTimeout = 30 * time.Second
)

// minPort and maxPort bound the accepted TCP port range.
const (
	minPort = 1
	maxPort = 65535
)

// Schema errors. Every rejection wraps exactly one of them.
var (
	// ErrUnknownField reports a key the schema does not define.
	ErrUnknownField = errors.New("config: unknown field")
	// ErrInvalidValue reports a defined key whose value failed validation.
	ErrInvalidValue = errors.New("config: invalid value")
)

// logLevels is the closed set of accepted log levels.
var logLevels = []string{"debug", "info", "warn", "error"}

// FieldError names the offending configuration field and the reason it was
// rejected. Unwrap returns either ErrUnknownField or ErrInvalidValue.
type FieldError struct {
	Path    string
	Problem string
	Kind    error
}

// Error renders the field path followed by the problem.
func (e *FieldError) Error() string {
	if e.Path == "" {
		return "config: " + e.Problem
	}
	return "config: " + e.Path + ": " + e.Problem
}

// Unwrap returns the schema sentinel this rejection belongs to.
func (e *FieldError) Unwrap() error { return e.Kind }

// Config is the whole configuration surface. The struct mirrors the YAML
// document one-to-one; every field must be known and valid.
type Config struct {
	Listen          Listen        `yaml:"listen"`
	Log             Log           `yaml:"log"`
	Detectors       Detectors     `yaml:"detectors"`
	Allowlist       []string      `yaml:"allowlist"`
	Upstreams       []Upstream    `yaml:"upstreams"`
	ScanBudgetBytes int64         `yaml:"scan_budget_bytes"`
	DetectorTimeout time.Duration `yaml:"detector_timeout"`
}

// Listen is the address the proxy binds.
type Listen struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// Log selects the minimum severity the logger emits.
type Log struct {
	Level string `yaml:"level"`
}

// Detectors holds one switch per detector. Entropy is opt-in.
type Detectors struct {
	Prefix  bool `yaml:"prefix"`
	Email   bool `yaml:"email"`
	Luhn    bool `yaml:"luhn"`
	JWT     bool `yaml:"jwt"`
	PEM     bool `yaml:"pem"`
	Entropy bool `yaml:"entropy"`
}

// Upstream routes requests whose path prefix matches Match to Target.
type Upstream struct {
	Match  string `yaml:"match"`
	Target string `yaml:"target"`
}

// UnmarshalYAML merges the written switches into the receiver, which already
// holds the defaults, and rejects any detector name the schema does not know.
func (d *Detectors) UnmarshalYAML(data []byte) error {
	var switches map[string]bool
	if err := yaml.Unmarshal(data, &switches); err != nil {
		return err
	}
	for name, on := range switches {
		switch name {
		case "prefix":
			d.Prefix = on
		case "email":
			d.Email = on
		case "luhn":
			d.Luhn = on
		case "jwt":
			d.JWT = on
		case "pem":
			d.PEM = on
		case "entropy":
			d.Entropy = on
		default:
			return &FieldError{Path: "detectors." + name, Problem: "unknown detector", Kind: ErrUnknownField}
		}
	}
	return nil
}

// Default returns the schema defaults: loopback listener, info logging, every
// detector on except the opt-in entropy pass, and the named numeric knobs.
func Default() Config {
	return Config{
		Listen: Listen{Host: DefaultHost, Port: DefaultPort},
		Log:    Log{Level: DefaultLogLevel},
		Detectors: Detectors{
			Prefix: true,
			Email:  true,
			Luhn:   true,
			JWT:    true,
			PEM:    true,
		},
		ScanBudgetBytes: ScanBudgetBytes,
		DetectorTimeout: DetectorTimeout,
	}
}

// Load reads path and returns the parsed, validated configuration. A missing
// file yields Default() and no error.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Default(), nil
		}
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes the YAML document in data strictly and validates the result.
func Parse(data []byte) (Config, error) {
	cfg := Default()
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data), yaml.DisallowUnknownField())
	if err := decoder.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Default(), nil
		}
		return Config{}, schemaError(err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports the first schema rule c breaks.
func (c Config) Validate() error {
	if err := validateListen(c.Listen); err != nil {
		return err
	}
	if !slices.Contains(logLevels, c.Log.Level) {
		return &FieldError{
			Path:    "log.level",
			Problem: fmt.Sprintf("%q is not one of %s", c.Log.Level, strings.Join(logLevels, ", ")),
			Kind:    ErrInvalidValue,
		}
	}
	if c.ScanBudgetBytes <= 0 {
		return &FieldError{
			Path:    "scan_budget_bytes",
			Problem: fmt.Sprintf("%d must be positive", c.ScanBudgetBytes),
			Kind:    ErrInvalidValue,
		}
	}
	if c.DetectorTimeout <= 0 {
		return &FieldError{
			Path:    "detector_timeout",
			Problem: fmt.Sprintf("%s must be positive", c.DetectorTimeout),
			Kind:    ErrInvalidValue,
		}
	}
	for i, upstream := range c.Upstreams {
		if upstream.Match == "" || upstream.Target == "" {
			return &FieldError{
				Path:    fmt.Sprintf("upstreams[%d]", i),
				Problem: "match and target must both be set",
				Kind:    ErrInvalidValue,
			}
		}
	}
	return nil
}

// validateListen enforces the loopback-only listener and the port range.
func validateListen(listen Listen) error {
	if listen.Host != "localhost" {
		ip := net.ParseIP(listen.Host)
		if ip == nil || !ip.IsLoopback() {
			return &FieldError{
				Path:    "listen.host",
				Problem: fmt.Sprintf("%q is not a loopback address", listen.Host),
				Kind:    ErrInvalidValue,
			}
		}
	}
	if listen.Port < minPort || listen.Port > maxPort {
		return &FieldError{
			Path:    "listen.port",
			Problem: fmt.Sprintf("%d is outside %d..%d", listen.Port, minPort, maxPort),
			Kind:    ErrInvalidValue,
		}
	}
	return nil
}

// schemaError maps a decode failure onto a FieldError: unknown keys keep the
// ErrUnknownField sentinel, everything else is an invalid value. FieldErrors
// raised by a field's own UnmarshalYAML pass through unchanged.
func schemaError(err error) error {
	var field *FieldError
	if errors.As(err, &field) {
		return field
	}
	var unknown *yaml.UnknownFieldError
	if errors.As(err, &unknown) {
		return &FieldError{Problem: unknown.Message, Kind: ErrUnknownField}
	}
	return &FieldError{Problem: err.Error(), Kind: ErrInvalidValue}
}
