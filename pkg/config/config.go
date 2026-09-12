package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
)

// maxConfigBytes bounds how much of tokenhush.yaml is read. The V1 config is a
// short, hand-written file; anything bigger is either a mistake or hostile and
// fails fast with ErrTooLarge.
const maxConfigBytes = 1 << 20 // 1 MiB

// Canonical detector ids, matching docs/13 §5.1. Note the deliberate mismatch
// with the YAML keys: `prefixes`/`private_keys` in the file map to the ids
// `prefix`/`private_key`.
const (
	DetectorPrefix      = "prefix"
	DetectorHighEntropy = "high_entropy"
	DetectorJWT         = "jwt"
	DetectorPrivateKey  = "private_key"
	DetectorLuhn        = "luhn"
	DetectorEmail       = "email"
)

// Config is a fully loaded and validated V1 configuration.
type Config struct {
	Listen    Listen    `yaml:"listen"`
	Detectors Detectors `yaml:"detectors"`
	Allowlist []string  `yaml:"allowlist"`
	Log       Log       `yaml:"log"`
	Upstreams Upstreams `yaml:"upstreams"`
}

// Listen is the loopback listener. Host is restricted to 127.0.0.1, ::1 or
// localhost; the wildcard is rejected by validate.
type Listen struct {
	Host string `yaml:"host"`
	Port Port   `yaml:"port"`
}

// Detectors mirrors the `detectors:` block. Every detector defaults to on.
type Detectors struct {
	Prefix      bool `yaml:"prefixes"`
	HighEntropy bool `yaml:"high_entropy"`
	JWT         bool `yaml:"jwt"`
	PrivateKey  bool `yaml:"private_keys"`
	Luhn        bool `yaml:"luhn"`
	Email       bool `yaml:"email"`
}

// EnabledIDs returns the canonical ids of all enabled detectors in docs/13
// §5.1 order, so the redaction engine never has to know YAML key names.
func (d Detectors) EnabledIDs() []string {
	ids := make([]string, 0, 6)
	for _, det := range [...]struct {
		id      string
		enabled bool
	}{
		{DetectorPrefix, d.Prefix},
		{DetectorHighEntropy, d.HighEntropy},
		{DetectorJWT, d.JWT},
		{DetectorPrivateKey, d.PrivateKey},
		{DetectorLuhn, d.Luhn},
		{DetectorEmail, d.Email},
	} {
		if det.enabled {
			ids = append(ids, det.id)
		}
	}
	return ids
}

// Log configures the daemon log level.
type Log struct {
	Level string `yaml:"level"`
}

// Default returns the opinionated V1 defaults from docs/13 §7.
func Default() Config {
	return Config{
		Listen: Listen{Host: "127.0.0.1", Port: 8787},
		Detectors: Detectors{
			Prefix:      true,
			HighEntropy: true,
			JWT:         true,
			PrivateKey:  true,
			Luhn:        true,
			Email:       true,
		},
		Allowlist: []string{},
		Log:       Log{Level: "info"},
	}
}

// Load reads tokenhush.yaml from the platform config directory. A missing file
// is not an error: Load returns Default().
func Load() (*Config, error) {
	path, err := defaultConfigFile()
	if err != nil {
		return nil, err
	}
	return LoadFile(path)
}

// LoadFile reads the configuration at path. A missing file yields Default();
// present files are merged over Default(), so omitted keys keep their default
// values, then validated.
func LoadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			cfg := Default()
			return &cfg, nil
		}
		return nil, &Error{Path: path, Reason: "cannot open config file", Err: ErrRead, Cause: err}
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, &Error{Path: path, Reason: "cannot read config file", Err: ErrRead, Cause: err}
	}
	if len(data) > maxConfigBytes {
		return nil, &Error{Path: path, Reason: fmt.Sprintf("file exceeds %d bytes", maxConfigBytes), Err: ErrTooLarge}
	}

	cfg := Default()
	// Preflight parse into any: goccy returns no error for an empty document
	// (empty file, comments only, whitespace) but silently zeroes the
	// prepopulated destination struct. Treat "no document" as defaults.
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, classifyYAMLError(path, err)
	}
	if doc == nil {
		return &cfg, nil
	}
	if err := yaml.UnmarshalWithOptions(data, &cfg, yaml.DisallowUnknownField()); err != nil {
		return nil, classifyYAMLError(path, err)
	}
	if err := cfg.validate(path); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// classifyYAMLError converts a goccy/go-yaml decoding failure into a typed
// *Error: unknown fields get ErrUnknownField, everything else ErrParse. Errors
// already typed by a custom unmarshaler (Port, Upstreams) pass through with the
// file path attached.
func classifyYAMLError(path string, err error) error {
	var cfgErr *Error
	if errors.As(err, &cfgErr) {
		cfgErr.Path = path
		return err
	}
	var unknown *yaml.UnknownFieldError
	if errors.As(err, &unknown) {
		if reason, moved := auditMigrationReason(unknown.GetMessage()); moved {
			return &Error{Path: path, Field: "audit", Reason: reason, Err: ErrUnknownField, Cause: err}
		}
		return &Error{Path: path, Reason: unknown.GetMessage(), Err: ErrUnknownField, Cause: err}
	}
	return &Error{Path: path, Reason: "invalid YAML: " + firstLine(err.Error()), Err: ErrParse, Cause: err}
}

// auditMigrationReason turns the removed top-level `audit` key (block or scalar
// form) into an actionable migration error. goccy's UnknownFieldError exposes
// only the bare key name, so the match is on the quoted key.
func auditMigrationReason(message string) (string, bool) {
	if !strings.Contains(message, `"audit"`) {
		return "", false
	}
	return `the "audit" block moved to tokenhush-pro; delete the audit: block from your config and install tokenhush-pro for local audit`, true
}

func (c *Config) validate(path string) error {
	if !isLoopbackHost(c.Listen.Host) {
		return &Error{
			Path:   path,
			Field:  "listen.host",
			Reason: fmt.Sprintf("must be loopback (127.0.0.1, ::1 or localhost), got %q", c.Listen.Host),
			Err:    ErrInvalidListenHost,
		}
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return &Error{
			Path:   path,
			Field:  "log.level",
			Reason: fmt.Sprintf("must be one of debug|info|warn|error, got %q", c.Log.Level),
			Err:    ErrInvalidLogLevel,
		}
	}
	return nil
}

// isLoopbackHost reports whether host is one of the three forms the listener
// can bind safely. Anything else (notably 0.0.0.0) is rejected.
func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "::1":
		return true
	default:
		return strings.EqualFold(host, "localhost")
	}
}
