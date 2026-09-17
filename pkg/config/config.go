package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/goccy/go-yaml"
)

// maxConfigBytes bounds how much of tokenhush.yaml is read. The V1 config is a
// short, hand-written file; anything bigger is either a mistake or hostile and
// fails fast with ErrTooLarge.
const maxConfigBytes = 1 << 20 // 1 MiB

// maxConfigEntryBytes bounds one allowlist entry. Entries are literals, not
// documents, so anything longer is a mistake or hostile and is rejected rather
// than truncated. maxConfigBytes still bounds the file as a whole.
const maxConfigEntryBytes = 4096

// Canonical detector ids, matching docs/configuration.md. Note the deliberate mismatch
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

// Canonical self-protection mode ids, matching the `self_protection.modes`
// values in docs/tool-setup.md. Unlike the detectors there is no key/id
// mismatch to remember: the YAML names and the ids are identical.
const (
	SelfProtectionModeCLICommand  = "cli-command"
	SelfProtectionModeControlPort = "control-port"
	SelfProtectionModeFileWrite   = "file-write"
)

// canonicalSelfProtectionModes is the frozen order used by
// SelfProtection.EnabledModes and the accepted value set of `modes:`.
var canonicalSelfProtectionModes = [...]string{
	SelfProtectionModeCLICommand,
	SelfProtectionModeControlPort,
	SelfProtectionModeFileWrite,
}

// Config is a fully loaded and validated V1 configuration.
type Config struct {
	Listen    Listen    `yaml:"listen"`
	Detectors Detectors `yaml:"detectors"`
	// Allowlist holds literals that are never redacted. The key keeps being
	// read after the runtime allowlist store exists: at startup these entries
	// seed the store and both sources stay active, so the effective allowlist
	// is the union of the static and runtime entries, never a replacement.
	// Matching stays byte-exact contains (pkg/redact).
	Allowlist []string  `yaml:"allowlist"`
	Log       Log       `yaml:"log"`
	Upstreams Upstreams `yaml:"upstreams"`
	// SelfProtection is the change-channel guard; Default() returns it
	// hardened (enabled, all three modes).
	SelfProtection SelfProtection `yaml:"self_protection"`
}

// Listen is the loopback listener. Host is restricted to 127.0.0.1, ::1 or
// localhost; the wildcard is rejected by validate.
type Listen struct {
	Host string `yaml:"host"`
	Port Port   `yaml:"port"`
}

// Detectors mirrors the `detectors:` block. Five detectors default to on;
// `high_entropy` defaults to **off** (a deliberate precision decision: its
// structural exemptions still produced false positives on real agent traffic —
// long tool names and session ids were redacted as if they were secrets, which
// broke function calling — so it is wired but disabled unless explicitly
// enabled). ScanBudgetBytes and Timeout tune the deterministic scan budget and
// the wall-clock backstop; their zero values mean "use the built-in defaults".
type Detectors struct {
	Prefix      bool `yaml:"prefixes"`
	HighEntropy bool `yaml:"high_entropy"`
	JWT         bool `yaml:"jwt"`
	PrivateKey  bool `yaml:"private_keys"`
	Luhn        bool `yaml:"luhn"`
	Email       bool `yaml:"email"`
	// ScanBudgetBytes bounds the deterministic per-request scan budget: a body
	// larger than this is refused before any detector runs. The verdict depends
	// only on the input size, never on CPU speed or load. 0 uses the built-in
	// 32 MiB default. Exceeding it refuses by design and never partially scans.
	ScanBudgetBytes int64 `yaml:"scan_budget_bytes"`
	// Timeout is the wall-clock backstop that bounds one detector invocation.
	// It is deliberately generous so a large legitimate body on a slow machine
	// still completes; normal operation never reaches it. 0 uses the built-in
	// 30s default.
	Timeout time.Duration `yaml:"timeout"`
}

// EnabledIDs returns the canonical ids of all enabled detectors in
// docs/configuration.md order, so the redaction engine never has to know YAML key names.
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

// SelfProtection mirrors the `self_protection:` block: the change-channel
// guard that keeps a model from weakening redaction through tool calls. It is
// hardening by default, so a config file that omits the block keeps every
// interception mode on; only an explicit `enabled: false` opts out (with
// `enabled: true`, at least one mode is required).
//
// The guard's exclusion set is deliberately NOT configurable: it is frozen to
// the control-token value plus the full <DataDir>/allowlist.json content, both
// derived at runtime by the gateway, so that no config value — and therefore
// no model-influenced input — can widen or shrink what is force-redacted and
// never restored.
type SelfProtection struct {
	Enabled bool     `yaml:"enabled"`
	Modes   []string `yaml:"modes"`
}

// EnabledModes returns the active interception categories in canonical
// docs/tool-setup.md order, so the gateway never has to know the YAML shapes.
// A disabled SelfProtection has no enabled modes; values outside the frozen
// set are rejected by validate and ignored here.
func (s SelfProtection) EnabledModes() []string {
	if !s.Enabled {
		return nil
	}
	var modes []string
	for _, mode := range canonicalSelfProtectionModes {
		if s.hasMode(mode) {
			modes = append(modes, mode)
		}
	}
	return modes
}

func (s SelfProtection) hasMode(mode string) bool {
	for _, m := range s.Modes {
		if m == mode {
			return true
		}
	}
	return false
}

// Log configures the daemon log level.
type Log struct {
	Level string `yaml:"level"`
}

// Default returns the opinionated V1 defaults from docs/configuration.md.
func Default() Config {
	return Config{
		Listen: Listen{Host: "127.0.0.1", Port: 8787},
		Detectors: Detectors{
			Prefix:      true,
			HighEntropy: false,
			JWT:         true,
			PrivateKey:  true,
			Luhn:        true,
			Email:       true,
			// Mirrors pkg/proxy.DefaultScanBudget and pkg/extension's default
			// backstop; the numbers are stated here so a config sample shows the
			// effective defaults.
			ScanBudgetBytes: 32 << 20,
			Timeout:         30 * time.Second,
		},
		Allowlist: []string{},
		Log:       Log{Level: "info"},
		SelfProtection: SelfProtection{
			Enabled: true,
			Modes: []string{
				SelfProtectionModeCLICommand,
				SelfProtectionModeControlPort,
				SelfProtectionModeFileWrite,
			},
		},
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
	if err := c.SelfProtection.validate(path); err != nil {
		return err
	}
	return validateAllowlist(path, c.Allowlist)
}

// validate rejects unusable self_protection values: modes outside the frozen
// set, duplicate modes, and `enabled: true` with an explicit empty modes list,
// which would announce the guard as on while enforcing nothing. `enabled:
// false` is an explicit user choice and is accepted without a warning; an
// omitted `modes:` key inherits the hardened three-mode default (see Default).
func (s SelfProtection) validate(path string) error {
	if s.Enabled && len(s.Modes) == 0 {
		return &Error{
			Path:   path,
			Field:  "self_protection.modes",
			Reason: "enabled: true requires at least one mode (" + strings.Join(canonicalSelfProtectionModes[:], "|") + "); use enabled: false to opt out",
			Err:    ErrInvalidSelfProtection,
		}
	}
	seen := make(map[string]struct{}, len(s.Modes))
	for i, mode := range s.Modes {
		if !isSelfProtectionMode(mode) {
			return &Error{
				Path:   path,
				Field:  "self_protection.modes",
				Reason: fmt.Sprintf("mode %d %q is not one of %s", i, mode, strings.Join(canonicalSelfProtectionModes[:], "|")),
				Err:    ErrInvalidSelfProtection,
			}
		}
		if _, duplicate := seen[mode]; duplicate {
			return &Error{
				Path:   path,
				Field:  "self_protection.modes",
				Reason: fmt.Sprintf("mode %q is duplicated", mode),
				Err:    ErrInvalidSelfProtection,
			}
		}
		seen[mode] = struct{}{}
	}
	return nil
}

func isSelfProtectionMode(mode string) bool {
	for _, known := range canonicalSelfProtectionModes {
		if mode == known {
			return true
		}
	}
	return false
}

// validateAllowlist rejects unusable `allowlist:` entries as a typed error; it
// does not change matching semantics, which stay byte-exact contains in
// pkg/redact.
func validateAllowlist(path string, entries []string) error {
	for i, entry := range entries {
		if reason, bad := entryProblem(entry); bad {
			return &Error{
				Path:   path,
				Field:  "allowlist",
				Reason: fmt.Sprintf("entry %d %s", i, reason),
				Err:    ErrInvalidAllowlist,
			}
		}
	}
	return nil
}

// entryProblem reports why an allowlist entry is unusable.
func entryProblem(entry string) (string, bool) {
	switch {
	case entry == "":
		return "must not be empty", true
	case strings.IndexFunc(entry, unicode.IsControl) >= 0:
		return "must not contain control characters", true
	case len(entry) > maxConfigEntryBytes:
		return fmt.Sprintf("must be at most %d bytes, got %d", maxConfigEntryBytes, len(entry)), true
	}
	return "", false
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
