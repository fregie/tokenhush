package cli

import (
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/redact"
)

// builtinDetectors maps a canonical detector id (docs/13 §5.1) to its
// constructor. The ids match config.Detector* exactly; the constructors share
// the pkg/redact Option signature so the config allowlist reaches every one.
var builtinDetectors = map[string]func(...redact.Option) extension.Inspector{
	config.DetectorPrefix:      redact.NewPrefixDetector,
	config.DetectorHighEntropy: redact.NewHighEntropyDetector,
	config.DetectorJWT:         redact.NewJWTDetector,
	config.DetectorPrivateKey:  redact.NewPrivateKeyDetector,
	config.DetectorLuhn:        redact.NewLuhnDetector,
	config.DetectorEmail:       redact.NewEmailDetector,
}

// buildPipeline assembles the W4.5 content pipeline for one daemon session:
// the enabled built-in detectors registered in a W4.1 Registry, a W4.2 Policy
// with the fail-closed detector settings, and a fresh W4.4 placeholder engine.
func buildPipeline(cfg *config.Config, sink audit.AuditSink, timeout time.Duration) (*proxy.Pipeline, error) {
	registry, err := buildRegistry(cfg)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultDetectorTimeout
	}
	policy := extension.NewPolicy(registry, extension.PolicyConfig{
		Sink:     sink,
		Timeout:  timeout,
		Failures: failClosedDetectors(cfg),
	})
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		return nil, err
	}
	return proxy.NewPipeline(proxy.PipelineConfig{
		Registry: registry,
		Policy:   policy,
		Engine:   engine,
		Sink:     sink,
	})
}

// buildRegistry registers the enabled built-in detectors in config order. A
// registration failure is a construction error: the registry is the security
// gate, so a rejected plugin must abort startup rather than be skipped.
func buildRegistry(cfg *config.Config) (*extension.Registry, error) {
	registry := extension.NewRegistry()
	options := detectorOptions(cfg.Allowlist)
	for _, id := range cfg.Detectors.EnabledIDs() {
		constructor, ok := builtinDetectors[id]
		if !ok {
			continue
		}
		if err := registry.Register(constructor(options...)); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// detectorOptions forwards the config allowlist to every detector; an empty
// allowlist passes no options so the detector defaults apply.
func detectorOptions(allowlist []string) []redact.Option {
	if len(allowlist) == 0 {
		return nil
	}
	return []redact.Option{redact.WithAllowlist(allowlist...)}
}

// failClosedDetectors marks every enabled built-in detector FailClosed. The
// detectors scan attacker-influenced bodies; under the advisory FailOpenWarn
// default a timeout on a large body would silently drop the finding and leak
// the secret upstream (W4.5 finding). FailClosed turns a detector timeout or
// error into a Block instead.
func failClosedDetectors(cfg *config.Config) map[string]extension.FailurePolicy {
	failures := make(map[string]extension.FailurePolicy, len(builtinDetectors))
	for _, id := range cfg.Detectors.EnabledIDs() {
		failures[id] = extension.FailClosed
	}
	return failures
}
