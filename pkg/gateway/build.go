package gateway

import (
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/redact"
)

// builtinDetectors maps a canonical detector id to its constructor. The ids
// match config.Detector* exactly; the constructors share the pkg/redact Option
// signature so the config allowlist reaches every one.
var builtinDetectors = map[string]func(...redact.Option) extension.Inspector{
	config.DetectorPrefix:      redact.NewPrefixDetector,
	config.DetectorHighEntropy: redact.NewHighEntropyDetector,
	config.DetectorJWT:         redact.NewJWTDetector,
	config.DetectorPrivateKey:  redact.NewPrivateKeyDetector,
	config.DetectorLuhn:        redact.NewLuhnDetector,
	config.DetectorEmail:       redact.NewEmailDetector,
}

// BuildOptions is the input to BuildPipeline.
type BuildOptions struct {
	// Detectors is the ordered list of enabled detector ids.
	Detectors []string
	// Allowlist forwards the config allowlist to every detector.
	Allowlist []string
	// Sink receives metadata-only audit rows from the policy and pipeline.
	Sink audit.AuditSink
	// Timeout bounds one detector invocation; <= 0 uses the default.
	Timeout time.Duration
	// Tool labels the content Document (for example "claude-code").
	Tool string
	// AllowlistStore 是 C7 的运行时白名单句柄，供检测器在请求期读取共享快照；
	// nil = 仅静态 Allowlist（零值即旧行为）。
	AllowlistStore AllowlistStore
	// SelfProtection 是 C8 的装配配置（窄口径排除集 + control token）；
	// 零值 = 关闭（零值即旧行为）。
	SelfProtection SelfProtectionConfig
}

// BuildPipeline assembles the content pipeline for one session: the enabled
// built-in detectors in a registry, a policy with fail-closed detector
// settings, and a fresh placeholder engine. The core CLI calls it; the Pro
// daemon has its own builder that can register extra plugin families. The
// gateway itself never builds a pipeline.
func BuildPipeline(opts BuildOptions) (*proxy.Pipeline, error) {
	registry, err := buildRegistry(opts.Detectors, opts.Allowlist, opts.AllowlistStore)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultDetectorTimeout
	}
	policy := extension.NewPolicy(registry, extension.PolicyConfig{
		Sink:     opts.Sink,
		Timeout:  timeout,
		Failures: failClosedDetectors(opts.Detectors),
	})
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		return nil, err
	}
	return proxy.NewPipeline(proxy.PipelineConfig{
		Registry: registry,
		Policy:   policy,
		Engine:   engine,
		Sink:     opts.Sink,
		Tool:     opts.Tool,
		// C8 接缝：此处只搬运原语，零值 = 完全无操作；拦截实现归 W6.1–W6.4。
		SelfProtectionEnabled: opts.SelfProtection.Enabled,
		SelfProtectionModes:   opts.SelfProtection.Modes,
		Exclusions:            opts.SelfProtection.Exclusions,
		ControlToken:          opts.SelfProtection.ControlToken,
	})
}

// buildRegistry registers the enabled built-in detectors in config order. A
// registration failure is a construction error: the registry is the security
// gate, so a rejected plugin must abort startup rather than be skipped.
func buildRegistry(detectors, allowlist []string, store AllowlistStore) (*extension.Registry, error) {
	registry := extension.NewRegistry()
	options := detectorOptions(allowlist, store)
	for _, id := range detectors {
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
// allowlist passes no options so the detector defaults apply. A nil store
// passes no runtime source (zero value = the pre-seam behaviour); a non-nil
// store wires the shared handle so every detector reads it at Inspect time
// (ADR-0012 A2: the effective literals are static ∪ dynamic, never a
// replacement of the static set).
func detectorOptions(allowlist []string, store AllowlistStore) []redact.Option {
	var options []redact.Option
	if len(allowlist) > 0 {
		options = append(options, redact.WithAllowlist(allowlist...))
	}
	if store != nil {
		options = append(options, redact.WithAllowlistSource(store.Entries))
	}
	return options
}

// failClosedDetectors marks every enabled built-in detector FailClosed. The
// detectors scan attacker-influenced bodies; under the advisory FailOpenWarn
// default a timeout on a large body would silently drop the finding and leak
// the secret upstream. FailClosed turns a detector timeout or error into a
// Block instead.
func failClosedDetectors(detectors []string) map[string]extension.FailurePolicy {
	failures := make(map[string]extension.FailurePolicy, len(builtinDetectors))
	for _, id := range detectors {
		failures[id] = extension.FailClosed
	}
	return failures
}
