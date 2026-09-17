package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fregie/tokenhush/pkg/allowlist"
	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/gateway"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// RunDeps carries the injectable seams of RunServer. The zero value is the
// production configuration: platform config/data directories and the default
// detector timeout.
type RunDeps struct {
	// ConfigPath is loaded only when cfg is nil: an explicit tokenhush.yaml
	// path, or the platform default when empty.
	ConfigPath string
	// DataDir overrides platform.DataDir(); it holds the control token, the
	// pid/port file and the C7 allowlist store (<DataDir>/allowlist.json).
	// Empty means the platform data directory.
	DataDir string
	// Stdout receives the human-facing startup lines. Nil discards them.
	Stdout io.Writer
	// Stderr is the diagnostics stream: the default-on masked redaction log, the
	// rules startup/fallback warnings and the C7 allowlist-store degradation
	// warnings are written here. When nil, all are silenced; in particular the
	// rule-fallback warning is dropped, never written to Stdout and never a
	// panic.
	Stderr io.Writer
	// PolicyTimeout bounds one content-detector invocation. Zero uses the
	// gateway default. It is the seam the fail-closed test drives to force a
	// detector timeout deterministically.
	PolicyTimeout time.Duration
	// Pipeline overrides the assembled content pipeline. Nil builds it from
	// cfg through gateway.BuildPipeline. Tests inject a pipeline with a
	// channel-gated detector so a fail-safe path is forced by the policy
	// timeout rather than a wall-clock race.
	Pipeline *proxy.Pipeline
	// Ready, when set, is called once the daemon is accepting connections and
	// its session files exist. It is how tests learn the bound ephemeral port.
	Ready func(RunInfo)
	// DisableRedactionLog turns off the default-on masked redaction log. At the
	// zero value the log is on (the production behavior): when Stderr is set,
	// the daemon prints one masked line per replaced value and per policy block.
	// Set it when a caller wants a silent daemon.
	DisableRedactionLog bool
}

// RunInfo is the daemon's post-startup snapshot handed to RunDeps.Ready. It is
// an alias of the gateway's contract type.
type RunInfo = gateway.RunInfo

// RunServer assembles and runs the foreground gateway until ctx is cancelled.
//
// It is the thin RunDeps -> gateway.Options adapter that keeps the existing
// CLI seam: it resolves the config, builds the content pipeline through
// gateway.BuildPipeline (unless a test injected one), and delegates the whole
// process shell and request path to gateway.Run.
//
// A nil cfg is loaded from deps.ConfigPath (or the platform default). When it
// builds the pipeline it also reads the cached remote rule pack from the local
// cache (never the network); a missing or unusable pack falls back to the
// built-in detectors with a warning on deps.Stderr. The returned error also
// wraps pkg/proxy's typed listener errors (for example ErrAddrInUse), so
// callers can classify with errors.Is.
func RunServer(ctx context.Context, cfg *config.Config, deps RunDeps) error {
	loaded, err := gateway.ResolveConfig(cfg, deps.ConfigPath)
	if err != nil {
		return err
	}

	// The core has no audit implementation (ADR-0009): it passes the no-op
	// seam, used only by the default resolver's unknown-path rejection row.
	sink := audit.NoopSink{}

	// C7 生产装配（W5.1）：store 持久化到 <DataDir>/allowlist.json，数据根必须在
	// 这里确定——gateway.Run 内部的解析发生在 pipeline 构造之后，而 store 在构造
	// detector 时就要接线。deps.DataDir 显式指定时原样使用，否则读平台默认（与
	// gateway.Run 的回退路径同一个值，并由 Setup 固定给本次会话）。
	dataDir := deps.DataDir
	if dataDir == "" {
		resolved, err := platform.DataDir()
		if err != nil {
			return err
		}
		dataDir = resolved
	}
	warn := deps.Stderr
	if warn == nil {
		warn = io.Discard
	}
	allowlistStore, err := allowlist.Open(dataDir, loaded.Allowlist, warn)
	if err != nil {
		return err
	}

	// C8 自保护的装配配置（加固默认）：Enabled/Modes 来自配置，排除集的两个值
	// （control.token 值 + <DataDir>/allowlist.json 内容）由 gateway.Run 在会话
	// 令牌生成后经 SetSelfProtectionExclusions 安装——令牌在 pipeline 构造时尚
	// 不存在，而 ADR-0012 冻结了「先绑定端口再写令牌」。同一份配置同时交给
	// BuildPipeline 与 gateway.Options（与 Pro 侧装配同形）。
	selfProtection := gateway.SelfProtectionConfig{
		Enabled: loaded.SelfProtection.Enabled,
		Modes:   loaded.SelfProtection.EnabledModes(),
	}

	pipeline := deps.Pipeline
	if pipeline == nil {
		timeout := deps.PolicyTimeout
		if timeout <= 0 {
			timeout = loaded.Detectors.Timeout
		}
		buildOpts := gateway.BuildOptions{
			Detectors:      loaded.Detectors.EnabledIDs(),
			Allowlist:      loaded.Allowlist,
			Rules:          activeRulesConfig(deps.Stderr),
			Sink:           sink,
			Timeout:        timeout,
			AllowlistStore: allowlistStore,
			SelfProtection: selfProtection,
		}
		pipeline, err = gateway.BuildPipeline(buildOpts)
		if err != nil {
			if !isRulesError(err) {
				return err
			}
			// A pack that passed Active() should always compile, so this is a
			// defensive fallback: drop the pack, keep the built-in detectors.
			warn := ruleWarn(deps.Stderr)
			warn(fmt.Sprintf("tokenhush: rules: %v; using built-in defaults", err))
			buildOpts.Rules = nil
			pipeline, err = gateway.BuildPipeline(buildOpts)
			if err != nil {
				return err
			}
		}
		// The deterministic byte budget is not part of the frozen ADR-0012
		// BuildOptions contract, so it is installed after construction. 0 keeps
		// pkg/proxy's built-in default.
		pipeline.SetScanBudget(loaded.Detectors.ScanBudgetBytes)
	}

	if !deps.DisableRedactionLog && deps.Stderr != nil {
		pipeline.SetRedactionReporter(newRedactionLogger(deps.Stderr).Report)
	}

	opts := gateway.Options{
		Core:           *loaded,
		Sink:           sink,
		Pipeline:       pipeline,
		PolicyTimeout:  deps.PolicyTimeout,
		Stdout:         deps.Stdout,
		Stderr:         deps.Stderr,
		Ready:          deps.Ready,
		AllowlistStore: allowlistStore,
		SelfProtection: selfProtection,
		// 固定本次会话的数据根：store 文件与 run.json/control.token 必须落在同一个
		// 目录（此前仅在 deps.DataDir 显式指定时固定；现在 store 也需要它）。
		Setup: func(d *gateway.Deps) error {
			d.DataDir = dataDir
			return nil
		},
	}
	return gateway.Run(ctx, opts)
}

// runCommand is the CLI entry for `tokenhush run`: it parses the documented
// flags, loads the config, installs Ctrl-C/SIGTERM handling and delegates to
// RunServer. It returns an exit code and never calls os.Exit.
func runCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath    string
		port          int
		logLevel      string
		logRedactions bool
	)
	fs.StringVar(&configPath, "config", "", "path to tokenhush.yaml (default: platform config dir)")
	fs.IntVar(&port, "port", 0, "override listen port (1..65535)")
	fs.StringVar(&logLevel, "log-level", "", "override log level (debug|info|warn|error)")
	fs.BoolVar(&logRedactions, "log-redactions", true, "print a masked line for every redacted value")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: run: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}

	cfg, err := gateway.ResolveConfig(nil, configPath)
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: run: %v\n", err)
		return ExitFailure
	}
	if port != 0 {
		if port < 1 || port > 65535 {
			fmt.Fprintln(stderr, "tokenhush: run: --port must be in 1..65535")
			return ExitUsage
		}
		cfg.Listen.Port = config.Port(port)
	}
	if logLevel != "" {
		switch logLevel {
		case "debug", "info", "warn", "error":
			cfg.Log.Level = logLevel
		default:
			fmt.Fprintf(stderr, "tokenhush: run: --log-level must be debug|info|warn|error, got %q\n", logLevel)
			return ExitUsage
		}
	}

	writeStartupSummary(stdout, cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := RunServer(ctx, cfg, RunDeps{Stdout: stdout, Stderr: stderr, DisableRedactionLog: !logRedactions}); err != nil {
		fmt.Fprintf(stderr, "tokenhush: run: %v\n", err)
		return ExitFailure
	}
	return ExitOK
}
