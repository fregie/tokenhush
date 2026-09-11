package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// Control-plane routes the outer mux reserves for the daemon's control API.
// They mirror the unexported constants in pkg/proxy; the control API itself
// applies the Go 1.22 method patterns (GET only) once a request reaches it.
const (
	controlStatusPath = "/status"
	controlAuditPath  = "/audit"
)

// Daemon tuning. The detector timeout is deliberately generous: the built-in
// detectors are configured FailClosed, so a too-short timeout would turn a
// large but legitimate request into a block. shutdownTimeout bounds how long a
// Ctrl-C waits for in-flight requests before the process files are removed.
const (
	defaultDetectorTimeout = 5 * time.Second
	shutdownTimeout        = 5 * time.Second
)

// Audit metadata stamped on the daemon's own lifecycle rows. Value rows carry
// no content; the real store is wired in W5.3.
const (
	auditProviderDaemon = "daemon"
	auditMethodRun      = "run"
)

// RunDeps carries the injectable seams of RunServer. The zero value is the
// production configuration: platform config/data directories, no-op audit
// seams, and the default detector timeout.
type RunDeps struct {
	// ConfigPath is loaded only when cfg is nil: an explicit tokenhush.yaml
	// path, or the platform default when empty.
	ConfigPath string
	// DataDir overrides platform.DataDir(); it holds the control token and the
	// pid/port file. Empty means the platform data directory.
	DataDir string
	// Sink receives metadata-only audit rows (lifecycle events, policy warnings
	// and unknown-path rejections). Nil means audit.NoopSink{}.
	Sink audit.AuditSink
	// Querier backs the control API GET /audit. Nil means audit.NoopQuerier{}.
	Querier audit.AuditQuerier
	// Stdout receives the human-facing startup lines. Nil discards them.
	Stdout io.Writer
	// Stderr is reserved for diagnostics. Nil discards them.
	Stderr io.Writer
	// PolicyTimeout bounds one content-detector invocation. Zero uses
	// defaultDetectorTimeout. It is the seam the fail-closed test drives to
	// force a detector timeout deterministically.
	PolicyTimeout time.Duration
	// Ready, when set, is called once the daemon is accepting connections and
	// its session files exist. It is how tests learn the bound ephemeral port.
	Ready func(RunInfo)
}

// RunInfo is the daemon's post-startup snapshot handed to RunDeps.Ready.
type RunInfo struct {
	Addrs []string
	Port  int
}

// RunServer assembles and runs the foreground gateway until ctx is cancelled.
//
// Assembly order (docs/13 §1/§3.3/§3.4): build the content pipeline (detectors
// -> policy -> placeholder engine) -> bind both loopback listeners before any
// session state is written, so a busy port fails fast and leaves nothing stale
// -> persist the per-session control token and pid/port file -> wire the
// per-request resolver and forwarder behind the response pipeline -> serve the
// control plane behind Host/Origin/bearer guards and the data plane behind the
// Host allowlist alone -> block until ctx is done, then shut down gracefully.
//
// A nil cfg is loaded from deps.ConfigPath (or the platform default). The
// returned error wraps pkg/proxy's typed listener errors (for example
// ErrAddrInUse), so callers can classify with errors.Is.
func RunServer(ctx context.Context, cfg *config.Config, deps RunDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	stdout := deps.Stdout
	if stdout == nil {
		stdout = io.Discard
	}

	loaded, err := resolveConfig(cfg, deps.ConfigPath)
	if err != nil {
		return err
	}
	dataDir := deps.DataDir
	if dataDir == "" {
		dataDir, err = platform.DataDir()
		if err != nil {
			return err
		}
	}
	sink := deps.Sink
	if sink == nil {
		sink = audit.NoopSink{}
	}
	querier := deps.Querier
	if querier == nil {
		querier = audit.NoopQuerier{}
	}

	pipeline, err := buildPipeline(loaded, sink, deps.PolicyTimeout)
	if err != nil {
		return err
	}

	// Bind before writing the token/pid file: a busy port must not leave a
	// stale session behind (adversarial class: stale_state).
	listeners, err := proxy.Listen(loaded.Listen.Host, int(loaded.Listen.Port))
	if err != nil {
		return err
	}

	port := listeners.Port()
	addrs := listenerAddrs(listeners)

	token, _, err := proxy.NewControlToken(dataDir)
	if err != nil {
		_ = listeners.Close()
		return err
	}
	state := RunState{
		PID:       os.Getpid(),
		Port:      port,
		Addrs:     addrs,
		StartedAt: time.Now().UnixMilli(),
	}
	if err := writeRunState(dataDir, state); err != nil {
		cleanupSessionFiles(dataDir)
		_ = listeners.Close()
		return err
	}

	resolver := proxy.NewResolver(loaded.Upstreams, sink)
	daemon := &daemon{
		pipeline:  pipeline,
		plane:     newDataPlane(resolver, pipeline),
		querier:   querier,
		token:     token,
		startedAt: time.Now(),
		addrs:     addrs,
	}
	srv := &http.Server{
		Handler:        daemon.handler(port),
		MaxHeaderBytes: proxy.MaxHeaderBytes,
	}

	daemon.recordStartup(sink)
	fmt.Fprintf(stdout, "tokenhush: gateway listening on http://127.0.0.1:%d\n", port)
	fmt.Fprintf(stdout, "tokenhush: control token file: %s\n", controlTokenPath(dataDir))
	if deps.Ready != nil {
		deps.Ready(RunInfo{Addrs: addrs, Port: port})
	}

	runErr := serveUntilDone(ctx, srv, listeners)
	daemon.recordShutdown(sink)
	cleanupSessionFiles(dataDir)
	return runErr
}

// resolveConfig returns cfg when set, otherwise loads it from path or the
// platform default. A partially populated cfg is never mutated.
func resolveConfig(cfg *config.Config, path string) (*config.Config, error) {
	if cfg != nil {
		return cfg, nil
	}
	if path != "" {
		return config.LoadFile(path)
	}
	return config.Load()
}

// serveUntilDone starts one Serve goroutine per loopback listener and blocks
// until ctx is cancelled or a listener fails. It then shuts the server down
// with a bounded deadline and drains both goroutines, so no request is still
// writing when RunServer removes the session files.
func serveUntilDone(ctx context.Context, srv *http.Server, ls *proxy.Listeners) error {
	errCh := make(chan error, 2)
	for _, listener := range []net.Listener{ls.V4(), ls.V6()} {
		go func(l net.Listener) { errCh <- srv.Serve(l) }(listener)
	}

	var runErr error
	served := 0
	select {
	case <-ctx.Done():
	case err := <-errCh:
		served++
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = err
	}
	for served < 2 {
		err := <-errCh
		served++
		if err != nil && !errors.Is(err, http.ErrServerClosed) && runErr == nil {
			runErr = err
		}
	}
	return runErr
}

// daemon holds the assembled control-plane state and the shared data plane.
type daemon struct {
	pipeline  *proxy.Pipeline
	plane     *dataPlane
	querier   audit.AuditQuerier
	token     string
	startedAt time.Time
	addrs     []string
}

// handler composes the two planes on one mux:
//
//   - control paths are wrapped HostAllowlist -> OriginPolicy -> ControlAuth
//     and registered for GET explicitly; the method-less pattern keeps a
//     non-GET method on a control path inside the control API (JSON 405)
//     instead of letting it fall through to the data plane;
//   - everything else is the pipeline-wrapped data plane behind HostAllowlist
//     alone, so proxied traffic never needs the control bearer token.
func (d *daemon) handler(port int) http.Handler {
	control := proxy.NewControlAPI(d.status, d.querier)
	guardedControl := proxy.HostAllowlist(port)(
		proxy.OriginPolicy(proxy.ControlAuth(func() string { return d.token })(control)))
	dataPlane := proxy.HostAllowlist(port)(d.pipeline.ResponseMiddleware(d.plane))

	mux := http.NewServeMux()
	for _, path := range []string{controlStatusPath, controlAuditPath} {
		mux.Handle("GET "+path, guardedControl)
		mux.Handle(path, guardedControl)
	}
	mux.Handle("/", dataPlane)
	return mux
}

// status is the live snapshot GET /status serializes. Counters are session
// scoped and metadata-only.
func (d *daemon) status() proxy.ControlStatus {
	return proxy.ControlStatus{
		State:      proxy.ControlStateRunning,
		Addrs:      append([]string(nil), d.addrs...),
		UptimeMS:   time.Since(d.startedAt).Milliseconds(),
		Requests:   d.plane.requests.Load(),
		Redactions: d.plane.redactions.Load(),
	}
}

// recordStartup writes the daemon-start audit row. A sink failure is ignored:
// the real store is W5.3 and a best-effort seam must not abort startup.
func (d *daemon) recordStartup(sink audit.AuditSink) {
	_ = sink.Record(audit.Record{
		TS:       time.Now().UnixMilli(),
		Provider: auditProviderDaemon,
		Method:   auditMethodRun,
		Path:     "start",
	})
}

// recordShutdown writes the daemon-stop audit row, best effort.
func (d *daemon) recordShutdown(sink audit.AuditSink) {
	_ = sink.Record(audit.Record{
		TS:       time.Now().UnixMilli(),
		Provider: auditProviderDaemon,
		Method:   auditMethodRun,
		Path:     "stop",
	})
}

// listenerAddrs renders the bound addresses in v4, v6 order.
func listenerAddrs(ls *proxy.Listeners) []string {
	addrs := make([]string, 0, 2)
	for _, addr := range ls.Addrs() {
		addrs = append(addrs, addr.String())
	}
	return addrs
}

// runCommand is the CLI entry for `tokenhush run`: it parses the documented
// flags, loads the config, installs Ctrl-C/SIGTERM handling and delegates to
// RunServer. It returns an exit code and never calls os.Exit.
func runCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath string
		port       int
		logLevel   string
	)
	fs.StringVar(&configPath, "config", "", "path to tokenhush.yaml (default: platform config dir)")
	fs.IntVar(&port, "port", 0, "override listen port (1..65535)")
	fs.StringVar(&logLevel, "log-level", "", "override log level (debug|info|warn|error)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: run: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}

	cfg, err := resolveConfig(nil, configPath)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := RunServer(ctx, cfg, RunDeps{Stdout: stdout, Stderr: stderr}); err != nil {
		fmt.Fprintf(stderr, "tokenhush: run: %v\n", err)
		return ExitFailure
	}
	return ExitOK
}
