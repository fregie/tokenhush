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
)

// Daemon tuning. The detector timeout is deliberately generous: the built-in
// detectors are configured FailClosed, so a too-short timeout would turn a
// large but legitimate request into a block. shutdownTimeout bounds how long a
// Ctrl-C waits for in-flight requests before the process files are removed.
const (
	defaultDetectorTimeout = 5 * time.Second
	shutdownTimeout        = 5 * time.Second
)

// RunDeps carries the injectable seams of RunServer. The zero value is the
// production configuration: platform config/data directories and the default
// detector timeout.
type RunDeps struct {
	// ConfigPath is loaded only when cfg is nil: an explicit tokenhush.yaml
	// path, or the platform default when empty.
	ConfigPath string
	// DataDir overrides platform.DataDir(); it holds the control token and the
	// pid/port file. Empty means the platform data directory.
	DataDir string
	// Stdout receives the human-facing startup lines. Nil discards them.
	Stdout io.Writer
	// Stderr is the diagnostics stream, kept in the seam for callers; the
	// audit-free core writes only to Stdout.
	Stderr io.Writer
	// PolicyTimeout bounds one content-detector invocation. Zero uses
	// defaultDetectorTimeout. It is the seam the fail-closed test drives to
	// force a detector timeout deterministically.
	PolicyTimeout time.Duration
	// Pipeline overrides the assembled content pipeline. Nil builds it from
	// cfg, the audit sink and PolicyTimeout. Tests inject a pipeline with a
	// channel-gated detector so a fail-safe path is forced by the policy
	// timeout rather than a wall-clock race.
	Pipeline *proxy.Pipeline
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
// returned error also wraps pkg/proxy's typed listener errors (for example
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

	sink := audit.NoopSink{}

	pipeline := deps.Pipeline
	if pipeline == nil {
		pipeline, err = buildPipeline(loaded, sink, deps.PolicyTimeout)
		if err != nil {
			return err
		}
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
		sink:      sink,
		token:     token,
		startedAt: time.Now(),
		addrs:     addrs,
	}
	srv := &http.Server{
		Handler:        daemon.handler(port),
		MaxHeaderBytes: proxy.MaxHeaderBytes,
	}

	fmt.Fprintf(stdout, "tokenhush: gateway listening on http://127.0.0.1:%d\n", port)
	fmt.Fprintf(stdout, "tokenhush: control token file: %s\n", controlTokenPath(dataDir))
	if deps.Ready != nil {
		deps.Ready(RunInfo{Addrs: addrs, Port: port})
	}

	runErr := serveUntilDone(ctx, srv, listeners)
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
	sink      audit.AuditSink
	token     string
	startedAt time.Time
	addrs     []string
}

// handler composes the two planes on one mux:
//
//   - the control path is wrapped HostAllowlist -> OriginPolicy -> ControlAuth
//     and registered for GET explicitly; the method-less pattern keeps a
//     non-GET method on the control path inside the control API (JSON 405)
//     instead of letting it fall through to the data plane;
//   - everything else is the pipeline-wrapped data plane behind HostAllowlist
//     alone, so proxied traffic never needs the control bearer token.
func (d *daemon) handler(port int) http.Handler {
	control := proxy.NewControlAPI(d.status)
	guardedControl := proxy.HostAllowlist(port)(
		proxy.OriginPolicy(proxy.ControlAuth(func() string { return d.token })(control)))
	dataPlane := proxy.HostAllowlist(port)(d.auditRequests(d.pipeline.ResponseMiddleware(d.plane)))

	mux := http.NewServeMux()
	mux.Handle("GET "+controlStatusPath, guardedControl)
	mux.Handle(controlStatusPath, guardedControl)
	mux.Handle("/", dataPlane)
	return mux
}

// auditRequests wraps the data plane so one metadata-only audit row is written
// per proxied response. It sits outside the response pipeline, so the status
// and byte counts it observes are the ones the client actually received (a
// response-pipeline rewrite or block is reflected). The per-request stats are
// threaded through the request context for the data plane to fill in.
func (d *daemon) auditRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats := &requestStats{path: r.URL.Path, method: r.Method}
		ctx := context.WithValue(r.Context(), requestStatsKey{}, stats)
		aw := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(aw, r.WithContext(ctx))
		status := aw.status
		if status == 0 {
			status = http.StatusOK
		}
		d.recordRequest(stats, status, aw.bytes)
	})
}

// recordRequest commits one metadata-only row for a request the data plane
// successfully resolved. An unresolved path is already recorded by the
// resolver's own rejection row, so it is skipped here to avoid a duplicate.
func (d *daemon) recordRequest(stats *requestStats, status, respBytes int) {
	if stats == nil || !stats.proxied {
		return
	}
	_ = d.sink.Record(audit.Record{
		TS:         time.Now().UnixMilli(),
		Provider:   stats.provider,
		Path:       stats.path,
		Method:     stats.method,
		Status:     status,
		ReqBytes:   int64(stats.reqBytes),
		RespBytes:  int64(respBytes),
		Redactions: stats.redactions,
		Detectors:  stats.detectors,
	})
}

// requestStats is the per-request audit state the data plane fills in and the
// audit middleware reads after the response completes. It is never shared
// across requests.
type requestStats struct {
	provider   string
	path       string
	method     string
	reqBytes   int
	redactions int
	detectors  []string
	proxied    bool
}

// requestStatsKey is the context key for the per-request stats. The unexported
// zero-size struct prevents collisions with other packages' keys.
type requestStatsKey struct{}

// requestStatsFrom returns the request's audit stats, or nil outside the audit
// middleware (for example a direct data-plane test).
func requestStatsFrom(ctx context.Context) *requestStats {
	stats, _ := ctx.Value(requestStatsKey{}).(*requestStats)
	return stats
}

// auditResponseWriter records the final status and body byte count of a
// response. It forwards Flush so SSE streaming is unaffected.
type auditResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

// WriteHeader records the first status the handler commits.
func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write records the status an implicit 200 and accumulates body bytes.
func (w *auditResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

// Flush forwards a flush to the wrapped writer when it supports one.
func (w *auditResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
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
