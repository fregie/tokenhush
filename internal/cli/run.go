// Package cli assembles the tokenhush command line: it is the only place that
// wires pkg/proxy, pkg/filter, pkg/redact and pkg/supply into a running
// product. run.go owns the run command, the startup order and the HTTP
// surface; cli.go owns the dispatcher and the content-policy glue.
package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/redact"
	"github.com/fregie/tokenhush/pkg/supply"
)

func init() { register("run", runCommand) }

// runSeams carries the injectable operations of the run command. Production
// uses defaultRunSeams; tests interpose each seam to pin the startup order and
// the failure paths without touching real state.
type runSeams struct {
	recoverRun func(string) (supply.RecoveryResult, error)
	loadConfig func(string) (config.Config, error)
	build      func(config.Config, string, io.Writer, bool) (*gateway, error)
	listen     func(string, int) (net.Listener, string, error)
	notify     func(chan<- os.Signal)
}

// defaultRunSeams is the production seam set.
func defaultRunSeams() runSeams {
	return runSeams{
		recoverRun: supply.Recover,
		loadConfig: config.Load,
		build:      buildGateway,
		listen:     proxy.Listen,
		notify:     func(stop chan<- os.Signal) { signal.Notify(stop, os.Interrupt, syscall.SIGTERM) },
	}
}

// runCommand is the CLI entry for `tokenhush run`.
func runCommand(args []string, _, stderr io.Writer) int {
	return runWith(args, stderr, defaultRunSeams())
}

// runWith runs the gateway. The startup order is the security contract and is
// never rearranged: (1) crash recovery of the running binary, before any
// update or rules state is read, (2) config load, (3) pipeline build (which
// reads the rules cache), (4) loopback bind, (5) session files, (6) serve.
// Nothing is written before the bind succeeds, so a busy port fails fast and
// leaves no session file behind. The gateway runs in the foreground only.
func runWith(args []string, stderr io.Writer, seams runSeams) int {
	if stderr != nil {
		// Every locally generated request refusal logs through the proxy's
		// shared notice seam, so refusal lines land on the gateway's own
		// stderr beside the startup notices.
		proxy.NoticeWriter = stderr
	}
	opts, code := parseRunFlags(args, stderr)
	if code != exitOK {
		return code
	}
	executable, err := os.Executable()
	if err != nil {
		return runFailure(stderr, "resolve executable", err)
	}
	if _, err := seams.recoverRun(executable); err != nil {
		return runFailure(stderr, "crash recovery", err)
	}
	cfgPath := opts.configPath
	if cfgPath == "" {
		dir, err := platform.ConfigDir()
		if err != nil {
			return runFailure(stderr, "resolve config dir", err)
		}
		cfgPath = filepath.Join(dir, "tokenhush.yaml")
	}
	cfg, err := seams.loadConfig(cfgPath)
	if err != nil {
		return runFailure(stderr, "load config", err)
	}
	cfg = applyRunOverrides(cfg, opts)
	dataDir, err := platform.DataDir()
	if err != nil {
		return runFailure(stderr, "resolve data dir", err)
	}
	gateway, err := seams.build(cfg, dataDir, stderr, opts.logRedactions)
	if err != nil {
		return runFailure(stderr, "build pipeline", err)
	}
	listener, addr, err := seams.listen(cfg.Listen.Host, cfg.Listen.Port)
	if err != nil {
		return runFailure(stderr, "listen", err)
	}
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		_ = listener.Close()
		return runFailure(stderr, "listen", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		_ = listener.Close()
		return runFailure(stderr, "listen", err)
	}
	gateway.port, gateway.addrs = port, []string{addr}
	if err := proxy.WriteSession(dataDir, proxy.NewRunState(port, []string{addr}), gateway.token); err != nil {
		_ = listener.Close()
		return runFailure(stderr, "write session", err)
	}
	defer func() { _ = proxy.RemoveSession(dataDir) }()
	printStartupBanner(stderr, cfg, gateway.addrs, port)
	if err := gateway.serve(listener, seams.notify); err != nil {
		return runFailure(stderr, "serve", err)
	}
	return exitOK
}

// gateway is the assembled pipeline: the rule policy, the session placeholder
// pair, the proxy counters, the control token and the data-plane handler
// chain. It is the sole assembly point of the product. budget is the effective
// per-primitive detector budget the pipeline was built with; the request path
// reports a leaf that exceeds it.
type gateway struct {
	cfg           config.Config
	stderr        io.Writer
	logRedactions bool
	budget        int
	policy        *filter.Policy
	writer        *redact.ForwardWriter
	backfiller    *redact.Backfiller
	restorer      proxy.Backfiller
	counters      *proxy.Counters
	responses     *proxy.ResponseHandler
	token         proxy.Token
	started       time.Time
	mu            sync.Mutex
	forwarders    map[string]*proxy.Forwarder
	port          int
	addrs         []string

	responseBufferBytes int64
	responseTimeout     time.Duration
}

// buildGateway builds the pipeline from the config: the built-in rule
// selection, the cached signed pack when one verifies, the session placeholder
// writer/backfiller, the proxy counters and the control token. It reads the
// rules cache (never the network) and performs no I/O besides that read. The
// configured scan budget is converted once and used for the built-ins, the
// cached pack compile and the request-path budget report, so all three agree.
func buildGateway(cfg config.Config, dataDir string, stderr io.Writer, logRedactions bool) (*gateway, error) {
	return buildGatewayWithVerifier(cfg, dataDir, stderr, logRedactions, supply.NewStaticVerifier())
}

// buildGatewayWithVerifier is buildGateway over an injected pack Verifier. It
// exists so a test can drive the production cache-load path — strict decode,
// signature verification, floor and compile — against its own in-process
// issuer key; production always passes the embedded trust roots.
func buildGatewayWithVerifier(cfg config.Config, dataDir string, stderr io.Writer, logRedactions bool, verifier supply.Verifier) (*gateway, error) {
	budget := scanBudget(cfg)
	registry := filter.NewRegistry()
	if err := registry.RegisterBuiltin(selectBuiltins(cfg.Detectors, budget)...); err != nil {
		return nil, err
	}
	if err := loadCachedPack(registry, dataDir, budget, stderr, verifier); err != nil {
		return nil, err
	}
	token, err := proxy.NewToken()
	if err != nil {
		return nil, err
	}
	gateway := &gateway{
		cfg: cfg, stderr: stderr, logRedactions: logRedactions, budget: budget, token: token,
		responseBufferBytes: cfg.ResponseBufferBytes, responseTimeout: cfg.ResponseTimeout,
		policy: filter.NewPolicy(registry, filter.PolicyConfig{Timeout: cfg.DetectorTimeout}),
		writer: redact.NewForwardWriter(nil), backfiller: sessionBackfiller(cfg, token), counters: proxy.NewCounters(),
		started: time.Now(), forwarders: make(map[string]*proxy.Forwarder),
	}
	gateway.restorer = newResponseLog(gateway.backfiller, stderr, logRedactions)
	gateway.responses = proxy.NewResponseHandler(proxy.ResponseConfig{Evaluator: gateway, Backfiller: gateway.restorer, Counters: gateway.counters, Warnings: gateway})
	return gateway, nil
}

// serve serves the listener until an interrupt or a serve failure, then shuts
// down cleanly. notify installs the signal handler (a test seam). Host and
// Origin are checked before anything else (invariant 4), then the control
// surface and the data-plane chain.
func (g *gateway) serve(listener net.Listener, notify func(chan<- os.Signal)) error {
	mux := http.NewServeMux()
	mux.Handle("/status", proxy.ControlGuard(g.token, proxy.NewControlAPI(proxy.ControlConfig{
		Addrs: g.addrs, Port: g.port, Started: g.started, Counters: g.counters,
	})))
	mux.Handle("/", countRequests(g.counters, proxy.NewDataPlane(http.HandlerFunc(g.route), proxy.DataPlaneConfig{
		Evaluator: g, Counters: g.counters, MaxBodyBytes: g.cfg.MaxBodyBytes, Timeout: g.cfg.DetectorTimeout,
	})))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := proxy.CheckHostOrigin(r.Host, r.Header.Get("Origin"), proxy.Allowed{Port: g.port}); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	stop := make(chan os.Signal, 1)
	notify(stop)
	select {
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// route resolves the request path and forwards it through the redaction
// transform, wrapping the client-bound response so the response path can
// decode, evaluate and backfill it. The outbound request context also carries
// the response_timeout deadline, so the whole upstream response read is
// bounded. An unknown path is a 404 and is never guessed at; the one local
// route (GET /v1/models) never dials an upstream.
func (g *gateway) route(w http.ResponseWriter, r *http.Request) {
	upstream, err := proxy.Resolve(r.URL.Path, g.cfg)
	if err != nil {
		http.Error(w, "unknown_upstream", http.StatusNotFound)
		return
	}
	if upstream.Local {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"list","data":[]}`)
		return
	}
	if g.responseTimeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), g.responseTimeout)
		defer cancel()
		r = r.WithContext(ctx)
	}
	forwarder, err := g.forwarder(upstream.BaseURL)
	if err != nil {
		http.Error(w, "unknown_upstream", http.StatusBadGateway)
		return
	}
	intercepted := &responseWriter{dst: w, gate: g, req: r}
	forwarder.ServeHTTP(intercepted, r)
	intercepted.finish()
}

// forwarder returns the cached forwarder for one upstream base URL, so the
// transport (and its connection pool) is shared across requests.
func (g *gateway) forwarder(baseURL string) (*proxy.Forwarder, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if forwarder, ok := g.forwarders[baseURL]; ok {
		return forwarder, nil
	}
	forwarder, err := proxy.NewForwarder(baseURL, g.redactionTransform, proxy.WithMaxBodyBytes(g.cfg.MaxBodyBytes))
	if err != nil {
		return nil, err
	}
	g.forwarders[baseURL] = forwarder
	return forwarder, nil
}
