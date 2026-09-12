// Package gateway is the shared request-path assembly layer for the core CLI
// and the private Pro daemon.
//
// It owns the pieces both builds used to duplicate: the dual-stack loopback
// listener lifecycle, the per-session control token and run.json, the
// Host-allowlist and per-request stats middleware chain, the data plane, and
// the bounded graceful shutdown. Callers keep their build-specific concepts
// (audit store, control session, entitlement, web UI) behind the lifecycle
// hooks in Options.
//
// The assembly contract (Deps, Options, BuildOptions, RequestStats) is frozen
// by ADR-0012 in the tokenhush-pro repository. pkg/gateway/testdata/
// options_contract.txt plus TestOptionsContractDoc pin the exported struct
// fields against accidental drift. The package itself is experimental until
// v1.0.
package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// controlStatusPath is the control-plane liveness route. It mirrors the
// unexported constant in pkg/proxy; the control API applies the Go 1.22
// method pattern (GET only) once a request reaches it.
const controlStatusPath = "/status"

// Tuning shared by every embedded gateway. The detector timeout is
// deliberately generous: the built-in detectors are configured FailClosed, so
// a too-short timeout would turn a large but legitimate request into a block.
// shutdownTimeout bounds how long a cancelled context waits for in-flight
// requests before the process files are removed.
const (
	defaultDetectorTimeout = 5 * time.Second
	shutdownTimeout        = 5 * time.Second
)

// Deps is the mutable per-session state shared with the lifecycle hooks. The
// gateway allocates the two atomic counters; Setup only reads and writes them.
type Deps struct {
	// DataDir is set by Setup when the caller pins its own root (Pro sets
	// TOKENHUSH_HOME before Run); when it stays empty the gateway resolves the
	// platform data directory. It holds the control token and run.json.
	DataDir string
	// Token is the per-session control-API token, written after the listener
	// is bound.
	Token string
	// Requests counts the data-plane requests served this session. It backs
	// the /status counter and is allocated by the gateway.
	Requests *atomic.Uint64
	// Redactions counts the placeholder substitutions applied this session. It
	// is allocated by the gateway and backs /status.
	Redactions *atomic.Uint64
}

// RunInfo is the post-startup snapshot handed to Options.Ready once the
// listeners are bound and the session files exist.
type RunInfo struct {
	Addrs []string
	Port  int
}

// Options is the frozen assembly contract. The zero value is not usable: Core
// and Pipeline must be provided. Every hook is optional except as documented.
type Options struct {
	// Core is the fully loaded core configuration. The pipeline, resolver and
	// listener settings are read from it; it never carries Pro-only concerns.
	Core config.Config
	// Router is the multi-provider / multi-account injection point. When nil,
	// the gateway falls back to proxy.NewResolver(Core.Upstreams, Sink).
	Router extension.Router
	// CostSink observes completed requests for token and cost accounting. Nil
	// is a no-op.
	CostSink extension.CostSink
	// Sink feeds the default resolver only (Router == nil); the core passes
	// audit.NoopSink{}, Pro passes its real sink.
	Sink audit.AuditSink
	// Pipeline is the caller-built content pipeline. It is required and the
	// gateway never rebuilds it.
	Pipeline *proxy.Pipeline
	// PolicyTimeout bounds one detector invocation. <= 0 uses the default.
	PolicyTimeout time.Duration
	// Setup runs first, before any platform.* call, so Pro can pin its root
	// and open resources. A Setup error still triggers exactly one Teardown.
	Setup func(*Deps) error
	// Mount attaches caller-owned control/UI subtrees to the shared mux before
	// the data-plane catch-all is registered.
	Mount func(*http.ServeMux, *Deps)
	// WrapDataPlane wraps the data-plane handler; Pro layers its audit and
	// credential-injection handlers here. The gateway's stats middleware sits
	// outside it, so StatsFrom works inside the wrapped handler.
	WrapDataPlane func(http.Handler, *Deps) http.Handler
	// Teardown finalises the session. It is idempotent and called exactly once
	// per Run, including when Setup returns an error.
	Teardown func(*Deps)
	// Stdout receives the human-facing startup lines. Nil discards them.
	Stdout io.Writer
	// Stderr is the diagnostics stream kept in the seam for callers.
	Stderr io.Writer
	// Ready is called once the listeners are bound and the session files are
	// on disk; it is how a test learns the bound ephemeral port.
	Ready func(RunInfo)
}

// Run assembles and runs one gateway session until ctx is cancelled.
//
// The fixed call order is:
//
//	Setup -> resolve DataDir -> bind listener -> generate token + session
//	files -> mux(Mount, WrapDataPlane) -> Ready -> serve -> drain -> Teardown
//	-> cleanup
//
// Setup runs first and before any platform.* call. The listener is bound
// before the token and run.json are written, so a busy port fails fast and
// leaves no stale session state. Teardown is called exactly once on every
// path, including a Setup failure; the session files are removed after it.
//
// The returned error wraps pkg/proxy's typed listener errors (for example
// ErrAddrInUse), so callers can classify with errors.Is.
func Run(ctx context.Context, opts Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	stdout := opts.Stdout
	if stdout == nil {
		stdout = io.Discard
	}

	deps := &Deps{
		Requests:   new(atomic.Uint64),
		Redactions: new(atomic.Uint64),
	}

	// Setup must be first, before any platform.* call: Pro pins its data root
	// here so the DataDir resolution below lands in the right place.
	if opts.Setup != nil {
		if err := opts.Setup(deps); err != nil {
			invokeTeardown(opts, deps)
			return err
		}
	}

	dataDir := deps.DataDir
	if dataDir == "" {
		resolved, err := platform.DataDir()
		if err != nil {
			invokeTeardown(opts, deps)
			return err
		}
		dataDir = resolved
	}
	deps.DataDir = dataDir

	// Bind before writing the token/run.json: a busy port must not leave a
	// stale session behind (adversarial class: stale_state).
	listeners, err := proxy.Listen(opts.Core.Listen.Host, int(opts.Core.Listen.Port))
	if err != nil {
		invokeTeardown(opts, deps)
		return err
	}
	port := listeners.Port()
	addrs := listenerAddrs(listeners)

	token, _, err := proxy.NewControlToken(dataDir)
	if err != nil {
		_ = listeners.Close()
		invokeTeardown(opts, deps)
		return err
	}
	deps.Token = token

	state := RunState{
		PID:       os.Getpid(),
		Port:      port,
		Addrs:     addrs,
		StartedAt: time.Now().UnixMilli(),
	}
	if err := WriteRunState(dataDir, state); err != nil {
		_ = listeners.Close()
		invokeTeardown(opts, deps)
		cleanupSessionFiles(dataDir)
		return err
	}

	srv := &http.Server{
		Handler:        buildHandler(opts, deps, port, addrs, time.Now()),
		MaxHeaderBytes: proxy.MaxHeaderBytes,
	}

	fmt.Fprintf(stdout, "tokenhush: gateway listening on http://127.0.0.1:%d\n", port)
	fmt.Fprintf(stdout, "tokenhush: control token file: %s\n", controlTokenPath(dataDir))
	if opts.Ready != nil {
		opts.Ready(RunInfo{Addrs: addrs, Port: port})
	}

	runErr := serveUntilDone(ctx, srv, listeners)
	// Teardown before cleanup: release everything Setup acquired first, then
	// remove the discovery files so no reader sees a half-torn-down session.
	invokeTeardown(opts, deps)
	cleanupSessionFiles(dataDir)
	return runErr
}

// invokeTeardown calls the teardown hook once. It is a named helper so every
// return path in Run uses the same "called exactly once" site.
func invokeTeardown(opts Options, deps *Deps) {
	if opts.Teardown != nil {
		opts.Teardown(deps)
	}
}

// buildHandler composes the control plane and the data plane on one mux. The
// middleware chain on the data plane is, outermost first:
//
//	HostAllowlist -> StatsMW -> WrapDataPlane -> data plane
//
// The control path is wrapped HostAllowlist -> OriginPolicy -> ControlAuth and
// registered for GET explicitly; the method-less pattern keeps a non-GET
// method on the control path inside the control API (JSON 405) instead of
// letting it fall through to the data plane.
func buildHandler(opts Options, deps *Deps, port int, addrs []string, startedAt time.Time) http.Handler {
	control := proxy.NewControlAPI(func() proxy.ControlStatus {
		return proxy.ControlStatus{
			State:      proxy.ControlStateRunning,
			Addrs:      append([]string(nil), addrs...),
			UptimeMS:   time.Since(startedAt).Milliseconds(),
			Requests:   deps.Requests.Load(),
			Redactions: deps.Redactions.Load(),
		}
	})
	guardedControl := proxy.HostAllowlist(port)(
		proxy.OriginPolicy(proxy.ControlAuth(func() string { return deps.Token })(control)))

	// StatsMW is injected by the gateway and sits outside WrapDataPlane: it
	// allocates the per-request RequestStats and puts it in the request
	// context before the wrapped handler runs.
	dataPlane := opts.Pipeline.ResponseMiddleware(newDataPlane(opts, deps))
	if opts.WrapDataPlane != nil {
		dataPlane = opts.WrapDataPlane(dataPlane, deps)
	}
	dataPlane = proxy.HostAllowlist(port)(statsMiddleware(dataPlane))

	mux := http.NewServeMux()
	mux.Handle("GET "+controlStatusPath, guardedControl)
	mux.Handle(controlStatusPath, guardedControl)
	if opts.Mount != nil {
		opts.Mount(mux, deps)
	}
	mux.Handle("/", dataPlane)
	return mux
}
