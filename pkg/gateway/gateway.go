// Package gateway is the shared request-path assembly layer for the core CLI
// and the private Pro daemon.
//
// It owns the pieces both builds used to duplicate: the loopback listener
// lifecycle (dual-stack, degrading to IPv4-only when the host has no usable
// IPv6 loopback), the per-session control token and run.json, the
// Host-allowlist and per-request stats middleware chain, the data plane, and
// the bounded graceful shutdown. Callers keep their build-specific concepts
// (audit store, control session, entitlement, web UI) behind the lifecycle
// hooks in Options.
//
// The assembly contract (Deps, Options, BuildOptions, RequestStats) plus the
// C7/C8 seam types (AllowlistStore, SelfProtectionConfig) is frozen by ADR-0012
// in the tokenhush-pro repository. pkg/gateway/testdata/options_contract.txt
// plus TestOptionsContractDoc pin the exported struct fields against
// accidental drift. The package itself is experimental until v1.0.
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

// controlAllowlistPath is the control-plane allowlist CRUD route. It mirrors
// the unexported constant in pkg/proxy and is registered for GET/POST/DELETE
// plus the method-less spelling (see buildHandler).
const controlAllowlistPath = "/allowlist"

// controlAuditProvider labels the audit rows produced by control-plane
// mutations, following the metadata-only row convention of the Pro daemon's
// lifecycle and plugin rows (Provider names the subsystem, Path names the
// operation, Method names the action, Client names the source and Detectors
// carries the resulting entry count as a tag).
const controlAuditProvider = "control"

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

// AllowlistStore 是运行时可变更白名单（C7）的存储接缝：句柄由调用方创建，
// 同一实例同时交给 BuildPipeline 与 Options，使检测器与 /allowlist 端点看到
// 同一份快照。nil 表示仅使用静态配置（与引入本接缝之前的行为一致）。
//
// 接口归属 pkg/gateway：pkg/allowlist 以结构化方式实现它（Go 接口结构化满足，
// 无需 import pkg/gateway），从而避免 pkg/allowlist → pkg/gateway 的反向依赖。
type AllowlistStore interface {
	// Entries 返回当前生效的全部条目（静态种子 ∪ 动态条目）。
	Entries() []string
	// Add 新增一条条目；重复或非法条目返回错误。
	Add(entry string) error
	// Remove 移除一条条目；不存在时返回错误。
	Remove(entry string) error
}

// SelfProtectionConfig 是变更通道自保护（C8）的装配配置：窄口径排除集、
// control token 值与拦截类别。零值 = 关闭，即与引入本配置之前的行为一致。
type SelfProtectionConfig struct {
	// Enabled 是自保护总开关；false（零值）= 关闭。
	Enabled bool
	// Modes 是启用的拦截类别，取值 cli-command / control-port / file-write；
	// nil/空 = 调用方默认集。
	Modes []string
	// Exclusions 是窄口径排除集的值：control.token 的值 +
	// <DataDir>/allowlist.json 的完整内容。这些值在请求方向强制脱敏且永不
	// 回填，且不可被白名单豁免；白名单条目值刻意不在其中（否则会抵消 C7）。
	Exclusions [][]byte
	// ControlToken 是当前会话 control token 的值；""（零值）= 不接线。
	ControlToken string
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
	// AllowlistStore 是 C7 的运行时白名单句柄，供 buildHandler 注册 /allowlist
	// 端点并读写同一份快照；nil = 仅静态配置（零值即旧行为）。
	AllowlistStore AllowlistStore
	// SelfProtection 是 C8 的装配配置（窄口径排除集 + control token），供
	// buildHandler 侧可见；零值 = 关闭（零值即旧行为）。
	SelfProtection SelfProtectionConfig
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
// leaves no stale session state. When the host has no usable IPv6 loopback the
// listener comes up IPv4-only and Run prints an explicit degrade line to
// Stdout instead of failing. Teardown is called exactly once on every path,
// including a Setup failure; the session files are removed after it.
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

	// W6.1: the session token is generated here, AFTER the caller built the
	// pipeline (ADR-0012 freezes "bind before writing the token", so the token
	// cannot exist at construction time). Install the C8 narrow exclusion set
	// now: the token value plus the current <DataDir>/allowlist.json content.
	// A missing file contributes nothing and never fails startup.
	installSelfProtectionExclusions(opts.Pipeline, deps.Token, opts.AllowlistStore, opts.Stderr)

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
	if listeners.Degraded() {
		fmt.Fprintf(stdout, "tokenhush: IPv6 loopback [::1] unavailable (%v); listening on 127.0.0.1 only\n", listeners.V6Err())
	}
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
//
// C7/C8 装配接缝：opts.AllowlistStore 与 opts.SelfProtection 在本函数内就地可用，
// 供 W5.3 直接注册 /allowlist 端点（不经 Options.Mount 的惰性端口机制——监听端口
// 与 deps.Token 已由 Run 在调用前就绪）。/allowlist 与 /status 采用同一双注册
// 模式：具体方法路由保证正确方法可达，无方法注册保证 PUT 等方法留在控制面并
// 由 ControlAPI 的内部 mux 产出 JSON 405，而不是落到 "/" catch-all 数据面。
func buildHandler(opts Options, deps *Deps, port int, addrs []string, startedAt time.Time) http.Handler {
	control := proxy.NewControlAPI(
		func() proxy.ControlStatus {
			return proxy.ControlStatus{
				State:      proxy.ControlStateRunning,
				Addrs:      append([]string(nil), addrs...),
				UptimeMS:   time.Since(startedAt).Milliseconds(),
				Requests:   deps.Requests.Load(),
				Redactions: deps.Redactions.Load(),
				Allowlist:  allowlistEntryCount(opts.AllowlistStore),
			}
		},
		proxy.WithControlAllowlist(opts.AllowlistStore),
		proxy.WithControlAudit(func(ev proxy.ControlAuditEvent) {
			recordAllowlistMutation(opts.Sink, ev)
			// W6.1: a runtime allowlist mutation rewrites
			// <DataDir>/allowlist.json, so refresh the C8 exclusion set to the
			// file's new bytes. The callback runs synchronously after a
			// successful mutation, before the HTTP response, so the refreshed
			// set is observable by the next request. A refresh failure is
			// metadata-only and non-fatal: the mutation already succeeded.
			installSelfProtectionExclusions(opts.Pipeline, deps.Token, opts.AllowlistStore, opts.Stderr)
		}),
	)
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
	mux.Handle("GET "+controlAllowlistPath, guardedControl)
	mux.Handle("POST "+controlAllowlistPath, guardedControl)
	mux.Handle("DELETE "+controlAllowlistPath, guardedControl)
	mux.Handle(controlAllowlistPath, guardedControl)
	if opts.Mount != nil {
		opts.Mount(mux, deps)
	}
	mux.Handle("/", dataPlane)
	return mux
}

// allowlistEntryCount returns the current effective entry count for /status.
// A nil store (C7 not wired) reports 0; the values themselves never appear in
// the status payload.
func allowlistEntryCount(store AllowlistStore) int {
	if store == nil {
		return 0
	}
	return len(store.Entries())
}

// recordAllowlistMutation writes one metadata-only audit row for a successful
// control-plane allowlist change. A nil sink is a no-op (core passes
// audit.NoopSink{}). The entry value is deliberately not recorded: the row
// carries the action, the source identifier and the resulting entry count, and
// the store's entries never leave memory through the audit seam.
func recordAllowlistMutation(sink audit.AuditSink, ev proxy.ControlAuditEvent) {
	if sink == nil {
		return
	}
	_ = sink.Record(audit.Record{
		TS:        time.Now().UnixMilli(),
		Provider:  controlAuditProvider,
		Method:    ev.Action,
		Path:      controlAllowlistPath,
		Client:    ev.Source,
		Detectors: []string{fmt.Sprintf("entries:%d", ev.Count)},
	})
}

// allowlistContentSource is the optional C7 store extension the gateway uses to
// read the persisted allowlist file's current bytes. It is a separate,
// structural interface rather than a method on the frozen AllowlistStore
// contract, so the ADR-0012 seam is unchanged; pkg/allowlist.Store implements
// it. A store that does not implement it simply contributes no file-content
// exclusion (the token value is still installed).
type allowlistContentSource interface {
	RawContent() ([]byte, error)
}

// selfProtectionExclusionValues assembles the frozen C8 narrow exclusion set:
// the session control-token value plus the allowlist store's current file
// content. Exactly those two values — never allowlist entry values, which would
// cancel C7. A missing file contributes nothing. The store's RawContent is
// bounded and reports an over-bound or unreadable file as an error, so the
// caller can warn; the token is still returned so the exclusion is never
// silently dropped in full.
func selfProtectionExclusionValues(token string, store AllowlistStore) ([][]byte, error) {
	values := make([][]byte, 0, 2)
	if token != "" {
		values = append(values, []byte(token))
	}
	source, ok := store.(allowlistContentSource)
	if !ok {
		return values, nil
	}
	content, err := source.RawContent()
	if err != nil {
		return values, err
	}
	if len(content) > 0 {
		values = append(values, content)
	}
	return values, nil
}

// installSelfProtectionExclusions derives and installs the C8 exclusion set on
// the pipeline. It is called once the session token exists and again after every
// allowlist mutation. A read failure is reported on warn (never fatal: startup
// and the mutation must not fail because the exclusion refresh could not read
// the file) and a nil pipeline is a no-op.
func installSelfProtectionExclusions(pipeline *proxy.Pipeline, token string, store AllowlistStore, warn io.Writer) {
	if pipeline == nil {
		return
	}
	values, err := selfProtectionExclusionValues(token, store)
	if err != nil && warn != nil {
		fmt.Fprintf(warn, "tokenhush: self-protection: read allowlist file content: %v\n", err)
	}
	pipeline.SetSelfProtectionExclusions(values)
}
