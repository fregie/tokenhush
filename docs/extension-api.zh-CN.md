# Extension API（公开核心）

[English](extension-api.md) | **中文**

> 状态：V1 已实现（2026-09）。下列接口与 `pkg/extension`、`pkg/proxy` 以及 `pkg/gateway` 的真实接线一致。插件作者上手指南见 [plugins.zh-CN.md](plugins.zh-CN.md)。

## 🎯 目的

公开核心只带一种实现：单账号直连。私有构建（闭源）和第三方通过扩展点接口挂载额外能力。接口公开，不等于实现公开。

## 🧩 接口（`pkg/extension`）

### 跨层扩展点

三个钩子：选上游、记成本、读审计记录。

```go
package extension

// Router decides which upstream a request takes (multi-provider / multi-account).
type Router interface {
    Name() string
    // Pick returns the target upstream. A zero-value Upstream with a nil error
    // means "no opinion, fall back to the default implementation".
    Pick(req *Request) (Upstream, error)
}

// CostSink records token usage and cost.
type CostSink interface {
    Name() string
    Record(req *Request, resp *Response)
}

// AuditExporter exports audit records (team audit / compliance reports).
type AuditExporter interface {
    Name() string
    Export(ctx context.Context, q Query) ([]Record, error)
}
```

### 内容插件（编译期内置，最小权限）

插件能检查或改写请求与响应内容，但只能走核心开放的通道。架构决策记录在私有 Pro 仓库。内置检测器本身就是 `Inspector` 实现；私有构建和第三方用同一套接口挂载更多插件。边界同前：明文生成、出站写入、占位符映射都只留在核心。

```go
type Phase string  // RequestContent | ResponseContent | Header | Metadata
type Action string // Allow | Warn | Redact | Block

type Plugin interface {
    ID() string
    Capabilities() Capabilities
}

type Capabilities struct {
    Phases       []Phase
    ReadContent  bool
    CanTransform bool
    CanBlock     bool
    CanNetwork   bool // denied at registration for the compiled-in third-party tier
    Priority     int  // ascending; ties break on plugin id
}

type Finding struct {
    LeafIndex  int
    Start      int
    End        int
    Type       string
    Confidence float64
    Action     Action
    PluginID   string
    Meta       map[string]any
}

type Leaf struct {
    Path    string
    Content []byte
    Len     int
}
type Document struct {
    Phase  Phase
    Tool   string
    Leaves []Leaf
}

type Inspector interface {
    Plugin
    Inspect(*Document) ([]Finding, error)
}

type Transformer interface {
    Plugin
    Transform(*Document) (*Document, error)
}

// Registry (NewRegistry) holds the compiled-in plugins; Register is the
// security gate.
type Registry struct{ /* ... */ }

func NewRegistry() *Registry
func (r *Registry) Register(p Plugin) error
func (r *Registry) Inspectors(phase Phase) []Inspector
func (r *Registry) Transformers(phase Phase) []Transformer

// Gate returns the view a plugin is allowed to see: without ReadContent,
// Content is cleared; the Header phase always clears Content (leaving only
// Path/Len).
func Gate(doc *Document, caps Capabilities) (*Document, error)
```

**安全约束（注册期与运行时）**

> [!IMPORTANT]
> 插件只能提议；决定和执行都在核心。`pkg/extension` 访问不到占位符到明文的映射。

- `Register` 用类型化错误拒绝以下情况：非插件或 typed-nil（`ErrNotAPlugin`）；id 为空或重复（`ErrMissingID` / `ErrDuplicateID`）；开启 `CanNetwork`（`ErrNetworkDenied`）；优先级为负（`ErrInvalidPriority`）；phase 为空或未知（`ErrNoPhases` / `ErrInvalidPhase`）；`Transformer` 声明 `RequestContent` 或 `Header`（`ErrTransformerPhase`）。全部检查通过，才会写入任何状态。
- 未开启 `ReadContent` 的 `Inspector` 只能看到 `Leaf.Len`，`Leaf.Content` 为 `nil`。
- `Transformer` 只能声明 `ResponseContent` 或 `Metadata`；声明 `RequestContent` 或 `Header`，注册时即被拒绝。
- 明文生成和所有出站写入只在核心。`ResponseContent` 重写先于回填运行，所以输出不可能再包含原始机密。
- 即使授予 `ReadContent`，`Header` phase 仍会清空 `Content`。只保留 header 名称和长度，`Authorization` 及其他任何凭据值都到不了插件。
- 插件访问不到占位符到明文的映射（`pkg/extension` 不暴露任何映射 API）。
- 策略引擎在核心：优先级顺序为 `Allow < Warn < Redact < Block`（`Block` 最严重）。单插件的失败策略是 `FailOpenWarn`（提示性，默认）或 `FailClosed`（关键性）。panic 或超时绝不静默。

`Gate` 还会拒绝 nil 文档（`ErrNilDocument`），以及插件未声明其 phase 的文档（`ErrPhaseNotDeclared`）。

辅助类型（示意）：`Request`（method/path/headers/解析后的 JSON）、`Response`、`Upstream`（base URL；不携带凭据，V1 透传凭据）。`Query` 与 `Record` 是 `pkg/audit` 类型的别名；审计读写由该包的 `AuditSink` / `AuditQuerier` 接缝承担。核心默认是 no-op sink，私有 Pro 层注入具体存储。

## 🏗️ 装配层（`pkg/gateway`）

核心 CLI（`internal/cli`）与私有 Pro daemon 通过同一装配层落地。`pkg/gateway` 负责：环回监听器的生命周期（`127.0.0.1`；主机有 IPv6 环回时同时绑 `[::1]`）、每会话控制 token 与 `run.json`、Host 允许列表与按请求统计的中间件链、数据面，以及有界的优雅关闭。各构建的特有概念（审计存储、控制会话、entitlement、Web UI）留在 `Options` 的生命周期钩子之后。

导出的契约由私有 Pro 仓库的 ADR-0012 冻结；`pkg/gateway/testdata/options_contract.txt` 与 `TestOptionsContractDoc` 一起钉住导出结构体字段，防止意外漂移。该包在 v1.0 前属实验性。

```go
package gateway

// Deps 是与生命周期钩子共享的每会话可变状态。两个原子计数器由 gateway
// 分配；Setup 可先固定 DataDir。
type Deps struct {
    DataDir    string         // 会话文件根目录；Setup 在任何 platform.* 调用前设置
    Token      string         // 每会话控制 API token，在监听器绑定后写入
    Requests   *atomic.Uint64 // 本会话处理的数据面请求数
    Redactions *atomic.Uint64 // 本会话应用的占位符替换数
}

// RunInfo 是监听器绑定、会话文件就绪后交给 Options.Ready 的启动快照。
type RunInfo struct {
    Addrs []string
    Port  int
}

// Options 是冻结的装配契约。零值不可用：必须提供 Core 与 Pipeline；
// 其余钩子均可选。
type Options struct {
    Core          config.Config                          // 已加载的核心配置
    Router        extension.Router                       // 为 nil 时回退到 proxy.NewResolver(Core.Upstreams, Sink)
    CostSink      extension.CostSink                     // 为 nil 时是 no-op
    Sink          audit.AuditSink                        // 只喂默认解析器
    Pipeline      *proxy.Pipeline                        // 必需；由调用方构建，gateway 绝不重建
    PolicyTimeout time.Duration                          // <= 0 时用默认值
    Setup         func(*Deps) error                      // 最先运行，早于任何 platform.* 调用
    Mount         func(*http.ServeMux, *Deps)            // 挂载调用方自有的控制/UI 子树
    WrapDataPlane func(http.Handler, *Deps) http.Handler // 审计 / 凭据注入层
    Teardown      func(*Deps)                            // 结束会话；幂等
    Stdout        io.Writer                              // 面向人的启动信息；nil 即丢弃
    Stderr        io.Writer                              // 保留给调用方的诊断流
    Ready         func(RunInfo)                          // 监听器已绑定、会话文件已落盘
}

// Run 装配并运行一个 gateway 会话，直到 ctx 被取消。返回的 error 包装
// pkg/proxy 的类型化监听错误（可用 errors.Is 判断）。
func Run(ctx context.Context, opts Options) error
```

**生命周期。** `Run` 的调用顺序固定：

```text
Setup -> 解析 DataDir -> 绑定监听器 -> 生成 token + 会话文件
  -> mux(Mount, WrapDataPlane) -> Ready -> serve -> drain -> Teardown -> cleanup
```

- `Setup` 最先运行，且早于任何 `platform.*` 调用，便于调用方固定数据根（`TOKENHUSH_HOME`）。
- 监听器在写入 token 与 `run.json` **之前**绑定：端口被占用会快速失败，不留下陈旧会话状态。
- `Teardown` 在所有路径（包括 `Setup` 失败）恰好调用一次；会话文件在其后移除。

**中间件链。** 同一个 mux 服务两个平面。数据面从最外层起：

```text
HostAllowlist -> StatsMW -> WrapDataPlane -> data plane
```

控制路径（`GET /status`，以及 `GET|POST|DELETE /allowlist`；无方法模式让其他方法留在控制 API 内返回 JSON 405）包裹为 `HostAllowlist -> OriginPolicy -> ControlAuth`。`StatsMW` 为每个请求分配一个 `RequestStats`，并在 `WrapDataPlane` **之前**放入请求 context，因此外层包裹器（Pro 审计层）可用 `StatsFrom` 读取：

```go
// RequestStats 是按请求的观测快照。只含元数据：检测器 id 与字节数，
// 绝不含命中的内容。
type RequestStats struct {
    Provider   string
    Path       string
    Method     string
    ReqBytes   int
    Redactions int
    Detectors  []string
    Proxied    bool
}

// StatsFrom 返回当前请求的 RequestStats；在 gateway 统计中间件之外返回 nil。
func StatsFrom(ctx context.Context) *RequestStats
```

**管线构建。** 核心用 `BuildPipeline` 构建自己的管线（启用内置检测器的注册表、fail-closed 策略、全新的占位符引擎）。Pro 有自带构建器，可注册额外插件族；gateway 本身绝不构建管线。

```go
type BuildOptions struct {
    Detectors []string        // 有序的启用检测器 id
    Allowlist []string        // 静态字面量，转发给每个检测器（与 AllowlistStore 并集生效）
    Sink      audit.AuditSink // 仅元数据审计行
    Timeout   time.Duration   // <= 0 时用默认值
    Tool      string          // 标注 Document（例如 "claude-code"）
    Rules     *rules.Config   // 已同步的签名规则包；nil = 仅内置检测器
    // AllowlistStore 是运行时可变更白名单句柄（C7）；nil = 仅静态 Allowlist。
    // gateway 用它注册 /allowlist。
    AllowlistStore AllowlistStore
    // SelfProtection 是变更通道自保护装配（C8）；零值 = 关闭。
    SelfProtection SelfProtectionConfig
}

func BuildPipeline(opts BuildOptions) (*proxy.Pipeline, error)
```

**会话文件与辅助导出。** `RunState` 是为进程发现而持久化的仅元数据 pid/port 快照，绝不含控制 token 或请求内容。`WriteRunState` 原子写入（同目录临时文件 + rename，`0600`）。`RunStateFileName` 是数据目录下的 `run.json`，优雅关闭时移除。`ResolveConfig` 在传入配置非空时原样返回，否则从路径或平台默认位置加载。

```go
const RunStateFileName = "run.json"

type RunState struct {
    PID       int      `json:"pid"`
    Port      int      `json:"port"`
    Addrs     []string `json:"addrs"`
    StartedAt int64    `json:"started_at"` // unix 毫秒
}

func WriteRunState(dataDir string, st RunState) error
func ResolveConfig(cfg *config.Config, path string) (*config.Config, error)
```

## 🧩 实现如何挂载

### 公开核心（默认）

默认路径只注册内置的空操作实现：直连、不路由、不追踪成本。

### 私有构建（闭源）

私有仓库是一个独立的 `main` 包，import 核心的公开包，再注册自己的实现：

```go
package main

import (
    "github.com/fregie/tokenhush/pkg/extension"
)

func main() {
    reg := extension.NewRegistry()

    // Content plugins go through Registry. An Inspector for detection...
    if err := reg.Register(myInspector{}); err != nil {
        return
    }
    // ...and a Transformer for response/metadata rewrites only.
    if err := reg.Register(myTransformer{}); err != nil {
        return
    }

    // Router, CostSink, and AuditExporter are independent injection points.
    // Wire them with the primitives exported by pkg/proxy and pkg/audit.
    // See plugins.md ("Registering plugins").
    _ = reg
}
```

> [!NOTE]
> 这里只展示注册表注入的形态。真实接线用 `pkg/proxy` 导出的原语与上文的 `pkg/gateway` 装配层；`internal/cli` 里的 `run` 实现是参考（`internal/` 不能被外部模块 import）。

**要点**：Pro 能力来自私有源代码，不是本仓库里的开关。破解公开核心解锁不了 Pro，因为公开二进制里没有任何 Pro 实现。

## 📌 稳定性策略

| 接口 | 稳定性 | 说明 |
|---|---|---|
| `extension.Router` | 自 V1 起稳定 | 第三方路由插件依赖它 |
| `extension.Inspector` / `Transformer` | 自 V1 起稳定 | 内容插件契约；能力分层见上文 |
| `extension.Capabilities` / `Phase` / `Action` / `Finding` / `Document` / `Leaf` | 自 V1 起稳定 | 核心插件契约类型 |
| `extension.CostSink` | 自 V1 起稳定 | |
| `extension.AuditExporter` | 自 V1 起稳定 | |
| `extension.Registry` | 可能变化 | 取决于接线；接线稳定后冻结 |
| `gateway.Options` / `Deps` / `BuildOptions` / `RequestStats` | 由 ADR-0012 冻结（私有 Pro 仓库） | 装配契约；由 `TestOptionsContractDoc` 钉住 |
| `gateway.Run` / `BuildPipeline` / `ResolveConfig` / `WriteRunState` / `StatsFrom` | 可能变化 | v1.0 前属实验性 |
| `Request` / `Response` 结构体 | 可能变化 | 随协议演进而调整，遵循语义化版本 |

- 公开接口按语义化版本管理；破坏性变更提升主版本号。
- 第三方扩展在 v1.0 之前不应依赖未冻结的字段。

## 🧩 第三方扩展

V1 只支持**编译期**插件（见 [plugins.zh-CN.md](plugins.zh-CN.md)）；不在运行时加载 WASM、子进程或动态库。面向生态（而非 IP 保护）的 WASM 沙箱不在 V1 范围内。
