# Extension API（公开核心）

[English](extension-api.md) | **中文**

> 状态：V1 已实现（2026-09）。下列接口与 `pkg/extension` 和 `pkg/proxy` 中的真实接线一致。面向插件作者的上手指南见 [plugins.zh-CN.md](plugins.zh-CN.md)。

## 目的

公开核心只提供单账号直连实现。私有构建（闭源）与第三方通过扩展点接口挂载额外能力。接口公开并不意味着实现公开。

## 接口（`pkg/extension`）

### 跨层扩展点

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

架构决策记录在私有 Pro 仓库中。内置检测器本身就是 `Inspector` 实现；私有构建与第三方通过同一接口挂载更多插件。接口公开并不意味着实现公开：明文生成、出站写入和占位符映射仍仅限核心。

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
> 插件只能提议；由核心决定并执行。占位符到明文的映射无法从 `pkg/extension` 访问。

- `Register` 以类型化错误拒绝：非插件或 typed-nil（`ErrNotAPlugin`）、空 id 或重复 id（`ErrMissingID` / `ErrDuplicateID`）、`CanNetwork`（`ErrNetworkDenied`）、负优先级（`ErrInvalidPriority`）、空 phase 或未知 phase（`ErrNoPhases` / `ErrInvalidPhase`），以及声明 `RequestContent` 或 `Header` 的 `Transformer`（`ErrTransformerPhase`）。只有全部检查通过才会存储任何东西。
- 未开启 `ReadContent` 的 `Inspector` 只能看到 `Leaf.Len`；`Leaf.Content` 为 `nil`。
- `Transformer` 只能声明 `ResponseContent` 或 `Metadata`。声明 `RequestContent` 或 `Header` 会在注册时被拒绝。
- 明文生成和所有出站写入仅限核心。`ResponseContent` 重写在回填之前运行，因此其输出不可能包含原始机密。
- `Header` phase 始终清空 `Content`，即使已授予 `ReadContent`。只有 header 名称和长度保留，因此 `Authorization` 及其他任何凭据值都不会到达插件。
- 插件无法访问占位符到明文的映射（`pkg/extension` 不暴露任何映射 API）。
- 策略引擎位于核心：优先级为 `Allow < Warn < Redact < Block`（`Block` 最严重）。按插件的失败策略为 `FailOpenWarn`（提示性，默认）或 `FailClosed`（关键性）。panic 或超时绝不会静默。

`Gate` 还会拒绝 nil 文档（`ErrNilDocument`）以及插件未声明其 phase 的文档（`ErrPhaseNotDeclared`）。

辅助类型（示意）：`Request`（method/path/headers/解析后的 JSON）、`Response`、`Upstream`（base URL；不携带凭据，V1 透传凭据）。`Query` 和 `Record` 是 `pkg/audit` 类型的别名；审计的写入与读取由 `pkg/audit` 中的 `AuditSink` / `AuditQuerier` 接缝负责（由守护进程注入实现）。

## 实现如何挂载

### 公开核心（默认）

作为默认路径，只注册内置的空操作实现：直连、无路由、无成本追踪。

### 私有构建（闭源）

私有仓库是一个独立的 `main` 包，它 import 核心的公开包并注册自己的实现：

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
> 这里只展示注册表注入的形态。真实接线使用 `pkg/proxy` 导出的原语；`internal/cli` 中的 `run` 实现是参考（`internal/` 无法被外部模块 import）。

**要点**：Pro 能力来自私有源代码，而不是本仓库里的某个开关。破解公开核心无法解锁 Pro，因为公开二进制不包含任何 Pro 实现。

## 稳定性策略

| 接口 | 稳定性 | 说明 |
|---|---|---|
| `extension.Router` | 自 V1 起稳定 | 第三方路由插件依赖它 |
| `extension.Inspector` / `Transformer` | 自 V1 起稳定 | 内容插件契约；能力分层见上文 |
| `extension.Capabilities` / `Phase` / `Action` / `Finding` / `Document` / `Leaf` | 自 V1 起稳定 | 核心插件契约类型 |
| `extension.CostSink` | 自 V1 起稳定 | |
| `extension.AuditExporter` | 自 V1 起稳定 | |
| `extension.Registry` | 可能变化 | 取决于接线；接线稳定后冻结 |
| `Request` / `Response` 结构体 | 可能变化 | 随协议演进而调整，遵循语义化版本 |

- 公开接口按语义化版本管理；破坏性变更提升主版本号。
- 第三方扩展在 v1.0 之前不应依赖未冻结的字段。

## 第三方扩展

V1 只支持**编译期**插件（见 [plugins.zh-CN.md](plugins.zh-CN.md)）。不运行时加载 WASM、子进程或动态库。此类机制（例如用于生态而非 IP 保护的 WASM 沙箱）不在 V1 范围内。第三方扩展在 v1.0 之前不应依赖未冻结的字段。
