# Extension API — tokenhush (public core)

> 状态：V1 已实现（2026-09）。接口以 `pkg/extension` 与 `pkg/proxy` 的真实装配为准；面向插件作者的实操指南见 [plugins.md](plugins.md)。

## 目的

公开核心只提供"单账户直连"的默认实现。Pro 构建（闭源）与第三方通过**扩展点接口**挂载额外能力。接口公开 ≠ 实现公开。

## 接口（`pkg/extension`）

### 跨层扩展点

```go
package extension

// Router 决定一个请求走哪个上游（多 provider / 多账号）。
type Router interface {
    Name() string
    // Pick 返回目标上游；返回零值 Upstream + nil 表示"不处理，交给默认实现"。
    Pick(req *Request) (Upstream, error)
}

// CostSink 记录 token 用量与成本（Pro：成本追踪）。
type CostSink interface {
    Name() string
    Record(req *Request, resp *Response)
}

// AuditExporter 导出审计记录（Pro：团队审计 / 合规报告）。
type AuditExporter interface {
    Name() string
    Export(ctx context.Context, q Query) ([]Record, error)
}
```

### 内容插件（编译内置、能力分级）

架构决策见 `../../tokenhush-pro/docs/decisions/0007-content-plugin-architecture.md`。内置检测器本身即 `Inspector`；Pro / 第三方用同一接口挂载更多插件。**接口公开 ≠ 实现公开：明文生成、出站写入与占位符映射始终由核心独占。**

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
    CanNetwork   bool // 编译内置第三方层在注册期被拒
    Priority     int  // 升序；同优先级按 id 升序
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

// Registry（NewRegistry()）持有编译内置插件；Register 是安全闸门。
type Registry struct{ /* ... */ }

func NewRegistry() *Registry
func (r *Registry) Register(p Plugin) error
func (r *Registry) Inspectors(phase Phase) []Inspector
func (r *Registry) Transformers(phase Phase) []Transformer

// Gate 返回插件被允许看到的视图：无 ReadContent 时清空 Content；
// Header 阶段无论能力一律清空 Content（只留 Path/Len）。
func Gate(doc *Document, caps Capabilities) (*Document, error)
```

**安全约束（注册 / 运行期）**

- `Register` 以类型化错误拒绝：非插件/typed-nil（`ErrNotAPlugin`）、空/重复 id（`ErrMissingID`/`ErrDuplicateID`）、`CanNetwork`（`ErrNetworkDenied`）、负优先级（`ErrInvalidPriority`）、空/未知阶段（`ErrNoPhases`/`ErrInvalidPhase`）、以及声明 `RequestContent`/`Header` 的 `Transformer`（`ErrTransformerPhase`）。全部通过才入库。
- 未声明 `ReadContent` 的 `Inspector` 只拿到 `Leaf.Len`，`Content` 为 `nil`。
- `Transformer` 只允许 `ResponseContent` / `Metadata`；声明 `RequestContent` / `Header` 者在**注册期被拒绝**。
- 明文生成与一切出站写入**仅核心可为**；`ResponseContent` 改写先于回填，其输出不可能包含原始 secret。
- `Header` 阶段一律清空 `Content`（即使声明 `ReadContent`），只留头名与长度，**绝不暴露 `Authorization` / 鉴权取值**。
- 占位符 ↔ 原文映射**对插件不可达**（`pkg/extension` 无映射 API）。
- 策略引擎在核心：优先级 `Allow < Warn < Redact < Block`（`Block` 最严重）；每插件失败策略 `FailOpenWarn`（advisory，默认）或 `FailClosed`（critical），panic / 超时绝不静默。

配套类型（示意）：`Request`（方法/路径/头/已解析 JSON）、`Response`、`Upstream`（base URL；**不携带凭据**，V1 透传）。
`Query` / `Record` 是 `pkg/audit` 的类型别名；审计写入与读取由 `pkg/audit` 的 `AuditSink` / `AuditQuerier` seam 承担（daemon 注入实现）。

## 挂载方式

### 公开核心（默认）
只注册内置的"直连 + 无路由 + 无成本"空实现，作为默认路径。

### Pro 构建（闭源）
Pro 仓库是**独立的 `main` 包**，导入本核心的公开包并注册私有实现：

```go
// 私有仓库 tokenhush-pro/cmd/tokenhush-pro/main.go（不存在于本仓库）
import (
    "github.com/fregie/tokenhush/pkg/extension"
    "github.com/fregie/tokenhush/pkg/proxy"
    pro "github.com/fregie/tokenhush-pro/internal/..."
)

func main() {
    // 内容插件经 Registry 注册；Router / CostSink / AuditExporter 是独立注入点。
    reg := extension.NewRegistry()
    _ = reg.Register(pro.NewCredentialInspector()) // Inspector（内容插件）
    _ = reg.Register(pro.NewSemanticTransformer()) // Transformer（仅 response/metadata）

    // 装配：Pro 用自己的 main 组合导入的公开原语
    // （pkg/proxy.Listen/NewPipeline/NewResolver/NewForwarder、pkg/audit 的 store 等），
    // 并把 reg 与私有 Router/CostSink/AuditExporter 注入。见 plugins.md「注册插件」。
    _ = reg
}
```

> 上面只展示 registry 注入的形状；真实装配用的是 `pkg/proxy` 导出的原语，`internal/cli` 的 `run` 是参考实现（`internal/` 不可被外部模块导入）。

**要点**：Pro 的能力来自**私有源码**，不是本仓库里的开关。破解公开核心无法解锁 Pro（因为公开二进制里根本没有 Pro 实现）。

## 稳定性策略

| 接口 | 稳定性 | 说明 |
|---|---|---|
| `extension.Router` | V1 起稳定 | 第三方路由插件依赖 |
| `extension.Inspector` / `Transformer` | V1 起稳定 | 内容插件契约；能力分级见上 |
| `extension.Capabilities` / `Phase` / `Action` / `Finding` / `Document` / `Leaf` | V1 起稳定 | 插件契约核心类型 |
| `extension.CostSink` | V1 起稳定 | |
| `extension.AuditExporter` | V1 起稳定 | |
| `extension.Registry` | **可能变动** | 依装配方式，装配稳定后冻结 |
| `Request` / `Response` 结构 | **可能变动** | 随协议演进调整，遵循语义化版本 |

- 公开接口以**语义化版本**管理；破坏性变更升级 major。
- 第三方扩展在 v1.0 前不建议依赖未冻结的字段。

## 第三方扩展

V1 只支持**编译内置**的插件（见 [plugins.md](plugins.md)），没有运行时加载 WASM / 子进程 / 动态库的机制。这类机制（如用于生态而非 IP 保护的 WASM 沙箱）不在 V1 范围内。第三方扩展在 v1.0 前不建议依赖未冻结的字段。
