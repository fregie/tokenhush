# Writing Plugins — tokenhush (public core)

> 状态：V1 已实现（2026-09）。本文面向想扩展检测/改写能力的作者；接口定义见 [extension-api.md](extension-api.md)，安全边界见 [security.md](security.md)。

Tokenhush 的内容处理是一条**编译内置、能力分级**的插件流水线。内置的六种检测器（`pkg/redact`）本身就是插件；你写的新插件走同一套接口，遵循同一套最小权限约束。V1 **没有动态加载**——插件在构建时编入二进制。

## 心智模型

```
出站请求 body ──▶ 解析为叶子 ──▶ Inspectors ──▶ 策略引擎 ──▶ 核心脱敏 ──▶ 上游
入站响应 body ──▶ 解析为叶子 ──▶ Inspectors ──▶ 策略引擎 ──▶ Transformers ──▶ 核心回填 ──▶ 客户端
```

两条铁律：

1. **插件只提议，核心做决定。** Inspector 返回 `Finding`（含期望的 `Action`），由核心的策略引擎聚合（`Allow < Warn < Redact < Block`）并执行。
2. **出站明文只有核心能动。** `Transformer` **只能**声明 `response_content` / `metadata`——请求内容和原始 header 永远不会交给它。占位符 ↔ 原文映射对插件不可达。

## 两种插件

| 接口 | 作用 | 允许的 phase | 返回 |
|---|---|---|---|
| `Inspector` | 检测，报告 `Finding` | 全部四种 | `[]Finding` |
| `Transformer` | 改写文档（仅入站） | `response_content`、`metadata` | `*Document` |

两者都实现 `Plugin`：

```go
type Plugin interface {
    ID() string
    Capabilities() Capabilities
}
```

## Phase 与 Capabilities

`Phase` 标识生命周期位置：

| Phase | 含义 |
|---|---|
| `extension.RequestContent` | 出站请求 body 的叶子 |
| `extension.ResponseContent` | 入站响应 body 的叶子 |
| `extension.Header` | header（**仅元数据**，取值永远被抹掉） |
| `extension.Metadata` | 非内容元数据（工具、模型、字节数…） |

`Capabilities` 是你申请的权限。**申请得越少，核心放行得越多**：

```go
extension.Capabilities{
    Phases:       []extension.Phase{extension.RequestContent},
    ReadContent:  true,   // 不申请就只能看到 leaf 路径与长度
    CanTransform: false,  // 仅 Transformer 需要
    CanBlock:     false,  // true 才能让策略采纳 Block
    CanNetwork:   false,  // 编译内置第三方层一律被拒
    Priority:     100,    // 升序执行；同优先级按 id 升序
}
```

- 未申请 `ReadContent` 时，`Leaf.Content == nil`，只有 `Leaf.Path` 与 `Leaf.Len`。
- `Header` phase 无论是否申请 `ReadContent`，`Content` 都被清空——**`Authorization` / `Cookie` / API key 取值永不进入插件**。
- 返回 `Block` 的 `Finding` 只有在 `CanBlock` 为真时才有效；否则核心视该插件输出非法。

## 核心为你保证什么

- 调用前核心已对文档做 `extension.Gate`：越权内容看不到，未声明 phase 的文档不会交给你。
- 你返回的 `Finding.PluginID` 会被核心覆写为你自己的 `ID()`——无法伪造他人来源。
- `Inspect` 在独立的 goroutine 中带超时调用，并 `recover` panic；插件崩溃/超时**绝不静默**。
- 响应 Transformer 在**回填之前**运行，所以它的输出不可能包含只有回填才会还原的原文。
- 核心只按叶子序号（优先）或路径（兜底）把你返回的内容拼回 body；`Content` 为 `nil` 或与原文相等时保持原 token。

## 写一个 Inspector

下面是一个完整、可直接编译的检测器：把字面量 `INTERNAL-` 标记为 `Redact`。

```go
package myplugins

import (
	"bytes"

	"github.com/fregie/tokenhush/pkg/extension"
)

type InternalMarker struct{}

func NewInternalMarker() *InternalMarker { return &InternalMarker{} }

func (*InternalMarker) ID() string { return "example_internal_marker" }

func (*InternalMarker) Capabilities() extension.Capabilities {
	return extension.Capabilities{
		Phases:      []extension.Phase{extension.RequestContent},
		ReadContent: true,
		Priority:    100,
	}
}

func (*InternalMarker) Inspect(doc *extension.Document) ([]extension.Finding, error) {
	const marker = "INTERNAL-"
	var findings []extension.Finding
	for i, leaf := range doc.Leaves {
		for at := 0; at+len(marker) <= len(leaf.Content); {
			j := bytes.Index(leaf.Content[at:], []byte(marker))
			if j < 0 {
				break
			}
			start := at + j
			findings = append(findings, extension.Finding{
				LeafIndex:  i,
				Start:      start,
				End:        start + len(marker),
				Type:       "internal_marker",
				Confidence: 0.9,
				Action:     extension.Redact,
			})
			at = start + len(marker)
		}
	}
	return findings, nil
}
```

要点：

- `Start`/`End` 是**该 leaf 内**的字节偏移，`End` 开区间；必须落在 `len(Content)` 内。
- `Confidence` 必须在 `[0,1]`；否则整个插件被判非法。
- 不要自作主张写占位符——核心的脱敏引擎负责替换。
- 越界/负偏移/未知 `Action` 都会让核心把**整个插件**判为非法（不会只丢弃你那条错误 finding）。

## 写一个 Transformer

Transformer 只能声明 `response_content` / `metadata`，用于改写入站响应（例如统一某类字段）。它**看不到原文 secret**。

```go
package myplugins

import "github.com/fregie/tokenhush/pkg/extension"

type HeaderStamper struct{}

func NewHeaderStamper() *HeaderStamper { return &HeaderStamper{} }

func (*HeaderStamper) ID() string { return "example_response_stamper" }

func (*HeaderStamper) Capabilities() extension.Capabilities {
	return extension.Capabilities{
		Phases:       []extension.Phase{extension.ResponseContent},
		ReadContent:  true,
		CanTransform: true,
		Priority:     200,
	}
}

func (*HeaderStamper) Transform(doc *extension.Document) (*extension.Document, error) {
	for i := range doc.Leaves {
		if len(doc.Leaves[i].Content) == 0 {
			continue
		}
		// 例：仅演示改写能力；真实插件应保持结构化，避免破坏 JSON。
		doc.Leaves[i].Content = append([]byte("handled: "), doc.Leaves[i].Content...)
	}
	return doc, nil
}
```

- 返回 `nil` 文档表示“不改写”，核心沿用上一版。
- 多个 Transformer 按 `Priority` 链式执行，后一个看到前一个的结果。
- Header phase 的 `Content` 始终为空，Transformer 拿不到 header 取值。

## 注册插件（编译内置）

插件在启动时注册进 `extension.Registry`，`Register` 就是安全闸门：

```go
reg := extension.NewRegistry()
if err := reg.Register(myplugins.NewInternalMarker()); err != nil {
    return err
}
if err := reg.Register(myplugins.NewHeaderStamper()); err != nil {
    return err
}
```

公开核心的 `tokenhush run` 只注册内置检测器。V1 **没有**运行时加载外部插件的开关——不支持 `.so` / WASM / 子进程，也没有“插件目录”。要让自定义插件生效，有两种方式：

1. **贡献到核心**：把插件加入内置集合，随核心一起评审发布。
2. **构建你自己的宿主程序**：写一个导入本核心库的独立 `main` 包，用导出的 `pkg/proxy` 原语自行装配流水线，把你的 registry 传进去。私有 Pro 构建就是这个模式；它的代码永远不会出现在公开仓库。

用导出原语装配的大致形状（示意；字段以 `PipelineConfig` 为准）：

```go
package main

import (
	"log"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/redact"
	// ...你的插件
)

func main() {
	reg := extension.NewRegistry()
	if err := reg.Register(NewInternalMarker()); err != nil {
		log.Fatal(err)
	}

	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		log.Fatal(err)
	}
	pipe, err := proxy.NewPipeline(proxy.PipelineConfig{
		Registry: reg,
		Engine:   engine,
		Tool:     "my-host",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = pipe
	// 再用 proxy.Listen / NewResolver / NewForwarder /
	// HostAllowlist / ControlAuth / OriginPolicy 组装出你的 server。
}
```

> `pkg/proxy` 导出 `Listen`、`NewPipeline`、`NewResolver`、`NewForwarder`、`HostAllowlist`、`ControlAuth`、`OriginPolicy` 等原语；`internal/cli` 的 `run` 装配是它们的参考用法（`internal/` 不可被外部模块导入）。

## 注册期会被拒绝的情况

`Register` 返回**类型化错误**（用 `errors.Is` 判断），任一不满足就不入库：

| 错误 | 触发 |
|---|---|
| `ErrNotAPlugin` | nil / typed-nil / 不实现 Inspector 或 Transformer |
| `ErrMissingID` | id 为空或只有空白 |
| `ErrDuplicateID` | id 已注册 |
| `ErrNoPhases` | 没声明 phase |
| `ErrInvalidPhase` | 声明了未定义的 phase |
| `ErrTransformerPhase` | Transformer 声明 `request_content` / `header` |
| `ErrNetworkDenied` | 声明 `CanNetwork` |
| `ErrInvalidPriority` | 负优先级 |

同时实现 Inspector 和 Transformer 的插件会被按**更严的 Transformer 规则**校验（只能声明 `response_content` / `metadata`）。

## 失败策略

- 默认 `FailOpenWarn`：插件报错/超时/panic 时记录一条审计告警，请求继续。
- `FailClosed`：用于关键检测器，失败即拒绝请求（返回 `Block`）。内置检测器采用更稳健的配置。
- 无论哪种策略，**失败都会留下审计告警**，绝不静默吞掉。

## 测试你的插件

插件是普通 Go 类型，直接单测即可，不需要起网关：

```go
func TestInternalMarker(t *testing.T) {
	doc := &extension.Document{
		Phase: extension.RequestContent,
		Leaves: []extension.Leaf{
			{Path: "/messages/0/content", Content: []byte("token INTERNAL-42 end")},
		},
	}
	findings, err := NewInternalMarker().Inspect(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Action != extension.Redact {
		t.Fatalf("want one redact finding, got %+v", findings)
	}
}
```

也要覆盖：回归到核心注册闸门（`Register` 拒绝越权能力）、`Gate` 下的可见性（无 `ReadContent` 时 `Content == nil`）、以及越界 finding 被判非法的路径。仓库内 `pkg/redact/*_test.go` 是很好的范例。

## Do / Don't

- **Do** 申请最小 `Capabilities`；只声明你真正处理的 phase。
- **Do** 对任意字节（含非法 UTF-8）保持健壮，绝不 panic。
- **Do** 用 `Finding` 表达意图，让核心决定并执行。
- **Don't** 试图持有或重建 占位符 ↔ 原文 映射——接口不提供。
- **Don't** 在 `RequestContent` 上做改写（只有 Inspector 能在请求侧动作）。
- **Don't** 依赖 `CanNetwork`；编译内置层会被拒绝。
