# tokenhush 插件

tokenhush 恰好有一个扩展点：`pkg/filter` 的 `Rule` 接口。检测器不是特殊对象
——六个内置检测器、签名远程规则包中的规则、以及第三方从自己的包编译进来的规则，
都实现同一契约、经由同一个公共注册表抵达。

- [契约](#契约)
- [检测器 options](#检测器-options)
- [`sensitive_keys` 块](#sensitive_keys-块)
- [从你自己的包中编译进规则](#从你自己的包中编译进规则)
- [内核提供与不提供什么](#内核提供与不提供什么)
- [响应阶段限制](#响应阶段限制)
- [远程包与-floor](#远程包与-floor)

## 契约

```go
type Rule interface {
	ID() string           // stable wire id; unique across the registry
	Type() string         // regex | keyword | prefix | email | luhn | jwt | pem | entropy
	Category() string     // api_key | email | credit_card | private_key | jwt | high_entropy | custom
	Scope() Scope         // request | response | both
	Action() Action       // allow | warn | redact | block
	Priority() int        // ascending; ties break on ID
	Confidence() float64  // in (0,1]
	Inspect(leaf []byte) []Span
}
```

规则检查一个叶值——请求或响应 body 里的一个字符串——并返回它认为敏感的字节
span。这就是全部职责。规则 id、动作与来源（origin）由内核盖章；规则无法冒充另一条
规则或伪造自己的来源，也不能自行替换任何内容。

注册表是唯一入口：

```go
reg := filter.NewRegistry()
err := reg.Register(myRule, myOtherRule)        // OriginPlugin
err = reg.RegisterBuiltin(builtinRules...)      // OriginBuiltin
err = reg.RegisterCompiled(compiledDocument)    // OriginRemotePack
```

`Register` 是第三方路径。整批规则先整体校验再写入，被拒绝的注册不会改变注册表
分毫。重复 id、非法 id 或元数据、以及响应阶段可 `redact` 的规则，都会以带类型、
指名该规则的错误被拒绝。注册应在求值开始之前完成；构造完成的注册表此后只读，
`Evaluate` 不保留状态，因此并发求值是安全的。

求值顺序确定，且对所有来源完全一致：按 `Priority` 升序，同优先级按 `ID` 打破
平局。规则 panic、超时、超出 span 预算（`MaxRuleSpans`）或返回畸形元数据/span 时，
会以带标签的 `*RuleFailure` 故障关闭，原因是五种之一（`budget`、`timeout`、
`error`、`panic`、`malformed`）——绝不产生部分结果，也绝不崩溃。

原始类型的内置规则还受预算上限约束：`prefix`、`email`、`luhn`、`jwt`、`pem` 与
`entropy` 每个叶最多检查自己的每原始检测器字节预算。`internal/cli` 对已准入的请求
把该预算与 `scan_budget_bytes` 对齐；`filter.CompileWithBudget`、
`filter.BuiltinDetectorsBudget` 与 `New*RuleBudget` 构造器可显式设置它，
`Compiled.Budget()` 报告生效值。超过预算的请求叶会在 stderr 上报（仅元数据），
绝不静默跳过。

## 检测器 options

编译文档中的规则可以在 `type` 旁携带 `options` 对象。它是每个可参数化检测器一个
带类型的子对象，绝不是自由形式的 map：严格解码会按名以带类型的错误拒绝未知选项键，
同一套校验在编译期还会再跑一次，因此手工构造的文档也无法绕过。

目前唯一的检测器选项是 `email`：

| 键 | 类型 | 含义 |
|---|---|---|
| `email.suffixes` | 字符串列表 | 追加式：每个条目扩展内置公共后缀集合。条目会被规范化（去空白、转小写、恰好一个前导点），列表上限 256 条。 |
| `email.replace` | 布尔值 | 用声明的 `suffixes` 整体替换内置公共后缀集合。仅允许非远程的本地文档；远程包设置它会被 floor 拒绝。 |

追加式 `email.suffixes` 只能扩展内置集合，因此签名规则包可以补上它需要的后缀，
但永远无法移除或收窄任一内置后缀。内置后缀表本身编译进程序且已冻结。

## `sensitive_keys` 块

编译文档可以在其 `rules` 旁携带一个文档级的 `sensitive_keys` 块。它是严格的子对象，
不是规则类型：

| 键 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| `keys` | 字符串列表 | 无（必填） | 其值要被脱敏的对象成员键名。至少一个键，最多 `MaxSensitiveKeys`（256）个，每个键最多 256 字节（`MaxLiteralBytes`）；空键会被拒绝。 |
| `case_sensitive` | 布尔值 | `false` | 为 false（默认）时折叠 ASCII 大小写；为 true 时成员键必须逐字节匹配。 |

未知子键会以 `sensitive_keys.<name>` 按名被拒绝，且同一套校验在解码路径与编译路径
都会运行，因此手工构造的文档无法跳过任何边界。该块不携带 `action` 字段：其效果是
固定的请求阶段 `redact`。

匹配依据是叶的**立即对象成员键，在任意对象深度**：因此 `{"password":"hunter2"}` 与
`{"credentials":{"password":"hunter2"}}` 都匹配 `password`，而数字键永远不会匹配
数组元素。命中的叶整体作为一个 finding 被脱敏——不会铸造任何内部替换，因此不会产生
孤儿占位符——但会让该叶 `Block` 的规则仍会被求值并保持 Block 优先，全局与每条规则的
allowlist 也仍会压制该 finding。

两种形态仍不匹配，属于已记录的残余（见 `security.md` R2）：敏感键的值是容器而非字符串
成员时（`{"password":{"secret":"x"}}`），以及 k8s/docker-env 同形
（`{"name":"DB_PASSWORD","value":"…"}`）。而放在 JSON 对象键本身的 secret 仍不会被
捕获。

### 签名规则包的投影槽位

签名规则包把这个块作为其规则载荷的可选字段携带。`SensitiveKeys` 声明在 **`blocklist`
之后、`rules` 之前**；声明顺序决定投影字节，因此 Pro 签名后端必须使用同一槽位。该字段
是指向结构体的指针并带 `omitempty`，这一点至关重要：`encoding/json` 不会省略零值结构体，
非指针字段会把该键加进每一个既有原像、使所有既有签名失效。不含该块的规则包与今天
逐字节一致地序列化，**不提升 `schema_version`**。操作层面的后果已记录：使用
`DisallowUnknownFields` 严格解码器的旧客户端会拒绝携带该块的规则包并回退到内置检测器，
因此后端只能向支持它的客户端发出该块。

## 从你自己的包中编译进规则

插件就是普通的 Go 包。它导入 `pkg/filter`、实现契约，并在组装时注册自己的规则：

```go
package myrules

import (
	"bytes"

	"github.com/fregie/tokenhush/pkg/filter"
)

type TicketRule struct{}

func (TicketRule) ID() string            { return "ticket" }
func (TicketRule) Type() string          { return filter.TypePrefix }
func (TicketRule) Category() string      { return filter.CategoryCustom }
func (TicketRule) Scope() filter.Scope   { return filter.ScopeRequest }
func (TicketRule) Action() filter.Action { return filter.ActionRedact }
func (TicketRule) Priority() int         { return 10 }
func (TicketRule) Confidence() float64   { return 0.95 }

func (TicketRule) Inspect(leaf []byte) []filter.Span {
	at := bytes.Index(leaf, []byte("TICKET-"))
	if at < 0 {
		return nil
	}
	return []filter.Span{{Start: at, End: at + 7}}
}
```

然后注册并求值：

```go
reg := filter.NewRegistry()
if err := reg.Register(TicketRule{}); err != nil {
	return err
}
findings, err := reg.Evaluate(leaves, filter.ScopeRequest)
```

`findings` 是内核盖章的 `AttributedFinding` 值，调用者总能分辨某个 span 来自哪条
规则、哪个类别、哪种来源。同一个注册表把内置规则、远程包规则与插件规则放在一起
求值，使用同一个确定性顺序。

`pkg/filter` 自带这条路径的验收测试：`pkg/filter/external_plugin_test.go` 在外部
测试包中定义规则，经由公共 API 注册，并与一条以编译文档形式到达的规则一起求值。

## 内核提供与不提供什么

| 提供 | 不提供 |
|---|---|
| 一个 `Rule` 接口与一个公共注册表 | 能力分级、gate、以及 `Scope` 之外的阶段 |
| 内核盖章的三种来源（builtin、remote pack、plugin） | 注册时的能力闸门或插件权限模型 |
| 确定性顺序（`Priority` 升序，同序按 `ID`） | 失败策略协商——一切失败都故障关闭 |
| 带标签的故障关闭，每次失败恰好一条仅含元数据的审计记录 | 插件可配置的超时或预算 |
| 注册时整批校验 | 运行时插件加载 |

**没有运行时插件加载。** 规则只在编译期进入（D12）：没有 WASM、没有 `.so` 共享
对象、没有子进程插件、没有脚本层。插件是编译进导入它的二进制里的 Go 代码——这
正是契约可审计、失败模型简单的原因。

## 响应阶段限制

响应路径上规则只能 `Block` 或 `Warn`。`Redact` 仅限请求路径，因为替换需要会话的
占位符 writer，而响应路径绝不能触及它。该限制在两条到达路径上同时强制：

- 编译文档中 `scope` 为 `response` 或 `both`、动作为 `redact` 的规则，在编译期被
  拒绝；
- 直接注册的 `Rule` 若为同样组合，在注册期以带类型的错误被拒绝。

限制放在注册期而不是留给运维者，因此插件无法通过声明一个本不该拥有的作用域来扩大
自己的权限。

## 远程包与 floor

签名远程包不是另一套扩展机制：它的规则经由 `RegisterCompiled` 进入，并与其余一切
按同一顺序求值。远程包额外受两条约束：

- **非弱化 floor。** 规则包可以增加检测、提高灵敏度，但 floor 恰好拒绝四件事：禁用
  基线检测器的包、丢弃必需类别的包、携带 `allow` 动作的规则，以及设置 email
  `replace` 标志的规则（那会换掉内置后缀集合）。追加式 `email.suffixes` 扩展内置
  集合，仍然允许；规则包追加式的 `sensitive_keys` 块同样不会被 floor 拒绝。floor 对
  allowlist 保持中立（OD-3）：它不检查全局或每条规则的 allowlist，因为更严格的 floor
  会拒绝真实签名包、使客户端退回内置检测器。
- **信任根。** 规则包只有在通过内嵌规则信任根（`rules-2026-09`）的签名校验之后才会
  被编译。本地运维者文档与签名远程包共用同一个严格解码器与编译器；只有远程路径受
  floor 约束。

注册表强制的不变量与 allowlist 中立 floor 带来的残余风险，见
[security.zh-CN.md](security.zh-CN.md)；`pkg/filter` 在分层图中的位置，见
[architecture.zh-CN.md](architecture.zh-CN.md)。
