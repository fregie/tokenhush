# Pro 迁移说明

**中文** | [English](PRO-MIGRATION.md)

本说明记录本次重写与私有 Pro 仓库之间的关系。**Pro 迁移在本文中记录，但不由本计划执行。** Pro 明确不在本次重写的范围内。

## 状态：硬分叉

- Pro 仓库继续通过它的 `tokenhush-pro/go.work` workspace 针对**旧版**树构建，其 `use ../tokenhush` 指令指向旧版检出。在 Pro 完成迁移之前，该指令必须一直指向那里。
- 本次重写是一次**硬分叉**。这里没有 Pro 契约：没有面向 Pro 的网关组装契约，没有生命周期钩子，没有供 Pro 使用的依赖注入表面，除下面一个刻意的例外之外也没有向后兼容 shim。
- 模块路径未变（`github.com/fregie/tokenhush`）。这恰恰是 `use` 指令重要的原因：把 `use ../tokenhush` 重新指向这棵树，会让 Pro 在相同 import 路径下针对不同的 API 编译，而无需做出任何迁移决策。
- **本次重写落地后，Pro 需要一份单独的迁移计划。** 本仓库没有任何部分设计成通过钉住版本字符串来增量采用；迁移是一次需要自行评审的刻意移植。

## 唯一的兼容例外

`pkg/filter` 仍然解码 **schema-v1 规则文档**。签名后端发布 schema-v1 文档，因此一旦这个客户端替换掉旧版客户端，丢掉该解码器就会拒绝每一个真实规则包。这是本次重写中唯一刻意的兼容路径；它之所以刻意，是因为传输格式已冻结，而不是因为支持旧版内部结构。

除此之外全是硬断裂：配置键、flag、命令集、包布局、Go API 表面与文档结构全部重写，没有任何 shim。

## Pro 可以依赖不变的部分

- **供应链传输格式。** 端点、路径、channel 查询、domain 标签、内嵌的信任根 id（`root-2026-09`、`rules-2026-09`）、三个规则载荷结构体、floor 的行为与文档大小上限全部冻结，并由 golden vector 钉住。针对旧版客户端设计的签名后端，在这个客户端上继续可用。
- **版本线从 `v0.5.0` 开始。** 规则 manifest 的 `min_binary_version` 闸门针对同一个版本来源求值，因此 `0.3.0` 的 floor 继续得到满足。
- **占位符语法与脱敏日志格式。** 如果 Pro 观察到其中任一，字节均未改变（见仓库 README 的验证步骤）。

## Pro 迁移时必须重做的部分

以下表面发生了根本变化，依赖旧版版本的 Pro 代码必须移植，而不是用 shim 兜住：

| 表面 | 变化 |
|---|---|
| 组装 | 没有 `pkg/gateway`，也没有 15 字段的 `Options` 契约。`internal/cli` 是唯一的组装者；需要自定义管线的 Pro 二进制自行组合公开包。 |
| 配置 | schema 严格且封闭：未知键是错误。已删除子系统的旧版键不复存在。 |
| CLI | 恰好七个命令：`run`、`rules`、`update`、`status`、`env`、`version`、`privacy`。没有 `doctor`，也没有独立的 `allowlist` 命令。 |
| 状态 | `GET /status` 就是整个控制 API，配一份冻结的十键元数据文档。 |
| 已删除的子系统 | change-channel guard、出站编码复检、键位置阻断、能力层级、keyring/secret store、`pkg/license`、OS 服务桩以及运行时插件协议都不存在。建立在这些之上的 Pro 功能需要新设计，否则必须放弃。 |
| 扩展点 | 规则仅限编译期，通过 `pkg/filter` 的 `Rule` 注册表。没有运行时插件加载，也没有能力协商。 |
| 响应路径 | 规则只能 block 或 warn；脱敏仅限请求路径。 |
| SSE 响应 | 增量式 `SSEHandler` 不再做决策（见下文）。 |
| 响应上限 | 新增配置键 `response_buffer_bytes`（默认 32 MiB）与 `response_timeout`（默认 5m）。整个响应（含 SSE）在提交任何字节之前被整段缓冲：超过上限是 502，超过 deadline 是 504，二者都在提交之前。 |

## SSE 响应处理器不再做决策

响应作用域求值已迁移到**整段响应缓冲**路径。网关缓冲 `text/event-stream` 响应、
解码其声明的 Content-Encoding、对每个 `data` 合并后为合法 JSON 的事件所构成的聚合
求值（遍历失败的 JSON 事件记一次 `walk_skip`；非 JSON、`[DONE]`、ping/comment 或
零叶事件不计），之后才提交：响应作用域的 Block 是在什么都没发出时返回的 `502`。
增量式 `proxy.SSEHandler` 现在只做重组与占位符还原——它的 `Evaluator`、`Counters`
与 `Warnings` 配置字段为 API 兼容而保留，但已**失效**，生产路径不再发出流内 block
记录。依赖旧的"首个完整事件、流内 block"语义或其错误记录的 Pro 代码，必须改为消费
缓冲后的裁决。

## 规则包新增可选 `sensitive_keys` 块

`RulesPackPayload` 新增 `SensitiveKeys *SensitiveKeysPayload`，声明在 **`Blocklist`
之后、`Rules` 之前**。声明顺序决定投影字节，因此发出该块的 Pro 签名后端必须使用同一
槽位。载荷类型为 `SensitiveKeysPayload{Keys []string; CaseSensitive bool}`，JSON 名为
`keys`/`case_sensitive` 且带 `omitempty`，且该字段是指针并带 `omitempty`，因为
`encoding/json` 不会省略零值结构体：非指针字段会把该键加进每一个既有原像、使所有既有
签名失效。**不提升 `schema_version`**。不含该块的规则包与今天逐字节一致地序列化，而
携带它的规则包会被旧客户端的 `DisallowUnknownFields` 解码拒绝、回退到内置检测器；只能
向支持它的客户端发出该块。客户端侧该块是追加式的（它增加一次对匹配的立即对象成员键的
值的固定请求阶段脱敏），因此 floor 不会拒绝它。

## 迁移清单（供独立的 Pro 工作使用）

1. 在移植完成之前，**不要**把 `tokenhush-pro/go.work` 重新指向这棵树。让 `use ../tokenhush` 保持在旧版检出上。
2. 审计 Pro 代码中对已删除包以及旧版 `pkg/gateway` 组装契约的 import；每一处都是移植决策，而不是改名。
3. 把 Pro 配置文件迁移到严格 schema，并删除已删除的键。
4. 在专用分支上针对本模块重建 Pro，保持供应链后端冻结：签名侧不变，因为传输格式没变。
5. 在切换 `use` 指令之前，针对移植后的构建重跑 Pro 自己的测试套件，包括它保留的任何 golden vector。
6. 把 `use ../tokenhush` 的切换当作最后一步，而不是第一步。

## 相关文档

- [architecture.zh-CN.md](architecture.zh-CN.md)——分层图与冻结的字节表面，包括 Pro 后端已经实现的传输格式。
- [security.zh-CN.md](security.zh-CN.md)——不变量与残余风险。
- [plugins.zh-CN.md](plugins.zh-CN.md)——仅限编译期的扩展点。
