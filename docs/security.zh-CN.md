# tokenhush 安全模型

本文是 v0.5.0 重写对运维者可见的安全契约。它列出内核保留的八条不变量与它不隐藏的
九项残余风险，说明各项在何处强制，并给出钉住每条不变量的测试名。

- [方向契约](#方向契约)
- [八条不变量](#八条不变量)
- [响应阶段的效应](#响应阶段的效应)
- [缓冲响应与 SSE](#缓冲响应与-sse)
- [磁盘上有什么](#磁盘上有什么)
- [九项残余风险](#九项残余风险)

## 方向契约

内容有两个方向，规则在各方向可采取的动作不同。这是被强制的设计规则，不是残余风险：
响应路径上规则只能 `Block` 或 `Warn`，`Redact` 仅限请求路径；作用域包含响应阶段
而动作是 `redact` 的规则会在编译期与注册期两处被拒绝。编译期拦截文档路径；注册表
拦截直接注册的 Go 值；求值循环再次断言。没有任何到达途径能在响应路径上请求替换。

| 阶段 | 可被应用的动作 |
|---|---|
| 请求内容（出站） | `Block`、`Redact`、`Warn`。`Redact` 是占位符 writer 唯一运行的地方。 |
| 响应内容（回客户端） | 仅 `Block` 与 `Warn`。`Redact` 被拒绝。 |
| 两者 | 规则可以在任一阶段*求值*。只有请求阶段可以替换。 |

## 八条不变量

以下八条不变量全部在代码中强制，并由具名测试钉住。

| # | 不变量 | 具名测试 | 所属文件 |
|---|---|---|---|
| 1 | Never backfill placeholders outbound | `TestInvariant1NeverBackfillOutbound` | `pkg/redact/invariants_test.go` |
| 2 | No request/response plaintext on disk; metadata only | `TestInvariant2NoPlaintextOnDisk` | `pkg/audit/invariants_test.go` |
| 3 | No root certificate, no MITM by default | `TestAbsenceNoCertificateInstallPath` | `internal/guards/absence_guard_test.go` |
| 4 | Loopback-only bind, Host/Origin validation and the control bearer token | `TestInvariant4LoopbackOnly` | `pkg/proxy/invariants_test.go` |
| 5 | Fail-safe on detection failure, not fail-open | `TestInvariant5FailSafe` | `pkg/filter/invariants_test.go` |
| 6 | Exactly two switchable vendor-bound egress categories, command-scoped | `TestInvariant6NoVendorEgress` | `pkg/proxy/invariants_test.go` |
| 7 | Content-Encoding fail-closed | `TestInvariant7EncodingFailClosed` | `pkg/proxy/invariants_test.go` |
| 8 | SSE-aware bounded backfill (256 KiB) | `TestInvariant8BoundDerived` | `pkg/redact/invariants_test.go` |

每条不变量的实际含义：

1. **绝不向出站回填占位符。** 出站 writer 只持有正向映射（secret → placeholder），
   没有反向映射也没有还原方法，其导出表面仅限铸造占位符。重复应用脱敏是幂等的，
   且已携带已知占位符的 body 原样转发。
2. **请求/响应明文不落盘；只落元数据。** 审计 seam 只有一个写方法，只写元数据记录；
   默认 sink 是 no-op，不持久化任何东西。脱敏日志经过掩码、只写 stderr、永不落盘。
   具名 sink 级测试 `TestInvariant2NoPlaintextOnDisk` 位于
   `pkg/audit/invariants_test.go`；运行级另一半 `TestOndiskGuardRunLevelPlaintext`
   位于 `internal/guards/ondisk_guard_test.go`，驱动真实二进制并扫描该次运行可能
   写入的一切。
3. **默认无根证书、无 MITM。** tokenhush 从不终止 TLS。absence 守卫扫描生产 Go
   源码中证书安装或 MITM 路径所需的每一种形状——TLS 监听器、密钥对、证书池、
   `tls.Config` 与 `http.Server` 字面量、内嵌证书、MITM 风格的配置键——一旦出现
   即失败。
4. **仅回环绑定、Host/Origin 校验与控制 bearer token。** 非回环绑定不可能成功
   （`ErrNonLoopbackBind`）；外部 `Host` 被拒绝；跨源请求被拒绝；控制表面缺少凭据
   返回 401、错误凭据返回 403。会话文件权限 `0600`，且 `run.json` 绝不含 token。
5. **检测失败时故障关闭，而非故障开放。** 规则 panic、超时、超出 span 预算、返回
   畸形发现或根本无法调用时，会产生带正确原因的标签化拒绝——绝不静默放过、绝不
   崩溃——且每次失败恰好写一条仅含元数据的审计记录。检测同时受预算限制：原始类型
   检测器每个叶最多检查自己的每原始检测器字节预算，把 `scan_budget_bytes` 作为
   每叶、每检测器预算对齐。预算截断是可观察的而非静默的：超过预算的请求叶恰好写
   一行仅含元数据的 `tokenhush: detector budget exceeded leaf=<len> budget=<n>`
   到 stderr，且不移动任何计数器与任何状态键。
6. **恰好两个可开关、命令限期绑定的厂商出口类别。** 产品只可为两种已披露用途触达
   厂商，且仅在运维者未设置已披露开关之前。这条不变量由两个产物共同证明，缺一不可：
   具名测试证明数据平面恰好发起一次上游拨号、对厂商主机零拨号；出口守卫
   `internal/guards/egress_guard_test.go` 证明披露恰好声明两个类别、各自命名其开关、
   每个主机都是冻结的供应链主机，且每个开关在任何网络调用之前短路。
7. **Content-Encoding 故障关闭。** 携带非 identity `Content-Encoding` 的请求在读取
   body、打开任何上游连接之前以 415 拒绝。响应方向先解码 gzip 与 deflate，再提交
   任何状态码；网关无法解码的编码以 502 拒绝并丢弃上游字节，且不移动内容计数器。
   不存在未检查的透传。
8. **SSE 感知的有界回填（256 KiB）。** SSE 流中未终止的 token 永远不能让回填 writer
   持有超过 `SSEBackfillHoldbackBytes`（256 KiB）的数据；越过界限后最旧的数据按字面
   顺序释放，因此 writer 始终有进展，而不是无限缓冲。不丢字节，也不伪造字节。

## 响应阶段的效应

这些效应可被观察，因此被冻结：

| 条件 | 效应 |
|---|---|
| 响应作用域规则决定 `Block` | 502，body 中给出规则 id，且在提交任何字节之前返回；整个已缓冲的上游响应被丢弃；会话的 `rule_blocks` 计数器自增 |
| 响应作用域规则决定 `Warn` | 响应原样转发；仅含元数据的警告行写入 stderr；计数器不变 |
| 缓冲响应超过 `response_buffer_bytes` | 在提交任何字节之前返回 502，被丢弃的 body 不做求值 |
| 缓冲响应超过 `response_timeout` | 在提交任何字节之前返回 504；若两者同时触发，缓冲上限优先 |
| 回填 | 在回客户端路径上始终最后执行，位于任何求值之后 |

回填绝不在求值之前运行，只向前替换的 writer 在响应路径上永远不可达。模型回显的
本会话已知占位符会被还原后交给客户端；本会话从未发放过的外部占位符按原样返回，
绝不会被伪造成 secret。

## 缓冲响应与 SSE

每个上游响应都会**整段**缓冲，之后才会有任何字节抵达客户端：网关先记录状态码与
header，缓冲并解码 body（无法解码的内容编码以 502 拒绝并丢弃上游字节、不做提交），
然后才求值、还原、提交。`text/event-stream` 同样如此。SSE 不再逐 token 流式输出：
其事件先被解码，对每个 `data` 合并后为合法 JSON 的事件所构成的聚合求值，回填最后
运行，还原后的流一次性发出。客户端手上不存在任何网关无法收回的部分响应，也不存在
token 级的流式输出。

SSE 缓冲响应上的响应作用域 `Block` 是在提交任何字节之前返回的 502，与缓冲 JSON
响应完全一致：因为什么都没发出，所以没有需要撤回的内容。缓冲上限由
`response_buffer_bytes`（默认 **32 MiB**）约束；超过上限的响应在提交前返回 502。
整段读取由 `response_timeout`（默认 **5m**）约束；超过 deadline 的响应在提交前返回
504，若两者同时触发则上限优先。回填仍然最后运行，因此跨 SSE `data:` 事件做内容层
拆分的占位符会在唯一一次提交之前被精确还原。

## 磁盘上有什么

| 路径 | 内容 |
|---|---|
| `<DataDir>/run.json` | `pid`、`port`、`addrs`、`started_at`。绝不含控制 token。权限 `0600`，原子写，干净退出时删除。 |
| `<DataDir>/control.token` | 会话控制 bearer token。权限 `0600`，原子写，干净退出时删除。 |
| `<DataDir>/rules/…` | 已验证的规则缓存与防回滚标记：签名文档与序列号，不含请求内容。 |
| `<DataDir>/update/highwater.json` | 更新防回滚标记：一个 serial/version 整数，别无其他。 |

请求与响应 body、检测出的 secret、以及占位符到 secret 的映射，永不写入磁盘。脱敏日志行
`tokenhush: redacted request <type> (len=<N>) <masked>` 只写 stderr、永不持久化；
其掩码形式要么不泄露任何内容（`****`、`[redacted]`），要么只泄露不透明凭据类型的有界
前缀与后缀。脱敏对每个请求整段客户端提供的对话只运行一次，因此在长会话中每轮都会重新
扫描并重新脱敏相同的 secret：`redactions` 计数器与该 stderr 日志随携带的出现次数增长，
而不是随不同 secret 的数量增长。这是仅含元数据、按请求进行的工作，绝不持久化任何 body。

## 九项残余风险

这些风险被诚实记录，而不是被隐去。列出它们并不等于声称它们不存在；每一项都是本设计的
已知边界。

| # | 残余风险 | 实际含义 | 状态 |
|---|---|---|---|
| R1 | Encoded secrets are not caught（编码后的 secret 不会被捕获） | base64、hex 或 URL 编码后才离开的 secret 不会被检测：本次重写有意不设 normalization 传递，且非 identity 的请求 `Content-Encoding` 会以 415 拒绝，而不是为检测而解码。JSON 字符串*转义*在**两个方向**都已处理——每个解码后的检测 span 在替换时会映射回拼写它的原始转义字节，且回客户端路径的还原是转义/深度感知的：按外层 JSON 深度重新拼写还原的 secret，使客户端 body 保持合法 JSON——因此残余仅是内容编码（base64、hex、URL 编码，或嵌套在另一容器里的 gzip），绝不是任一方向上的 JSON 字符串转义。 | 已记录并接受 |
| R2 | A secret in a JSON object key is not caught（JSON 对象键中的 secret 不会被捕获） | 放在 JSON 对象键而不是值里的 secret 会原样转发：按 D10，键位置阻断被删除，叶遍历不提供键叶，也不存在死的键表面。`sensitive_keys` 文档块不改变这一点——它脱敏的是**值**（任意深度上、立即对象成员键名匹配者），绝不是存放在键里的 secret。两种同形仍不匹配，记录在此：敏感键的值是容器而非字符串成员时（`{"password":{"secret":"x"}}`，其立即键是 `secret`），以及 k8s/docker-env 同形（`{"name":"DB_PASSWORD","value":"…"}`）。 | 已记录并接受 |
| R3 | A signed remote pack may weaken detection through its own allowlist（签名远程包可能通过自身 allowlist 弱化检测） | 签名远程包可能通过其全局或每条规则的 allowlist 压制匹配：按 OD-3，非弱化 floor 对 allowlist 保持中立、不检查 allowlist；规则签名密钥 `rules-2026-09` 仍是信任根。 | 已记录并接受 |
| R4 | The OD-2 command-rule rejection is dormant and the v2 manifest bump is backward-incompatible（OD-2 command 规则拒绝处于休眠，v2 manifest 升级不向后兼容） | OD-2 的 `command` 规则拒绝保持休眠，直到 OD-4 闸门打开；闸门只在规则 manifest `schema_version` 达到 2 时打开；该升级与钉住 `== 1` 的客户端不兼容，因此后端必须继续提供 v1 manifest，直到旧版本线退出支持。 | 已记录并接受 |
| R5 | Response-path bodies are not capped by the request-side body guard（响应路径 body 不受请求侧 body 护栏约束） | 响应 body 不受请求侧护栏限制：`response_buffer_bytes`（默认 **32 MiB**）是整个缓冲响应的一个**独立的、总量**上限，超过它的响应在提交前返回 502。请求侧的 `max_body_bytes` 内存护栏从不作用于响应，而每叶、每检测器的 `scan_budget_bytes` 在两个方向上都不是整段 body 上限。这个总量上限并没有关闭 R5。响应作用域的原始检测器仍最多扫描每原始检测器 `budget`：超过该预算的响应叶会被截断，且没有 stderr 报告、没有计数器，因此响应作用域检测仍可能漏掉总量上限放行 body 中超出每原始检测器预算的内容。预算报告仍有意只存在于请求路径，且不移动任何状态键。 | 已记录并接受 |
| R6 | A placeholder split across SSE JSON-envelope `data:` events is only partially restored（跨 SSE JSON 信封 `data:` 事件拆分的占位符仅部分还原） | 占位符在**完整 JSON 信封**的 `data:` 事件之间做内容层拆分时，现在会被精确还原一次，`choices[].delta.content` 通道与 `tool_calls[].function.arguments` 通道皆然：每个贡献事件只从自身事件字节里删除自己的片段，且每个发出的信封仍是独立合法的 JSON；匹配在**解码域**进行，因此像 `__PII_\u0061pi_key_…__` 这样的转义拼写也会被接受并还原。该关闭在拆分跨越**同一通道身份**的**连续** `data:` 事件时成立。剩余边界：当上游把 JSON 文档本身撕开时，token 仍能跨拆分补全，但只有**原始拼写**可知，带引号、反斜杠或控制字节的 secret 会以原始形态落在信封片段中；而当**起始叶**是撕裂的内层 JSON 片段（非 `Encoded`、非法 JSON、以 `{` 或 `[` 开头）、其 secret 又需要 JSON 转义时，会刻意**保留**占位符，而不是破坏客户端嵌套文档。另一项残余是**交织**拆分：若在两半之间到达一个非匹配通道的事件，被扣留的分段会在该事件处按**字节原样、不做改动**释放，token 因此永不补全，占位符片段以**字面**形式送达客户端，该拆分**不会**被还原。无匹配的 JSON 事件流（包括其值以不完整的 `__PII_` 前缀收尾者）**字节完全一致**，拆分的异源占位符同样字节一致，且绝不会被捏造成 secret。延迟契约（所有者决策 D13）：token 未解析期间，**仅受影响通道**的贡献分段被扣留、不发送给客户端，直到 token 解析（通常是接下来 1-2 个事件）或联合 **256 KiB** 预算触发，届时被扣留的分段按字面释放、不还原；延迟局限于受影响通道，其余流量照常流动，因为对该通道而言，正确性（绝不发出不完整占位符）与有界内存优先于零新增延迟。同一时刻**只有一个** carry 生效；通道身份 = RFC 6901 路径 + 每个外层 frame 的前置非字符串标量成员 + 该叶在同路径叶中的 0 基出现序号，因此**省略**判别性标量（或在该叶之后才发出该标量）的事件不在身份之内、不会匹配；比内层更深一层的撕裂嵌套、且 secret 需要转义时，仍是残余。 | 部分关闭；剩余项已记录并接受 |
| R8 | The global blocklist is not applied on every evaluation path（全局 blocklist 并非在每条求值路径上都被应用） | `Policy.Decide` 与共享的 `collect` 不应用全局 blocklist；只有 `Compiled.Evaluate` 运行 `blocklistSpans`。因此 `sensitive_keys` 门控叶与其余每个叶在 `Compiled.Evaluate` 路径上保持 Block 优先，但通过 `Policy.Decide` 决策的调用方不会得到全局 blocklist 的应用。这一点被记录而不是被修复：blocklist 不被压制的测试位于 `Compiled.Evaluate` 路径上。 | 已记录并接受 |
| R7 | The opt-in `high_entropy` detector replaces legitimate base64 payloads（按需启用的 `high_entropy` 检测器会替换合法 base64 载荷） | `entropy` 默认关闭，因为合法的高熵载荷与 secret 在构造上无法区分：设置 `detectors: {entropy: true}` 后，OpenAI `image_url` 片段或 Anthropic `image` 内容块里约 2.7 KB 的 base64 图片会在请求抵达上游之前被替换成单个占位符，因此模型看不到该图片——客户端仍会通过回填收到它，但上游载荷已被替换。仅对不携带图片、data URL 或长随机标识符的工作负载启用它，或者接受这次替换。纯 hex 串仍被排除，因此 hex 摘要不受影响。 | 已记录并接受 |
| R9 | The request body guard is a memory wall, and the second walk is unguarded（请求 body 护栏是内存墙，且第二次遍历不受保护） | 等于或低于 `max_body_bytes`（默认 64 MiB）的 body 在声明 JSON 的路径上现在要被遍历两次，而只有**第一次**遍历（`DataPlane.inspect`）运行在 `guardCall` 内、受 `detector_timeout`（30 秒）约束。第二次遍历（Forwarder 内的 `redactRequest`）**不受保护、没有超时**：实践中第一次遍历把住了准入，但它不是对第二次的约束。`protocol.Walk` 会复制每个叶值（`[]byte(raw)`），因此一次遍历会再占用大致一个 body 大小的内存，而声明 JSON 的请求要遍历两次，所以峰值内存是 body 的一个小倍数，而不是 body 本身。准入上限从旧的 32 MiB 总量预算提高到 64 MiB body 护栏，使既有的标量/路径/身份放大暴露窗口从 32 MiB 扩大到 64 MiB；`MaxNestingDepth` 仍为嵌套设界，第一次遍历在超时时仍故障关闭，超时后被放弃的遍历 goroutine 是既有行为。超过 `max_body_bytes` 的 body 仍以 403 `body_too_large` 拒绝；由于会话只会增长，仍可能再次触墙——区别在于这堵墙现在是可观察、可处置的（一行仅含元数据的 `tokenhush: refused request body_too_large`），而不再是静默的总量拒绝。 | 已记录并接受 |

每项为何保持现状：

- **R1——不设 normalization 传递。** 解码"自身包含 JSON 的 JSON 字符串"（递归编码
  字符串）在范围内；解码*编码*不在。JSON 字符串转义不属于本残余：替换路径会把每个
  解码 span 映射回其原始转义字节，回客户端路径的还原同样按外层 JSON 深度重新拼写，
  两个方向都不会破坏 JSON。normalization 传递因与检测重复并且带来虚假信心
  而被删除；诚实的立场是：编码后的 secret 可能通过。
- **R2——键位置阻断是删除，不是降级。** 叶遍历完全不提供键叶，因此不存在半可用的
  键路径来误导运维者。
- **R3——floor 保持 allowlist 中立。** 让 floor 检查 allowlist 会拒绝旧客户端接受过
  的签名包，使客户端退回内置检测器、比它替代的客户端更弱。那是安全退步，不是加固。
  信任根是签名密钥；弱化检测的包是签名密钥持有者选择发布的包。
- **R4——协调后的后端变更，不是随手拨动的开关。** 闸门客户端侧已实现并测试；后端必须
  继续提供 v1 manifest，直到没有受支持的客户端钉住 `== 1`。OD-4 闸门的存在，就是让
  客户端行为在 manifest 版本移动之前先行就绪。
- **R5——总量上限不是每原始检测器预算。** `response_buffer_bytes` 为整个缓冲响应
  设界，是一个新的响应侧表面，但它是总量上限，不是每叶检测预算：它无法指出响应作用域
  检测器漏扫了哪些字节。关闭剩余截断要么让每原始检测器预算对齐整个 body，要么新增
  响应路径预算报告（一种本次重写拒绝的新可观察表面）。响应作用域检测器仍受同一
  每原始检测器预算约束，每原始检测器截断被记录而不是被隐藏。
- **R6——信封拆分是上游的选择；完整信封内容拆分现已关闭。** 事件值在文档中途被拆分的
  JSON 信封流，任何客户端本就无法逐事件解析，因此没有可保留的逐事件 JSON 文档；有界
  重组器仍会跨拆分补全 token，但只有原始拼写可知，带引号、反斜杠或控制字节的 secret
  会以原始形态落在信封片段中。撕裂的内层 JSON 起始叶、其 secret 又需要 JSON 转义，是
  第二项残余：会有意保留占位符，而不是破坏客户端嵌套文档。当每个事件都是完整 JSON
  信封时，内容层拆分的占位符会被精确还原一次，涉及 `content` 与
  `tool_calls[].function.arguments` 通道，匹配在解码域进行，因此转义拼写也会被接受；
  无匹配流与拆分的异源占位符保持字节一致；若非匹配通道的事件在两半之间到达，被扣留的分段按字节原样、不做改动释放，token 永不补全，片段以字面形式送达客户端、不还原。延迟契约（D13）是这份正确性刻意付出的代价：
  受影响通道的贡献分段被扣留，直到 token 解析或联合 `256 KiB` 预算触发，随后按字面
  释放、不还原。缓冲 body 与未被拆分的 JSON 信封继续使用深度感知、保持合法 JSON 的
  还原。这些残余都不会向第三方隐藏 secret：客户端才是预期的接收方。
- **R7——entropy 默认关闭是有原因的。** 高熵并不是 secret 的证据：一张图片、一个
  data URL 或一个随机标识符看起来与 secret 一模一样。因此该检测器默认关闭，它对
  合法 base64 载荷所做的替换被记录在此，而不是被隐藏。从不携带此类载荷的工作负载
  可以启用它；会携带的工作负载则不应启用。
- **R8——既有缺口，因门控而显形。** 全局 blocklist 一直只在 `Compiled.Evaluate`
  路径上应用；`sensitive_keys` 门控没有制造该缺口，因此在这里修复它会是无关的行为
  变更。门控在 blocklist 真正运行的路径上保持 Block 优先，运行时缺口被记录，而不是
  被悄悄声称已修复。
- **R9——墙移到了内存护栏。** 旧的总量拒绝是一种会在合法多模态流量上触发的扫描
  策略；诚实的替代方案是在 body 边界设一道内存护栏，让拒绝有名有姓
  （`body_too_large`）并被记录一次。第二次不受保护的遍历与逐叶复制是遍历两次的
  既有代价；为第二次遍历设界会改变 forwarder 的契约，因此在这里记录而不是修复。

## 相关文档

- [architecture.zh-CN.md](architecture.zh-CN.md)——分层图、单一规则抽象与冻结的字节
  表面。
- [plugins.zh-CN.md](plugins.zh-CN.md)——扩展点及其限制。
- [PRO-MIGRATION.md](PRO-MIGRATION.md)——本次重写落地后 Pro 仓库必须做的事。
