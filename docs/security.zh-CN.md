# tokenhush 安全模型

本文是 v0.5.0 重写对运维者可见的安全契约。它列出内核保留的八条不变量与它不隐藏的
四项残余风险，说明各项在何处强制，并给出钉住每条不变量的测试名。

- [方向契约](#方向契约)
- [八条不变量](#八条不变量)
- [响应阶段的效应](#响应阶段的效应)
- [SSE 的限制](#sse-的限制)
- [磁盘上有什么](#磁盘上有什么)
- [四项残余风险](#四项残余风险)

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
   端到端的磁盘扫描在最终验收波中补齐这条不变量。
3. **默认无根证书、无 MITM。** tokenhush 从不终止 TLS。absence 守卫扫描生产 Go
   源码中证书安装或 MITM 路径所需的每一种形状——TLS 监听器、密钥对、证书池、
   `tls.Config` 与 `http.Server` 字面量、内嵌证书、MITM 风格的配置键——一旦出现
   即失败。
4. **仅回环绑定、Host/Origin 校验与控制 bearer token。** 非回环绑定不可能成功
   （`ErrNonLoopbackBind`）；外部 `Host` 被拒绝；跨源请求被拒绝；控制表面缺少凭据
   返回 401、错误凭据返回 403。会话文件权限 `0600`，且 `run.json` 绝不含 token。
5. **检测失败时故障关闭，而非故障开放。** 规则 panic、超时、超出 span 预算、返回
   畸形发现或根本无法调用时，会产生带正确原因的标签化拒绝——绝不静默放过、绝不
   崩溃——且每次失败恰好写一条仅含元数据的审计记录。
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
| 响应作用域规则决定 `Block`（缓冲响应） | 502，body 中给出规则 id；上游字节被丢弃；会话的 `rule_blocks` 计数器自增 |
| 响应作用域规则决定 `Warn` | 响应原样转发；仅含元数据的警告行写入 stderr；计数器不变 |
| 回填 | 在回客户端路径上始终最后执行，位于任何求值之后 |

回填绝不在求值之前运行，只向前替换的 writer 在响应路径上永远不可达。模型回显的
本会话已知占位符会被还原后交给客户端；本会话从未发放过的外部占位符按原样返回，
绝不会被伪造成 secret。

## SSE 的限制

SSE 流上响应作用域的 `Block` 无法撤回已经发出的增量：决策发生在第一个完整事件求值
之时，因此客户端已经收到的事件仍会被投递。阻断 SSE 响应只会从那一刻起停止流，不会
收回前缀。需要全有或全无响应的运维者不应让流式请求经过响应作用域的阻断规则。

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
前缀与后缀。

## 四项残余风险

这些风险被诚实记录，而不是被隐去。列出它们并不等于声称它们不存在；每一项都是本设计的
已知边界。

| # | 残余风险 | 实际含义 | 状态 |
|---|---|---|---|
| R1 | Encoded secrets are not caught（编码后的 secret 不会被捕获） | base64、hex 或 URL 编码后才离开的 secret 不会被检测：本次重写有意不设 normalization 传递，且非 identity 的请求 `Content-Encoding` 会以 415 拒绝，而不是为检测而解码。 | 已记录并接受 |
| R2 | A secret in a JSON object key is not caught（JSON 对象键中的 secret 不会被捕获） | 放在 JSON 对象键而不是值里的 secret 会原样转发：按 D10，键位置阻断被删除，叶遍历不提供键叶，也不存在死的键表面。 | 已记录并接受 |
| R3 | A signed remote pack may weaken detection through its own allowlist（签名远程包可能通过自身 allowlist 弱化检测） | 签名远程包可能通过其全局或每条规则的 allowlist 压制匹配：按 OD-3，非弱化 floor 对 allowlist 保持中立、不检查 allowlist；规则签名密钥 `rules-2026-09` 仍是信任根。 | 已记录并接受 |
| R4 | The OD-2 command-rule rejection is dormant and the v2 manifest bump is backward-incompatible（OD-2 command 规则拒绝处于休眠，v2 manifest 升级不向后兼容） | OD-2 的 `command` 规则拒绝保持休眠，直到 OD-4 闸门打开；闸门只在规则 manifest `schema_version` 达到 2 时打开；该升级与钉住 `== 1` 的客户端不兼容，因此后端必须继续提供 v1 manifest，直到旧版本线退出支持。 | 已记录并接受 |

每项为何保持现状：

- **R1——不设 normalization 传递。** 解码"自身包含 JSON 的 JSON 字符串"（递归编码
  字符串）在范围内；解码*编码*不在。normalization 传递因与检测重复并且带来虚假信心
  而被删除；诚实的立场是：编码后的 secret 可能通过。
- **R2——键位置阻断是删除，不是降级。** 叶遍历完全不提供键叶，因此不存在半可用的
  键路径来误导运维者。
- **R3——floor 保持 allowlist 中立。** 让 floor 检查 allowlist 会拒绝旧客户端接受过
  的签名包，使客户端退回内置检测器、比它替代的客户端更弱。那是安全退步，不是加固。
  信任根是签名密钥；弱化检测的包是签名密钥持有者选择发布的包。
- **R4——协调后的后端变更，不是随手拨动的开关。** 闸门客户端侧已实现并测试；后端必须
  继续提供 v1 manifest，直到没有受支持的客户端钉住 `== 1`。OD-4 闸门的存在，就是让
  客户端行为在 manifest 版本移动之前先行就绪。

## 相关文档

- [architecture.zh-CN.md](architecture.zh-CN.md)——分层图、单一规则抽象与冻结的字节
  表面。
- [plugins.zh-CN.md](plugins.zh-CN.md)——扩展点及其限制。
- [PRO-MIGRATION.md](PRO-MIGRATION.md)——本次重写落地后 Pro 仓库必须做的事。
