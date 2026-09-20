# tokenhush 架构

tokenhush v0.5.0 是对 tokenhush 内核的一次从头重写。它保留安全不变量与供应链
线格式，并删除所有证据表明已经冗余或重复的子系统。本文是架构地图：分层依赖图、
单一规则抽象、冻结的供应链字节表面，以及把这一切组装起来的 CLI。

- [重写的四个目标](#重写的四个目标)
- [分层依赖图](#分层依赖图)
- [单一规则抽象](#单一规则抽象)
- [数据路径一瞥](#数据路径一瞥)
- [两个签名输入投影](#两个签名输入投影)
- [冻结的字节表面](#冻结的字节表面)
- [七命令 CLI](#七命令-cli)

## 重写的四个目标

1. **更轻。** 只保留不可妥协的不变量与扩展机制。旧内核约有 60,551 行 Go 代码，
   复杂度集中在少数几个子系统上——变更通道自保护守卫、出站编码复检、只有一个
   消费者的 keyring/secret store、两套并行的 SSE 累加器、两份独立的签名机制。
   它们在这里一概不再创建。
2. **过滤/替换 = 一个最小且高度可扩展的框架。** 单一规则抽象
   `pkg/filter` 的 `Rule` 就是*唯一*的扩展点。内置检测器、签名远程规则包与第
   三方规则都经由同一个公共注册表进入。
3. **供应链保留。** 签名规则同步与签名自更新与既有后端保持字节兼容：相同的
   端点、相同的域标签、相同的内嵌密钥 ID、相同的文档 schema 与相同的 floor
   行为。
4. **精简、清晰分层、高度可扩展。** 每个包只向下依赖，允许的边由测试
   （`internal/layering`、`scripts/check-layering.sh`）强制执行，而不是靠约定。

## 分层依赖图

依赖只朝一个方向。下图的箭头表示"导入"；没有环，兄弟包之间从不互相深入。

```
platform          -> (stdlib only)
audit             -> (stdlib only)
protocol          -> (stdlib only)

redact            -> protocol
filter            -> protocol, audit
config            -> platform

supply            -> stdlib, platform, filter

proxy             -> protocol, redact, filter, audit, config, platform

internal/cli      -> everything (the ONLY assembler)
cmd/tokenhush     -> internal/cli

internal/guards   -> (analysis only; imported by nothing)
internal/layering -> (analysis only; imported by nothing)
internal/layering/cmd -> internal/layering
```

这个图里有三条承重性质：

- **`filter` 与 `redact` 是兄弟，不是栈。** `filter` 产出发现，`redact` 执行
  替换；两者互不导入，由 `proxy` 编排。正是这个切分让不变量 1 成为结构性事实：
  只向前替换的 writer 住在 `redact`，响应路径永远到不了它。
- **`supply -> filter` 是有意为之。** 规则文档 schema、严格解码器与非弱化
  floor 都住在 `pkg/filter`，`pkg/supply` 在激活任何规则包之前先调用它们完成
  校验。
- **`internal/cli` 是唯一的组装点。** `pkg/proxy`、`pkg/filter`、`pkg/redact`
  与 `pkg/supply` 都是带可注入 seam 的库；只有 `internal/cli` 把它们接成一个
  运行中的产品，并拥有命令表面。

## 单一规则抽象

`pkg/filter` 拥有唯一导出的扩展契约：

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

每一条规则——编译进二进制的检测器、来自签名远程规则包的规则、第三方在自己的包
里注册的值——都经由同一个注册表抵达同一个求值器。规则只提供 span：规则 id、
动作与来源（origin）由内核盖章，因此规则无法冒充另一条规则或伪造自己的来源。

规则作者可以依赖的性质，以及内核实名拒绝的行为：

- **确定性顺序。** 按 `Priority` 升序、同优先级按 `ID` 打破平局；编译文档路径
  与直接注册路径顺序完全一致，规则不可能以文档身份和值身份得到两种顺序。
- **失败关闭且带标签。** 规则 panic、超时、超出 span 预算或返回畸形输出时，会产生
  一个带标签的拒绝，原因是五种之一（`panic`、`timeout`、`budget`、`malformed`、
  `error`）——绝不静默放过，也绝不崩溃。
- **注册即闸门。** 整批规则先整体校验再写入，被拒绝的注册不会改变注册表分毫。
- **没有能力分级、没有 gate、除 `Scope` 之外没有阶段、没有失败策略协商。** 注册
  即求值，没有任何可协商项。
- **方向契约。** 响应路径上规则只能 `Block` 或 `Warn`。`Redact` 仅限请求路径；
  作用域包含响应阶段而动作是 `redact` 的规则，会在编译期（文档）与注册期
  （直接注册的值）两处被拒绝。
- **有预算上限的原始检测器。** 原始类型规则（`prefix`、`email`、`luhn`、`jwt`、
  `pem`、`entropy`）每个叶最多检查自己的每原始检测器字节预算。`internal/cli`
  对已准入的请求把该预算与 `scan_budget_bytes` 对齐，因此检测成本保持 O(budget)，
  预算也绝不是静默盲区：超过预算的请求叶会在 stderr 上报（仅元数据），且不移动
  任何计数器。
- **带类型、严格校验的 options。** 编译后的规则文档可以携带 `options` 对象：每个
  可参数化检测器一个带类型的子对象，绝不是自由形式的 map。严格解码会按名以带类型
  的错误拒绝未知选项键，同一套校验在编译期还会再跑一次。目前唯一的选项是 `email`：
  追加式 `suffixes` 扩展内置公共后缀集合，`replace` 则用声明的后缀整体换掉内置
  集合——只允许非远程的本地文档，因为远程包设置它会被 floor 拒绝。

第三方示例与完整注册语义见 [plugins.md](plugins.md)，注册表强制的不变量见
[security.md](security.md)。

## 数据路径一瞥

运行时各部件是这样串起来的：

1. **启动顺序固定，永不重排。** `tokenhush run` 先对正在运行的二进制执行崩溃
   恢复，再加载配置、构建管线（只读规则缓存，绝不联网）、绑定回环监听、写会话
   文件，最后才开始服务。绑定成功之前不写任何东西。
2. **每个请求先过回环守卫。** 在路由之前先检查 `Host` 头与 `Origin`，非回环或
   跨源请求在做任何事之前就被拒绝。
3. **路由是一张显式表。** 内置厂商路径解析到 OpenAI 兼容或 Anthropic 风格上游；
   `GET /v1/models` 是唯一本地应答的路由；配置的 `upstreams` 条目优先于内置表；
   其余路径是带类型的 `unknown_upstream` 拒绝——近似路径永不猜测。
4. **出站请求先走叶遍历、求值与重写。** 声明为 JSON 却无法遍历的 body 以 400
   拒绝；非 identity 的 `Content-Encoding` 在读取 body、打开任何上游连接之前以
   415 拒绝。请求阶段决策随后允许、阻断或替换。替换是**逐 span 精确**的：每个
   解码后的检测 span 都会映射回拼写它的原始转义字节，因此多行或带引号的 secret
   以占位符离开、并原样返回。脱敏日志行与 `redactions` 计数器只统计真正改变了
   字节的替换。原始类型检测器每个叶最多扫描 `scan_budget_bytes` 字节——对已准入
   的请求，每原始检测器预算与配置的扫描预算对齐——超过预算的叶会在 stderr 上报
   （仅元数据），而不是静默失败。脱敏对每个请求整段客户端提供的对话只运行一次，因此
   在长会话中每轮都会重新扫描并重新脱敏相同的 secret：`redactions` 计数器与该 stderr
   日志随携带的出现次数增长，而不是随不同 secret 的数量增长；这是仅含元数据、按请求
   进行的工作，绝不持久化任何 body。
5. **回客户端响应在提交任何字节之前整段缓冲。** 每个上游响应——包括
   `text/event-stream`——都先缓冲并解码，无法解码的内容编码以 502 拒绝并丢弃
   上游字节，绝不未检查地透传。缓冲后的响应随后被求值并回填，最后只提交一次；
   不存在 token 级流式输出。缓冲由 `response_buffer_bytes`（默认 32 MiB）设界，
   整段读取由 `response_timeout`（默认 5m）设界：超过上限是 502，超过 deadline
   是 504，二者都在提交之前决定，若同时触发则上限优先。回填最后执行，且只还原
   本会话铸造过的占位符。还原是**转义/深度感知**的：还原的 secret 按外层 JSON
   深度重新拼写（与客户端发出的拼写完全一致），因此多行或带引号的 secret 不会
   破坏客户端的 JSON。原始流片段或非 JSON body 保持原始拼写；外部占位符按字节
   原样返回。在**同一通道身份**、**连续**的**完整 JSON 信封** `data:` 事件之间
   做内容层拆分的占位符会被精确还原一次：每个被扣留分段针对**自身原始字节**应用
   一次编辑，贡献片段被删除、由补全叶携带 secret，因此每个发出的信封都保持合法
   JSON。联合 **256 KiB** 预算（`protocol.SSEBackfillHoldbackBytes`；写者尾部加上
   未解析 carry 再加上被扣留分段）为扣留内存设界；一旦将超限，被扣留分段按字面
   释放、不还原。这种有界扣留只发生在唯一一次提交内部，客户端永远观察不到——
   它一次收到整段已还原的流。**撕裂的内层 JSON 起始叶**（非 `Encoded`、非法
   JSON、以 `{` 或 `[` 开头）、其 secret 需要 JSON 转义时，会保留**占位符**，
   而不是破坏客户端嵌套文档——即 `docs/security.md` R6 记录的残余。若非匹配通道
   的事件在两半之间交织进来，被扣留的分段会按原样释放，该拆分只会以字面形式
   送达、不还原。
6. **控制表面恰好是 `GET /status`。** 仅含元数据，需要会话 bearer token；数据
   平面与控制表面是两个独立的 mux 模式。

## 两个签名输入投影

供应链有两类文档，各自签名一个**不同**的投影。二者永不统一：后端与尚未进行的
离线密钥仪式都冻结在现有字节之上。

| 文档族 | 签名输入 |
|---|---|
| update 文档 | `domain + "\n" + 每字段一行 key:value`，时间戳为**epoch 秒** |
| rule 文档 | `domain + "\n" + hex(sha256(json.Marshal(payloadStruct)))` |

对 rule 文档族，**三个** payload 结构体形状全部冻结——pack、manifest 与
revocations 各自精确复刻旧实现的字段集、字段顺序、JSON 名、类型与 `omitempty`
标签。投影只从原始、未套用默认值的解码值计算，绝不在套用 `scope: request` 或
`confidence: 0.9` 之类的默认值之后计算，因为多出的键会出现在既有文档里、破坏其
签名。新字段一律 `omitempty`，且不出现在任何既有文档中。

## 冻结的字节表面

`pkg/supply` 与 `pkg/filter` 内部其余部分都可以重构（重复机制的合并正是这样完成
的）；下表表面不可更改。

| 表面 | 冻结值 |
|---|---|
| 源站与端点 | `https://updates.tokenhush.com` 加 `/v1/update/{manifest,revocations,keylist}` 与 `/v1/rules/{manifest,bundle,revocations}`，始终带 `?channel=stable` |
| 域标签 | `tokenhush-update-manifest-v1`、`tokenhush-update-revocations-v1`、`tokenhush-update-keylist-v1`、`tokenhush-rules-manifest-v1`、`tokenhush-rules-pack-v1`、`tokenhush-rules-revocations-v1` |
| 内嵌密钥 ID | `root-2026-09`（update 信任根）与 `rules-2026-09`（rule 信任根），只含公钥半。在线更新密钥（`upd-*`）经由根签名密钥列表获取，绝不内嵌。 |
| 两个文档大小上限 | update 文档（`manifest`、`revocations`、`keylist`）：**128 KiB**。rules 文档（`manifest`、`bundle`、`revocations`）：**256 KiB**。既不收紧也不放宽。 |
| 制品上限 | 下载的二进制制品：**256 MiB**（`MaxArtifactBytes`），由独立的有界 fetcher 抓取，不得继承文档上限。 |
| 线上检测器与类别 ID | 检测器 `prefix`、`high_entropy`、`jwt`、`private_key`、`luhn`、`email`；类别 `api_key`、`high_entropy`、`jwt`、`private_key`、`credit_card`、`email` |
| floor 行为 | 恰好拒绝四件事：禁用基线检测器的包、丢弃必需类别的包、携带 `allow` 动作的规则，以及设置 email `replace` 标志的规则。追加式 `email.suffixes` 扩展内置公共后缀集合，仍然允许。它对 allowlist 保持中立（OD-3）。 |
| 缓存与防回滚布局 | `<DataDir>/rules/{active,revoked.json,<serial>/{manifest,bundle}.json,highwater.json}` 与 `<DataDir>/update/highwater.json`；原子写入，权限 `0600` |
| 会话文件 | `<DataDir>/run.json`（`pid`、`port`、`addrs`、`started_at`；绝不含 token）与 `<DataDir>/control.token`；原子、权限 `0600`、干净退出时删除 |
| 占位符语法 | `__PII_<type>_<digest>__` |
| 脱敏日志行 | `tokenhush: redacted request <type> (len=<N>) <masked>`，只写 stderr，永不落盘 |

## 七命令 CLI

`internal/cli` 是各包唯一的组装处，其命令注册表恰好有七个动词。增加第八个是一次
有意的产品变更，而不是接线时的意外。

| 命令 | 作用 |
|---|---|
| `tokenhush run` | 启动网关：崩溃恢复、加载配置、构建管线、绑定回环、写会话文件、服务。标志：`--config`、`--port`、`--log-level`、`--log-redactions`。 |
| `tokenhush rules` | `rules sync [--check]` 校验并激活签名规则包；`rules rollback` 回到此前验证过的 serial。`--check` 在一次性沙箱中跑完全部检查，不写任何真实状态。 |
| `tokenhush update` | 检查并应用签名二进制更新，遵循 D17 安装来源路由（Homebrew 与 Scoop 委托；只有 self-managed 安装自替换）。`--check` 只报告，不下载、不安装、不写入。 |
| `tokenhush status` | 读取会话文件并询问运行中网关的控制表面。`--json` 输出冻结的十键文档。网关未运行时输出 `not running` 并以 1 退出。 |
| `tokenhush env <tool>` | 为十四种受支持工具之一打印接入片段，把其 base URL 指向回环网关。 |
| `tokenhush privacy` | 打印由 `egress.yaml` 渲染的出口披露：恰好两个厂商绑定类别，各带开关、主机与保留期。`--json` 输出同一文档的 JSON 形式。 |
| `tokenhush version` | 打印 OD-1 版本行（`v0.5.0`）以及构建目标与工具链。 |

退出码冻结，因为脚本会观察它们：`0` 成功、`1` 检查或操作失败、`2` 用法错误
（未知命令或工具、非法标志值）。未知命令的消息按字典序列出已注册命令，因此帮助
文本永远不会宣传不存在的命令。
