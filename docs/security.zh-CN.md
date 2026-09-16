# 安全模型

[English](security.md) | **中文**

> 状态：V1 已实现（2026-09）。硬不变量由 `pkg/*` 中的具名测试锁定，并在下方“硬不变量”一节和 `architecture.zh-CN.md` 中重述。

Tokenhush 本身就是安全工具，所以**它自己必须先安全**。本文档定义威胁模型，以及不能破坏的不变量。

## 🛡️ 威胁模型

| 威胁 | 描述 | 缓解 |
|---|---|---|
| **提示注入导致外泄** | 攻击者诱导模型输出占位符；网关若在出站方向回填，密钥就会泄露 | **硬不变量：绝不向出站方向回填**（见硬不变量） |
| **本地恶意进程/网页访问网关** | 任何本地进程或浏览器页面都能 `fetch` `127.0.0.1:8787` | 仅绑环回（`127.0.0.1`；主机有 IPv6 环回时同时绑 `[::1]`）；校验 `Host` 头；控制面额外要求每次 `run` 生成的 bearer token，以 `0600` 存盘，并对携带 `Origin` 的请求做同源校验；运行期白名单只能经该已鉴权控制面变更，且每次变更写一条仅元数据审计行 |
| **DNS 重绑定** | 恶意域名解析到 127.0.0.1，绕过同源 | 校验 `Host`/`Origin` 头 |
| **占位符冲突** | 两个密钥映到同一占位符，导致错误回填 | HMAC 确定性映射 + 高熵后缀 |
| **从内存读明文** | 同一用户下的另一进程调试或转储 | 沙箱/加固运行时；不明文写盘 |
| **供应链攻击** | 依赖被投毒（见 LiteLLM 事件） | 最小依赖 + 固定版本 + 签名发行版 + SBOM |

其中两条值得展开看看。

- **提示注入长什么样。** 被投毒的文件让模型打印 `__PII_email_3f9a2b__`。模型照做、回显占位符，网关若出站回填，真邮箱就发往上游。不变量 1 堵住这条路：回填只朝客户端走。
- **本地可达性长什么样。** 环回不是墙。随机 npm `postinstall` 脚本，或开着的网页，都能调 `fetch("http://127.0.0.1:8787/...")`。但它过不了：只绑环回、校验 `Host`、每次 `run` 生成的 bearer token。

## 🛡️ 硬不变量

1. **绝不向出站方向回填占位符。** 回填只发生在返回给客户端的响应上。
2. **默认不存请求/响应明文。** 核心不保存请求或响应内容。控制台上的脱敏日志只是一条瞬时的本地诊断：只含掩码形式、检测器类型与字节长度，绝不含完整值，也绝不持久化。它默认开启，可用 `--log-redactions=false` 关闭。
3. **默认不装根证书，也不做 MITM。** MITM 在后续阶段是显式选择加入，公开核心不实现。
4. **本地服务仅绑环回：始终绑 `127.0.0.1`；主机有 IPv6 环回时同时绑 `[::1]`。主机没有 IPv6 环回时只服务 `127.0.0.1`，并打印提示。**
5. **检测失败时失败安全（fail-safe），不是失败开放（fail-open）。** 网关判断不了内容是否敏感时，宁可过度脱敏，或在告警下放行，绝不静默发出明文。该策略可配置（见下）。唯一能在运行期放行某个具体值的入口是白名单：变更必须是人经环回控制面（CLI 或 Pro Web UI）做出的显式、可审计动作，绝不是静默改文件；模型不是授权变更主体。
6. **面向厂商的外发仅有更新检查与规则同步两个可关、按命令触发的类别。** 这两个类别均记录在机器可读的 [`egress.yaml`](../egress.yaml) 中且均可关闭；二者都不由网关数据面执行：代理请求仍只发往配置的上游，占位符绝不向出站方向回填，审计接缝仅携带元数据。
7. **入站响应若带非 identity 的 `Content-Encoding`，要么被解码，要么 fail-closed——绝不未经检视就透传。** 管线会分类**每一行** `Content-Encoding`（用 `Header.Values` 按逗号拆分，而非只取首个值）。`gzip`/`deflate` 的 body 在 buffered 路径中、**提交任何状态码之前**整体解压，随后检视并回填，并删除 `Content-Encoding`。不支持的编码（`br`、`zstd` 等）、解压失败，或 `text/event-stream` body 上的可解编码，一律应答 **502 Bad Gateway** 并丢弃上游字节。由 `TestPipelineGzipResponseBackfilled`、`TestPipelineDecodableResponseInspected`、`TestPipelineUndecodableEncodingFailsClosed`、`TestPipelineMultiValuedEncodingFailsClosed` 锁定。
8. **入站请求若带非 identity 的 `Content-Encoding`，在任何改写之前、拨号上游之前即以 415 拒绝。** 否则客户端压缩过的请求体会绕过脱敏，因为请求路径只遍历明文 JSON，无法解码压缩体。该检查位于 `Forwarder.ServeHTTP`——唯一能读到该头的层：body 从不读取，不运行任何改写，也不建立上游连接。由 `TestPipelineCompressedRequestBodyFailsClosed` 锁定。
9. **入站回填对 SSE 感知，且其保留量有界。** 占位符可能被拆到多个 `data:` 事件（每个携带一段部分 JSON delta）里，在原始字节流中找不到，因此回填器按 JSON 叶子路径重新拼装，并在该路径窗口于事件边界清空时还原。被改写的事件就地拼接，故 SSE 分帧、事件数、以及所有非 delta 字段（`event:`、`id:`、`retry:`、注释、多行或无冒号 `data:`）都逐字节保留。保留字节由 `sseBackfillMaxHoldbackBytes`（256 KiB）限定；超过上限时最旧的窗口按字面文本刷出。由 `TestPipelineSSEBackfillAcrossDeltas`、`TestSSEBackfillerRestoresAcrossProviderDeltaPaths`、`TestSSEBackfillerHoldbackBoundEnforcedFromConstant` 锁定。

> [!IMPORTANT]
> 正是不变量 1，让提示注入没法把网关变成外泄通道：占位符只在返回客户端的路径上被替换。

> [!NOTE]
> **兼容性变更（有意为之）。** 过去会压缩请求体的客户端（`Content-Encoding: gzip`）被原样转发，从而静默绕过脱敏——压缩字节不是可遍历的 JSON。现在它会收到 **415 Unsupported Media Type**（不变量 8）。这是 fail-safe 取舍：宁可拒绝请求，也不转发未检视的 body。响应方向同理：上游无视 identity 请求仍返回 `br`/`zstd` 时，应答 **502**（不变量 7）。

> [!NOTE]
> **已知边界（stdlib 行为，非解析器缺陷）。** 使用默认 HTTP client 时，若响应的 `Content-Encoding` 以两行头到达且首行值恰为 `gzip`，Go 的 `net/http` transport 会在管线看到它之前就解压，因为 transport 用 `Header.Get`（只看首个值）而非全部值判断。当 body 并非合法 gzip 时，观测结果是 200 + 空 body，且**没有**任何上游字节释放给客户端。这是 `net/http` 的行为，不是解析器缺陷，也不会造成未检视透传：管线自己的「读全部值」分类器不受影响，且由 `TestClassifyContentEncodingMultiValued` 锁定，transport 的提前解压不会释放任何管线本会原样转发的字节。

## 🧯 失败策略按路径分级

失败策略取决于 body 的传输方向，因为只有出站（请求）方向会把解析失败变成对上游的泄露。

- **请求路径：声明为 JSON 时 fail-closed。** 请求体在转发前先做叶位遍历。若遍历失败且该请求声明为 JSON（`Content-Type` 为 `application/json*`；或缺失 `Content-Type` 但出现 JSON 征兆，即首个非空白字节是 `{`、`[` 或 `"`），网关即 fail-closed：返回 **HTTP 400**，且**上游零字节**。该裁决在 HTTP 层（`pkg/gateway` 数据面）做出，因为 body 改写接缝读不到请求头；底层哨兵是 `proxy.ErrUnwalkableBody`。显式非 JSON 的请求（`text/plain` 等）保持既有直通：body 逐字节转发，不运行任何遍历。由 `TestPipelineMalformedInputPassthrough`（接缝返回哨兵且 body 逐字节不变）与 `pkg/gateway` 数据面测试锁定。
- **响应与 SSE 路径：刻意不 fail-closed。** walker 无法解析的响应体仍逐字节转发，回填也照旧运行。这两个方向都是回客户端方向（入站）：无法解析的响应不可能把任何东西外泄到上游；fail-closed 只会打断合法的纯文本错误体与 `data: [DONE]`/ping 流。跳过不再是静默的：`Pipeline.ResponseWalkFailures()` 为其计数，每次跳过发出一条仅元数据的 `RedactionEvent`（缓冲路径为 `response_walk_failed`，SSE desync 守卫为 `sse_walk_failed`；direction `response`、phase `response_content`），不含任何正文、对象键或 JSON 路径。

这一不对称是刻意为之：会在可能泄露处 fail-closed，在不可能泄露处保持透明且可观测。

## 📌 具名路由例外清单

网关**拒绝猜测**未知请求的上游：未知路径是明确的类型化错误（`ErrUnknownUpstream`），绝不静默错路由。只有一份**具名例外清单**，且一条路径能进清单的唯一理由是：该调用不携带用户数据，且所有提供商的服务方式完全一致：

| 路径 | 默认上游 | 为何安全 |
|---|---|---|
| `GET /v1/models` | OpenAI | 模型发现。请求不携带提示词或载荷，两家提供商暴露的形状相同；指定任一家都不会泄露或错路由用户内容。 |

配置的 `upstreams:` 覆盖仍然优先于该例外（也优先于内置路由表）。其他任何路径——包括形近的 `/v1/model`、`/v1/models/foo` 或 `/v1/modelsX`——依旧是类型化错误，所以“绝不猜测”规则不变。该清单是封闭的，由 `pkg/proxy` 的 `TestResolveModels` 锁定；新增条目是经过文档记录的刻意决定，不是默认行为。

## 🔍 检测器取舍

- **假阳性（过度脱敏）** 伤体验：模型收到占位符，代码或回答质量下降。
- **假阴性（脱敏不足）** 伤承诺：敏感内容离开本机。

V1 用**确定性、高精度优先的检测器**（已知密钥前缀、高熵、JWT、私钥头、Luhn 卡号校验和、电子邮件地址），再配白名单（`tokenhush.yaml` 的静态键，加上只经控制面变更且逐次审计的运行期 store）和一键放行。本项目**不**声称“永不泄露”。诚实的说法是**“高置信密钥拦截”**。

## 🔎 检测范围：值域与对象键

在一个被遍历的 JSON 文档中，检测运行在两个相互独立的位置：

- **字符串值**（原有范围）。每个字符串叶都会被检视，命中即以占位符替换。
- **对象键**（后续加入）。JSON 对象的成员名作为**独立的键位机制**被检视：即 `protocol.WalkKeys`——一个独立 API，返回键位 span 与 JSON Pointer 路径。键位参与判定的检测器集恰为 **`prefix`（api_key）、`high_entropy`、`jwt`、`private_key`**。`luhn`（credit_card）与 `email` 在键位被**刻意排除**，以免对 16 位数字键与邮箱形态键误报。凭据形态的键会使**请求 fail-closed**（整请求被阻断，上游零字节），且键**永不被重写**；键位上有检测器失败关闭时同样阻断。

对象键**不是** `Leaf`，绝不进入 `pkg/extension` 定义的文档模型。键位扫描是一个独立、纯新增的 API（`protocol.WalkKeys`，新增而不改动 `Walk` 或 `Leaf`），因此 `architecture.zh-CN.md` 中记录的“叶子=值”契约**保持不变**。

**决策留痕。** 选择新增独立的 `WalkKeys` API，而不是把键位塞进 `protocol.Walk` 的 `Leaf` 契约，是一项刻意的决定（加固计划中的 O3 决策）。否决“扩展 `Leaf`”的理由是：那会改动 `pkg/extension` 的 V1 稳定公开面，并破坏“叶子=值”契约（`architecture.zh-CN.md`）。键位机制由 `pkg/protocol` 测试与 `pkg/proxy` 的键位测试锁定；外围加固工作所依赖的跨仓装配契约冻结在私有 Pro 仓库的 ADR-0012 增补 A2。

## ⚠️ 已知限制

如实列出，以免此处任何一句被读成已闭合的保证。全文的诚实口径是**高置信拦截**。

- **`high_entropy` 对纯 hex 的排除同样作用于键域。** 该检测器本就不标记只由 hex 字符构成的运行（避免对哈希与 ID 误报）。同一排除也作用于对象键位，故**纯 hex** 的密钥置于对象键**不会被拦**。这与值域是同一排除、并非新增缺口；由 `TestPipelinePureHexKeysNotBlocked` 钉死。
- **编码形态的覆盖尚未确立（占位）。** 在离开本机之前被某层编码（hex、base64、gzip 等）变换过的密钥是一片已知残余风险区；而“已知**不**被覆盖的编码类别”这份显式清单尚未发布。
  <!-- W1.5 占位：由编码归一化工作（W2.2）在此填写“已知不覆盖的编码类别”清单；在此之前不得写入覆盖保证。 -->
- **响应/SSE 的可观测性是仅元数据。** 响应路径的 walk 失败计数与事件按设计只携带元数据（direction、phase、action；无正文、无键、无路径），且无法解析的响应体**刻意不阻断**（见“失败策略按路径分级”）。

## 🔑 密钥处理

- **V1：透传。** 工具自带提供商密钥；网关只转发，**不存储**。
- 多账号/路由（Pro）需要存密钥时，走跨平台密钥环抽象（macOS Keychain / Windows Credential Manager / Linux Secret Service 加一条回退链，该设计记录在私有 Pro 仓库），再加网关 token + Origin 校验来防 CSRF。
- **诚实降级**：没有 OS 密钥环时，退回受限文件（`0600`），并通过密钥存储的 `Backend()` **显式**报告，绝不静默。

## 📦 发行与供应链

- **依赖审计**：核心只允许宽松许可证（MIT/Apache/BSD）；**禁止 GPL/AGPL**。
- **发行**：签名构建 + 校验和 + SBOM；CI 扫描依赖与密钥。
- **更新**：Homebrew / Scoop / 签名的 `install.sh` 与 `install.ps1` 分发。

## 🔁 网络外发

面向厂商的请求仅有**更新检查**与**规则同步**两个可关、按命令触发的类别。二者都不会自动运行，也不由网关数据面执行。每个类别的状态如实标注：只有真正生效后才标 `active`。

| 类别 | 命令 | 状态 |
|---|---|---|
| 规则同步 | `tokenhush rules sync` | **已生效** —— 从 `updates.tokenhush.com` 获取已签名的规则清单与规则包 |
| 更新检查 | `tokenhush update`（self-managed 安装） | **已生效** —— 运行 `tokenhush update`（或 `--check`）时经 HTTPS 获取根签名 key-list 与已签名更新清单 |

两者都披露服务端可观察到的信息（来源 IP、时间戳与 Cloudflare 访问日志）及其保留期，且均可关闭：设置 `TOKENHUSH_NO_RULE_SYNC=1` 可让 `rules sync` 拒绝同步且不发起任何网络请求；设置 `TOKENHUSH_NO_UPDATE_CHECK=1` 可让 `tokenhush update` 在发起任何网络请求前直接返回。披露由机器可读的 [`egress.yaml`](../egress.yaml) 生成，由 `tokenhush privacy` 打印，并发布在 [generated/network-egress.md](generated/network-egress.md)。该范围由 `pkg/proxy` 的 `TestNoTelemetry` 锁定，证明数据面即使面对形似厂商端点的路径也绝不外发到厂商主机。

## 🛡️ 漏洞披露

> [!CAUTION]
> **别为漏洞开公开 issue。** 按 [SECURITY.md](../SECURITY.md)（英文）的披露流程走（支持版本、私密报告与响应时间）。详情等修复发布后再公开。
