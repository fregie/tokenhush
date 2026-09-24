# 配置

**中文** | [English](configuration.md)

Tokenhush 只读取一个配置文件：`tokenhush.yaml`。schema 严格且封闭：文件缺失表示使用内置默认值，未知键是错误而不是警告。安全相关设置（检测器开关、监听地址）里的拼写错误会显式失败，而不是静默回退到宽松默认值。

多数用户根本不用碰这个文件。你只在两种情况下需要它：把请求路由到 OpenAI 或 Anthropic 之外的厂商（中转站、自建端点、网关），以及调整某个检测器开关或某个大小上限。其中路由部分值得仔细阅读，可直接跳到[将请求路由到上游（upstreams）](#将请求路由到上游upstreams)。

## 配置文件的位置

Tokenhush 把配置目录与数据目录分开：

| 平台 | 配置目录 | 数据目录 |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/config/` | `~/Library/Application Support/tokenhush/Data/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LocalAppData%\tokenhush\` |

把 `tokenhush.yaml` 放进配置目录。`TOKENHUSH_HOME` 会把两个目录移到一个根：配置在 `<TOKENHUSH_HOME>/config`，数据在 `<TOKENHUSH_HOME>/data`（空值视为未设置）。

想改读指定的文件，就给 `tokenhush run` 或 `tokenhush env` 传 `--config PATH`。文件是可选的：不存在时使用下面的默认值。

## 全部配置项

schema 定义的每一个键，均以默认值展示：

```yaml
listen:            {host: 127.0.0.1, port: 8787}
log:               {level: info}
detectors:         {prefix: true, email: true, luhn: true, jwt: true, pem: true, entropy: false}
allowlist:         ["literal"]
upstreams:         [{match: "/v1/chat/completions", target: "https://api.openai.com"}]
scan_budget_bytes: 33554432
detector_timeout:  30s
max_body_bytes:    67108864
response_buffer_bytes: 33554432
response_timeout:  5m
```

这就是全部表面。任何其它顶层键都是 schema 错误，而不是警告。

## 配置参考

| 键 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `listen.host` | 字符串 | `127.0.0.1` | 只能是 `127.0.0.1`、`::1` 或 `localhost`。`0.0.0.0` 会被拒绝。 |
| `listen.port` | 整数 | `8787` | 1..65535。 |
| `log.level` | 字符串 | `info` | `debug`、`info`、`warn`、`error` 之一。 |
| `detectors.prefix` | 布尔值 | `true` | 已知 key 形态：`sk-`、`AKIA`、`ghp_`、`glpat-`、`xox*`、`AIza`、`npm_`。 |
| `detectors.email` | 布尔值 | `true` | 邮箱地址；匹配要求域名在标签边界处结束于已知公共后缀。 |
| `detectors.luhn` | 布尔值 | `true` | 卡号，经 Luhn 校验。 |
| `detectors.jwt` | 布尔值 | `true` | JSON Web Token。 |
| `detectors.pem` | 布尔值 | `true` | PEM 私钥头。 |
| `detectors.entropy` | 布尔值 | `false` | 高熵字符串。默认关闭，需显式开启：它在真实 agent 流量上的误报（长工具名、会话 id）曾破坏 function calling。 |
| `allowlist` | 字符串列表 | 空 | 永不脱敏的字面量。 |
| `upstreams` | `{match, target}` 列表 | 空 | 指向你自己源站的路径前缀路由。见[将请求路由到上游（upstreams）](#将请求路由到上游upstreams)。 |
| `scan_budget_bytes` | 整数 | `33554432`（32 MiB） | 每叶、每检测器扫描预算：原始检测器对单个叶最多检查这么多字节。 |
| `detector_timeout` | 时长 | `30s` | 检测兜底。 |
| `max_body_bytes` | 整数 | `67108864`（64 MiB） | 整个请求 body 的内存护栏。超过它的 body 在共享读取 seam 处、任何遍历之前以 403 `body_too_large` 拒绝，且绝不截断、绝不部分转发。 |
| `response_buffer_bytes` | 整数 | `33554432`（32 MiB） | 单个缓冲响应的总量上限。超过上限的响应在提交任何字节之前返回 502。 |
| `response_timeout` | 时长 | `5m` | 读取单个响应的整体上限。超过 deadline 的响应在提交任何字节之前返回 504。若上限与 deadline 同时触发，上限优先。 |

检测器键名恰好是 `prefix`、`email`、`luhn`、`jwt`、`pem` 和 `entropy`。它们不是 `prefixes`，不是 `high_entropy`，也不是 `private_keys`：未知检测器名是 schema 错误。每个数值键（`scan_budget_bytes`、`detector_timeout`、`max_body_bytes`、`response_buffer_bytes`、`response_timeout`）都必须是正数。

`email` 检测器精确匹配：只有当地址域名在标签边界上以已知公共后缀（`.com`、`.co.uk`）结尾时才算命中，因此子域名同样计入，而 `evilcorp.com` 这类形似地址只有在 `replace` 模式下把更窄的 `.corp.com` 配置为后缀时才会被拒绝（追加模式下的 `.corp.com` 仍带有内置的 `.com`，因此 `evilcorp.com` 仍会命中）。内置后缀表编译进程序、已冻结、始终生效。

## 将请求路由到上游（upstreams）

如果你使用中转站、自建端点，或 OpenAI / Anthropic 之外的任何厂商，这一节就是必读。没有它，网关按内置表转发，而内置表只认识这两家厂商。

### 路由如何工作

路由按**请求路径**，不是按厂商名，也不是按模型。对每个请求，网关读取入站路径、选出匹配的上游、把请求路径拼接到该上游的 base 上，然后恰好拨号一次。

因为选上游的是路径而不是模型，一个上游可以服务多个模型：模型由请求 body 选择，所以一个在 `/v1` 后面服务多个模型的中转站只需要一条条目。

### 声明一个上游

`upstreams` 是 `{match, target}` 条目的**列表**，不是映射。每条条目恰好两个键：

- `match` —— 该条目路由的入站请求路径前缀。
- `target` —— 请求被转发到的上游 base。

两个键都必须设置；`match` 或 `target` 为空会导致配置加载失败。`target` 必须是带 host 的绝对 `http` 或 `https` URL，且**不带** userinfo、query 或 fragment；格式非法的 `target` 在成为可用路由之前就会被拒绝。

最小可用的条目，把所有 OpenAI 风格路径路由到一个中转站：

```yaml
upstreams:
  - match: /v1
    target: https://your-relay.example.com
```

### 请求路径如何拼接

网关把入站请求路径（及其 query 字符串）拼接到 `target` 上，两段之间只用一个斜杠连接：

- `match: /v1` + `target: https://relay.example.com` + 请求 `/v1/chat/completions` → `https://relay.example.com/v1/chat/completions`。
- `target` 上的路径前缀会保留：`target: https://host/openai` + 请求 `/v1/chat/completions` → `https://host/openai/v1/chat/completions`。

这就是为什么 `target` 是厂商**源站加上 `/v1` 之前的任何前缀**，且**不带 `/v1`**、不带结尾斜杠。你的工具已经会发 `/v1/...`，网关把它接在后面。如果真实端点是 `https://host/openai/v1/chat/completions`，就把 `target` 设为 `https://host/openai`。

### 匹配规则与优先级

配置的 `match` 在以下情况路由一个请求：

- 路径与 match 完全相等，或
- 路径在 match 之下，且落在**路径段边界**上 —— `/v1/chat` 匹配 `/v1/chat/completions`，但不匹配 `/v1/chatX`，或
- match 是 `/`，即显式 catch-all。

在所有匹配的配置条目中，**最长的 `match` 胜出**；若两条条目的 match 长度相同，则字典序较小的胜出，因此选择是确定的。配置条目始终优先于内置表。

路径按大小写敏感匹配，其余一概不做规范化：大小写、`.` 与 `..`、百分号转义永不折叠。像 `/v1/model`、`/v1/models/foo`、`/v1/chat/completionsX` 这样的近似路径会得到带类型的 `no upstream for request path` 错误，绝不静默错发到相邻厂商。

### 内置路由表

没有配置条目匹配时，应用内置表。内置条目是**精确路径**，而配置的 `match` 是前缀。完整表如下：

| 请求路径 | 上游 |
|---|---|
| `/v1/audio/speech` | OpenAI |
| `/v1/audio/transcriptions` | OpenAI |
| `/v1/audio/translations` | OpenAI |
| `/v1/chat/completions` | OpenAI |
| `/v1/completions` | OpenAI |
| `/v1/embeddings` | OpenAI |
| `/v1/images/edits` | OpenAI |
| `/v1/images/generations` | OpenAI |
| `/v1/moderations` | OpenAI |
| `/v1/responses` | OpenAI |
| `/v1/messages` | Anthropic |
| `/v1/messages/batches` | Anthropic |
| `/v1/messages/count_tokens` | Anthropic |
| `GET /v1/models` | 由网关自身应答 |
| 其它任意路径 | 显式错误 |

OpenAI 是 `https://api.openai.com`，Anthropic 是 `https://api.anthropic.com`。

`GET /v1/models` 是唯一指名的例外：两家厂商以相同语义提供它，所以网关自己应答模型发现，不拨号任何上游。其它任何未知路径都是显式错误，绝不静默错发。

### 完整示例

**直连 OpenAI 或 Anthropic。** 无需 `upstreams`，内置表生效。

**一个把 `/v1` 下所有内容都前接的中转站。**

```yaml
upstreams:
  - match: /v1
    target: https://relay.example.com
```

**只把 chat 指向自建的 OpenAI 兼容端点**，Anthropic 内置项保持不变：

```yaml
upstreams:
  - match: /v1/chat/completions
    target: http://127.0.0.1:8000
```

**分流。** 把一类路径发给本地服务，其余 `/v1` 下的路径发给中转站。最长的 match 胜出，所以更具体的条目拿走它的路径，`/v1` 接住剩下的：

```yaml
upstreams:
  - match: /v1/chat/completions
    target: http://127.0.0.1:8000
  - match: /v1
    target: https://relay.example.com
```

**base 位于路径前缀之下的端点。** 对于 `https://host/openai/v1/chat/completions`，把 target 设为 `/v1` 之前的部分：

```yaml
upstreams:
  - match: /v1
    target: https://host/openai
```

### 路由排错

- **请求到了错误的厂商。** 没有 `upstreams` 时，未匹配路径走内置表。把中转站指向网关之前，先设置 `upstreams`。
- **出现重复的 `/v1`（`/v1/v1/...`）。** `target` 不能包含 `/v1`；工具已经会发它。
- **`upstreams` 看起来没生效。** 它必须是列表，不是 YAML 映射；映射会因封闭 schema 失败。
- **`match` 或 `target` 为空。** 加载时即拒绝。
- **`no upstream for request path`。** 该路径既不匹配任何配置条目，也不匹配内置表。加一条条目，或检查是否有拼写错误、多出的路径段（内置路径是精确匹配，不是前缀）。
- **端口不匹配。** 如果你用 `--port` 或 `listen.port` 改了网关端口，让工具指向同一个端口。

### 认证头

网关逐字节转发认证头，从不解析它们；只有请求 **body** 会被转换。厂商的 API key 留在工具自己的配置里。

## 请求与响应限制

每个上游响应都会**整段**缓冲，之后才会有任何字节抵达客户端，`text/event-stream` 同样如此：不存在 token 级流式输出。缓冲响应上的响应作用域 `Block`（含 SSE）在提交任何字节之前返回 502，回填则在唯一一次提交之前把内容层拆分的占位符精确还原一次。`response_buffer_bytes` 与 `response_timeout` 分别为缓冲 body 与整段读取设界；超过上限是 502，超过 deadline 是 504，二者都在提交之前决定。

在请求侧，`max_body_bytes` 在任何遍历或上游拨号之前为整个 body 设护栏，`scan_budget_bytes` 与 `detector_timeout` 为每次检测设界。

## 另见

- [tool-setup.zh-CN.md](tool-setup.zh-CN.md)：把 14 种工具分别指向网关。
- [verify.zh-CN.md](verify.zh-CN.md)：本地 echo 上游往返检查。
- [security.zh-CN.md](security.zh-CN.md)：回环绑定背后的安全模型。
