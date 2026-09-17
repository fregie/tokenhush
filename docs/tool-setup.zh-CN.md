# 各工具配置教程

[English](tool-setup.md) | **中文**

> 状态：V1（2026-09）。本文为 `tokenhush env` 支持的全部工具提供逐步配置教程，并附路由可达性矩阵与 `tokenhush.yaml` 参考。

Tokenhush 是一个本地基础 URL 网关：把 AI 编程工具的 API 基础 URL 指向 `http://127.0.0.1:8787`，它就会在转发上游之前对敏感内容脱敏。本文针对每种支持的工具说明：配置写在哪里、填什么值、如何在不覆盖现有配置的前提下合并、如何选择 provider/模型，以及如何验证与还原。

只想复制一行命令的话，`tokenhush env <tool>` 会打印出来；本文就是那条片段的详细展开版。

## 🎯 开始之前

1. **启动网关。** `tokenhush run` 留在前台运行，并在 `tokenhush: gateway listening on http://127.0.0.1:<port>` 之前打印生效的上游路由表和 `tokenhush env <tool>` 接入提示。默认端口 `8787`。安装渠道、服务包装与目录见 [deployment.zh-CN.md](deployment.zh-CN.md)。
2. **确认网关在运行。** `tokenhush status` 会打印 `requests` 与 `redactions` 计数。工具发出请求后，这两个计数可用于确认流量确实到达网关。`tokenhush status --json` 会以 JSON 输出同样字段。
3. **打印片段。** `tokenhush env <tool>` 会按当前端口渲染。用 `--port N` 对齐非默认网关，或用 `--config PATH` 从别处读取 `tokenhush.yaml`。
4. **匹配你的 shell。** macOS 与 Linux 上 `tokenhush env` 打印 POSIX `export` 行；Windows PowerShell 上会打印当前会话的 `$env:NAME = "..."` 以及用于持久化的 `setx` 行。有疑问时直接运行 `tokenhush env` 并复制其原样输出。

### 两种基础 URL 形态

粘贴哪个值取决于工具说的协议，而非工具名字：

| 形态 | 取值 | 客户端 |
|---|---|---|
| 裸 origin | `http://127.0.0.1:8787` | Anthropic 协议客户端（`/v1/messages`） |
| `/v1` | `http://127.0.0.1:8787/v1` | OpenAI 兼容客户端（`/v1/chat/completions`、`/v1/responses`） |

网关按协议路由未匹配路径：`/v1/messages` 走 Anthropic，`/v1/chat/completions` 与 `/v1/responses` 走 OpenAI。`GET /v1/models` 是唯一的具名例外，默认走 OpenAI。其他任何未知路径都会明确报错，不会静默错路由。见[路由可达性矩阵](#路由可达性矩阵) 与 [security.zh-CN.md](security.zh-CN.md#具名路由例外清单)。

> [!NOTE]
> **密钥、凭证与 API key。** Tokenhush 监听环回地址，不会改动工具的凭据；你仍需为上游模型提供有效 key。工具要求填 API key 时，请填真实的上游 key（若你的网关接受占位符，也可填占位符）。切勿把 key 提交进纳入版本管理的配置文件。

### 各工具速查

| 工具 | 片段命令 | 基础 URL | 默认上游 | 配置位置 |
|---|---|---|---|---|
| Claude Code CLI | `tokenhush env claude` | 裸 origin | Anthropic | Shell 环境变量，或 `~/.claude/settings.json` |
| Codex CLI | `tokenhush env codex` | `/v1` | OpenAI | `~/.codex/config.toml` |
| Aider | `tokenhush env aider` | `/v1` 与裸 origin | OpenAI / Anthropic | Shell 环境变量、`.env` 或 `.aider.conf.yml` |
| Cline | `tokenhush env cline` | `/v1` | OpenAI | VS Code 扩展设置 |
| Roo Code | `tokenhush env roo` | `/v1` | OpenAI | VS Code 扩展设置 |
| opencode | `tokenhush env opencode` | `/v1` | OpenAI | `opencode.json` |
| Qwen Code | `tokenhush env qwen` | `/v1` 与裸 origin | OpenAI / Anthropic | Shell 环境变量 |
| Charm Crush | `tokenhush env crush` | `/v1` | OpenAI | `crush.json` |
| Zed | `tokenhush env zed` | `/v1` | OpenAI | `settings.json` |
| Continue.dev | `tokenhush env continue` | `/v1` | OpenAI | `~/.continue/config.yaml` |
| Open WebUI | `tokenhush env openwebui` | `/v1` | OpenAI | Shell 环境变量，或 Admin → Connections |
| Goose | `tokenhush env goose` | 裸 host + `v1` 路径 | OpenAI | Shell 环境变量 |
| OpenHands | `tokenhush env openhands` | `/v1` | OpenAI | Shell 环境变量，或 `[llm].base_url` |
| Kilo Code | `tokenhush env kilo` | `/v1` | OpenAI / Anthropic | VS Code 扩展设置 |

**默认上游**是指没有配置 `upstreams:` 时该工具到达的 provider。如果你的 provider 不是它，请读下一节。

<a id="配置请求路由upstreams"></a>
## ⚙️ 配置请求路由（`upstreams:`）

把工具指向网关只是一半。网关随后要决定每条请求去**哪个 provider**，而它只看**请求路径**，看不到工具的名字。本节就是完整的路由约定。

### 网关如何选择上游

首个命中即用：

1. `upstreams:` 的**精确路径**键（例如 `/v1/chat/completions`）；
2. `upstreams:` 的**精确主机**键（大小写不敏感；带端口的键先于不带端口的尝试）；
3. `upstreams:` 的**最长路径前缀**键（按路径段边界匹配，`/v1` 命中 `/v1/chat/completions` 但不命中 `/v1beta/x`）；
4. **内置表**：`/v1/messages` 与 `/v1/messages/count_tokens` → Anthropic；`/v1/chat/completions` 与 `/v1/responses` → OpenAI；
5. **具名例外**：`GET /v1/models` → OpenAI；
6. 以上都不命中 → 明确报错（`ErrUnknownUpstream`），不猜、不静默错发。

没有 `upstreams:` 块时，OpenAI 兼容工具去 `https://api.openai.com`，Anthropic 工具去 `https://api.anthropic.com`。如果你的 provider 就是它，无需再配。

### `upstreams:` 块

`upstreams:` 把请求的**主机**或**路径前缀**映射到网关要转发到的 base URL。请求自身的路径会拼接到该 base 之后。

```yaml
upstreams:
  # /v1 下的任何请求路径都去这个 provider
  /v1: https://api.deepseek.com
```

只把某一个端点转到别的 provider：

```yaml
upstreams:
  /v1/chat/completions: https://api.deepseek.com
  /v1/models: https://api.deepseek.com
```

加载器在启动时校验该块；非法值会让启动失败，绝不会成为一条生效路由：

- **键**是主机（`api.example.com`、`api.example.com:443`）或以 `/` 开头的路径。键不能含 `://`。
- **值**必须是带主机的绝对 `http(s)` URL，且不能含 userinfo、query 或 fragment。
- 省略该块，或写 `upstreams: {}`，都表示“只用内置路由”。
- `tokenhush.yaml` 里任何未知键都会被拒绝，拼错不会悄悄关掉保护。

**路径拼接规则（精确）。** 网关转发到 `base + 请求路径`；它只加前缀，绝不改写路径。所以 base 是 provider 的 origin（外加位于 `/v1` **之前**的前缀），且不带尾斜杠。**不要把 `/v1` 写进 base**——工具发出的路径已含 `/v1/chat/completions`：

| provider 端点 | 应填的 base |
|---|---|
| `https://host/v1/chat/completions` | `https://host` |
| `https://host/api/v1/chat/completions` | `https://host/api` |

**主机键 vs 路径键。** 工具拨的是 `127.0.0.1`，因此请求 Host 头是 `127.0.0.1:8787`，`api.example.com` 这类主机键永远匹配不上。要路由环回流量，请用**路径**键。主机键只在网关前面有东西保留原始 authority 时才用得上。

**凭据。** 工具的鉴权头（`Authorization`、`x-api-key` 等）会逐字节复制到上游。请把 provider 的真实 API key 填在工具的 provider 设置里；网关既不添加也不替换它。脱敏只作用于请求**体**，所以你发给 provider 的 key 就是 provider 看到的 key。

### 可照抄的例子

provider 就是 OpenAI —— 无需添加：

```yaml
# /v1/chat/completions 与 /v1/responses 去 https://api.openai.com
```

OpenAI 兼容 provider（DeepSeek、OpenRouter、Together、本地 vLLM/Ollama 等）：

```yaml
upstreams:
  /v1: https://api.deepseek.com
```

按端点拆分：Responses 留在 OpenAI，chat completions 发给兼容厂商（精确键优先于内置表）：

```yaml
upstreams:
  /v1/chat/completions: https://api.deepseek.com
  /v1/models: https://api.deepseek.com
  # /v1/responses 继续走内置 OpenAI 路由
```

给 Claude Code 用的 Anthropic 兼容厂商：

```yaml
upstreams:
  /v1/messages: https://api.example-anthropic-compatible.com
  /v1/messages/count_tokens: https://api.example-anthropic-compatible.com
```

完整文件示例，供参考：

```yaml
listen:
  host: 127.0.0.1
  port: 8787
upstreams:
  /v1: https://api.deepseek.com
```

### 路由可达性矩阵

`tokenhush env` 接入的每个工具，都必须发出网关能路由的请求路径。下表列出各集成实际使用的路径，`internal/cli` 的 `TestToolRouteMatrix` 断言每条路径都能经 `pkg/proxy` 解析：

| 工具 | 请求路径 | 上游 |
|---|---|---|
| Claude Code | `/v1/messages` | Anthropic |
| Codex CLI | `/v1/responses` | OpenAI |
| Aider | `/v1/chat/completions` | OpenAI |
| Cline / Roo Code | `/v1/chat/completions` | OpenAI |
| opencode | `/v1/chat/completions`、`/v1/models` | OpenAI |
| Qwen Code | `/v1/chat/completions`、`/v1/messages` | OpenAI / Anthropic |
| Charm Crush | `/v1/chat/completions` | OpenAI |
| Zed | `/v1/chat/completions`、`/v1/models` | OpenAI |
| Continue.dev | `/v1/chat/completions`、`/v1/models` | OpenAI |
| Open WebUI | `/v1/models`、`/v1/chat/completions` | OpenAI |
| Goose | `/v1/chat/completions` | OpenAI |
| OpenHands | `/v1/chat/completions` | OpenAI |
| Kilo Code | `/v1/chat/completions`、`/v1/messages` | OpenAI / Anthropic |

`/v1/models` 能解析，只因为那条具名例外（见 [security.zh-CN.md](security.zh-CN.md#具名路由例外清单)）。若某工具需要表外协议——例如 Gemini CLI 用的 Google GenAI `generateContent`——会标注为**未验证（unverified）**，在网关支持前不予接入。当前没有未验证的工具。

### 文件位置与重载

| 平台 | 配置目录 |
|---|---|
| macOS | `~/Library/Application Support/tokenhush/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` |

文件名为 `tokenhush.yaml`。用 `tokenhush run --config PATH` 覆盖路径，或用 `TOKENHUSH_HOME` 同时搬走配置与数据目录。它在**启动时**读取，改完请重启网关。唯一例外是运行期白名单：它是独立 store，经控制面变更并立即生效，无需重启（见 [`tokenhush.yaml` 参考](#tokenhushyaml-参考)）。`tokenhush doctor` 会校验配置与端口。`listen`、`detectors`、`allowlist`、`self_protection`、`log` 见 [`tokenhush.yaml` 参考](#tokenhushyaml-参考)。

### 限制

- 一条请求路径只解析到**一个**上游。只用单一路径的工具，一次只能到达一个 provider。
- 路径不能改写，只能加前缀。需要非标准路径的 provider（例如 Azure OpenAI 的 `/openai/deployments/<deployment>/chat/completions?api-version=…`）无法按原样经 `upstreams:` 接入。
- `GET /v1/models` 是唯一在没有数据承载信号下被指派的路由；`upstreams:` 覆盖仍优先于它。

**验证：** 重启后，用工具发一次请求，再跑 `tokenhush status`。`requests` 计数应增长；上游返回 4xx/5xx 通常意味着 base URL 拼接或 provider key 有问题。

<a id="tokenhushyaml-参考"></a>
## ⚙️ `tokenhush.yaml` 参考

配置文件在平台配置目录（`pkg/platform.ConfigDir()`）：macOS `~/Library/Application Support/tokenhush/`，Linux `${XDG_CONFIG_HOME:-~/.config}/tokenhush/`，Windows `%AppData%\tokenhush\`。用 `--config PATH` 覆盖，或用 `TOKENHUSH_HOME` 同时搬走配置和数据目录。文件不存在即用默认值。**未知键会被拒绝**，拼错不会悄悄关掉保护：`listen` 写成 `listenn`，加载直接失败。

完整默认值：

<!-- check-docs:config:start -->
```yaml
listen:
  host: 127.0.0.1      # 仅允许 127.0.0.1 / ::1 / localhost；0.0.0.0 会被拒绝
  port: 8787           # 1..65535
detectors:
  prefixes: true       # 已知密钥前缀（sk-、AKIA、ghp_、...）
  high_entropy: false  # 默认关闭；显式置 true 才启用（见下方精度说明）
  jwt: true            # JWT
  private_keys: true   # PEM 私钥头
  luhn: true           # 卡号（Luhn）
  email: true          # 电子邮件地址
  scan_budget_bytes: 33554432  # 确定性扫描预算（32 MiB）；超过即拒绝，绝不部分扫描
  timeout: 30s                 # 单次检测器调用的墙钟兜底；大默认值，正常运行永不触达
allowlist: []          # 在列期间永不脱敏的字面量；运行时白名单与其并集生效
self_protection:       # 变更通道自保护；默认开启
  enabled: true        # false 为显式退出
  modes: [cli-command, control-port, file-write]
log:
  level: info          # debug | info | warn | error
upstreams:             # 主机或路径前缀 -> 上游基础 URL
  api.example.com: https://api.example.com
```
<!-- check-docs:config:end -->

要点：

- `listen.host` 只接受环回地址。网关**绝不**绑定 `0.0.0.0` 或空主机。它始终绑 `127.0.0.1`；主机有 IPv6 环回时同时绑 `[::1]`，没有时只服务 `127.0.0.1` 并打印提示。
- 默认开启五个确定性、高精度检测器：密钥前缀、JWT、PEM 私钥头、Luhn 卡号、电子邮件。`high_entropy` 已接线但**默认关闭**（用 `high_entropy: true` 显式开启）：它是更弱的信号，其结构化豁免在真实 agent 流量上仍产生误报（长工具名与会话 id 被当成密钥脱敏，破坏了函数调用），代价超过收益。命中生成稳定占位符，如 `__PII_email_9f2c8a4b6d1e__`，上游拿不到原始值。
- `prefixes` 对应检测器 id `prefix`，`private_keys` 对应 `private_key`（见 `pkg/config` 注释）。
- `scan_budget_bytes`（默认 32 MiB）是**确定性**扫描预算：判定只取决于请求/响应体大小，与 CPU 速度或负载无关。体量不超过预算则照常检测（受墙钟兜底约束）；超过则任何检测器运行前即**拒绝**——绝不静默放行，也绝不部分扫描。`timeout`（默认 30s）是宽松的墙钟兜底，只为阻断病态检测器而存在，正常运行永不触达。完整失败策略见 [security.zh-CN.md](security.zh-CN.md#失败策略按路径分级)。
- `allowlist` 放**在列期间**不脱敏的字面量。运行时白名单出现后静态条目仍然生效：启动时它们作为种子导入运行时 store，且本键继续被读取——最终生效集合是两者的**并集**，而不是替换。每条必须非空、不含控制字符、长度不超过 4096 字节。运行期白名单持久化在 `<DataDir>/allowlist.json`（`0600`、带 `schema_version`、**非** session file），且只经环回控制面变更：`tokenhush allowlist list|add|remove`、`GET|POST|DELETE /allowlist`，或 Pro Web UI。变更立即生效、无需重启，且每次变更写一条仅元数据审计行。
- `self_protection` 保护变更通道（`tokenhush allowlist` CLI、环回控制端口、直写白名单文件），默认开启且三个模式全开。`enabled: true` 时 `modes:` 不得为空列表（省略该键则保留三个默认模式）；`enabled: false` 是显式退出。排除集本身刻意不可配置：它在运行时由 control token 值与白名单文件内容派生。该守护是**高置信拦截、best-effort**，而非闭合；已知不覆盖的通道列在[变更通道自保护](security.zh-CN.md#变更通道自保护)一节。
- 核心配置里没有 `audit:` 键：仍带该键的配置会加载失败。审计块位于私有 Pro 层；公开核心只保留仅元数据的审计接缝。
- `upstreams:` 把主机或路径前缀映射到你的 OpenAI 兼容上游。没配到的请求走内置路由：`/v1/messages` 去 Anthropic；`/v1/chat/completions` 和 `/v1/responses` 去 OpenAI。`GET /v1/models` 是唯一的**具名例外**：模型发现调用不携带用户数据，默认去 OpenAI，`upstreams:` 覆盖仍可改走别处。其他任何未知路径都明确报错（`ErrUnknownUpstream`），不会静默错路由；见 [security.zh-CN.md](security.zh-CN.md#具名路由例外清单)。

## 🧩 Claude Code CLI

**集成方式：** `ANTHROPIC_BASE_URL`（裸 origin）。

最快的方式是每个终端临时设置，无需改文件：

```bash
eval "$(tokenhush env claude)"   # 导出 ANTHROPIC_BASE_URL
claude
```

要持久化，就在用户设置文件里加一个 `env` 块：

- macOS / Linux：`~/.claude/settings.json`
- Windows：`%USERPROFILE%\.claude\settings.json`

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787"
  }
}
```

合并而非替换：保留所有已有的顶层键，只在 `env` 内新增或修改 `ANTHROPIC_BASE_URL`。该文件是严格 JSON（无注释、无尾逗号），语法错误会导致 Claude Code 忽略它。

- 项目级：同样的 `env` 块也可放在项目的 `.claude/settings.json`（共享）或 `.claude/settings.local.json`（仅本机，通常已被 git 忽略）。用户级 `env` 块最不容易出意外。
- 自定义鉴权头：若网关需要 bearer 风格的头，Claude Code 也读取 `ANTHROPIC_AUTH_TOKEN`。
- 验证：启动 `claude`，运行 `/status`，确认 Anthropic 基础 URL 与凭据来源；再发一次请求，观察 `tokenhush status` 计数。
- 还原：从 `env` 块删除 `ANTHROPIC_BASE_URL`，或 `unset ANTHROPIC_BASE_URL`。
- 官方文档：<https://code.claude.com/docs/en/llm-gateway-connect>。

## 🧩 Codex CLI

**集成方式：** `~/.codex/config.toml` → `model_providers.<id>.base_url`（`/v1`）。

Codex 默认用 Responses API（`/v1/responses`），Tokenhush 支持它。

1. 编辑 `~/.codex/config.toml`（Windows：`%USERPROFILE%\.codex\config.toml`）。
2. 定义 provider 并选中它：

```toml
model_provider = "tokenhush"
model = "<model-id>"

[model_providers.tokenhush]
name = "Tokenhush"
base_url = "http://127.0.0.1:8787/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
```

- `model_provider` 决定 Codex 使用哪个 provider；不设它，Codex 会停在内置 `openai` provider 上，永远不会联系网关。
- `env_key` 指定 Codex 从哪个环境变量读取 API key。启动 `codex` 前先导出它（或写进 shell profile）；它不从 `config.toml` 读取。
- `wire_api = "responses"` 与 Codex 默认一致；Tokenhush 支持它，也支持增量式 SSE 回填。
- 合并而非替换：`model_provider` 与 `model` 是顶层键，应加在第一个 `[table]` 行之前，而不是放进某个表里。

> [!WARNING]
> 经网关的 ChatGPT 订阅登录（非 API 密钥）**不支持**：订阅 token 只对 ChatGPT 服务路径有效，转发到 OpenAI 平台 API 会返回 401（见 [openai/codex#34608](https://github.com/openai/codex/issues/34608)）。请改用 API 密钥模式。

- 验证：启动 `codex`，发一次请求，观察 `tokenhush status`。
- 还原：删除 `[model_providers.tokenhush]` 表与 `model_provider` 键（`model` 可按需保留）。
- 官方文档：<https://developers.openai.com/codex/config-basic>。

## 🧩 Aider

**集成方式：** `OPENAI_API_BASE`（`/v1`）和/或 `ANTHROPIC_API_BASE`（裸 origin）。

Aider 是终端工具，用环境变量最简单：

```bash
export OPENAI_API_BASE=http://127.0.0.1:8787/v1
export ANTHROPIC_API_BASE=http://127.0.0.1:8787
aider --model openai/<model-name>
```

- 模型前缀很关键：OpenAI 兼容端点用 `openai/` 前缀选择；Anthropic 模型用 `anthropic/`。
- 一次性参数：`aider --openai-api-base http://127.0.0.1:8787/v1`。
- 配置文件（持久化）：在 `.aider.conf.yml` 里写 `openai-api-base:`。Aider 依次查找 home 目录、git 仓库根目录、当前目录，后加载者优先。
- Dotenv：key 与设置也可放在 git 根目录的 `.env`，Aider 会自动加载。
- 验证：发一次编辑请求，观察 `tokenhush status`。`aider --list-models <partial>` 可确认模型名被识别。
- 还原：删除对应变量或 YAML 键。
- 官方文档：<https://aider.chat/docs/config/aider_conf.html>。

<a id="cline-roo-code"></a>
## 🧩 Cline / Roo Code

**集成方式：** VS Code 扩展设置里的 OpenAI Compatible 基础 URL（`/v1`）。Roo Code 是 Cline 的 fork，流程相同。

1. 打开扩展的设置面板（Cline / Roo Code 侧栏里的齿轮图标）。
2. 把 **API Provider** 设为 **OpenAI Compatible**。
3. 把 **Base URL** 设为 `http://127.0.0.1:8787/v1`。
4. 填 API key（该字段必填；填真实的上游 key，若网关接受占位符也可填占位符）。
5. 按上游期望精确填写模型 ID。

- 不会写入项目文件；设置由扩展自己保存。
- 扩展可能仍会向自己的厂商发送遥测。那部分流量不走这个基础 URL；只有模型请求走。
- 验证：发一次对话请求，观察 `tokenhush status`。
- 还原：把 **API Provider** 切回原值，或清空 Base URL。
- 官方文档：[Cline](https://docs.cline.bot/provider-config/openai-compatible) · [Roo Code](https://docs.roocode.com/providers/openai-compatible)。

## 🧩 opencode

**集成方式：** `opencode.json` → `provider.<id>.options.baseURL`（`/v1`）。

在全局配置（`~/.config/opencode/opencode.json`）或项目级 `opencode.json` 里添加 provider：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "tokenhush": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Tokenhush",
      "options": { "baseURL": "http://127.0.0.1:8787/v1" }
    }
  }
}
```

- 合并而非替换：若 `provider` 已存在，把 `tokenhush` 作为其中一个键加进去，保留现有 provider。
- 选择模型：设置顶层 `"model": "tokenhush/<model-id>"`，或传 `opencode run -m tokenhush/<model-id>`。模型 id 必须与上游暴露的一致。
- 验证：运行 `opencode models` 列出 provider/模型，发一次请求，观察 `tokenhush status`。
- 还原：删除 `tokenhush` provider 条目。
- 官方文档：<https://opencode.ai/docs/providers/>。

## 🧩 Qwen Code

**集成方式：** `OPENAI_BASE_URL`（`/v1`）和/或 `ANTHROPIC_BASE_URL`（裸 origin）。

启动前把 CLI 指向网关。Anthropic 模式用裸 origin；OpenAI 模式用 `/v1`：

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
qwen
```

- 把它们放进 shell profile 或 `~/.qwen/.env`，免得每次重敲。
- 验证：发一次请求，观察 `tokenhush status`。
- 还原：删除变量。
- 官方文档：<https://qwenlm.github.io/qwen-code-docs/en/users/configuration/model-providers/>。

## 🧩 Charm Crush

**集成方式：** `crush.json` → `providers.<id>.base_url`（`/v1`）。

在全局配置（`~/.config/crush/crush.json`；Windows `%LOCALAPPDATA%\crush\crush.json`）或项目 `crush.json` / `.crush.json` 里添加 provider：

```json
{
  "$schema": "https://charm.land/crush.json",
  "providers": {
    "tokenhush": {
      "type": "openai",
      "base_url": "http://127.0.0.1:8787/v1"
    }
  }
}
```

- 合并而非替换：在已有 provider 旁边加上 `tokenhush`。
- provider 注册后，在 Crush 的模型选择器（或 `/models`）里选模型。
- 验证：发一次请求，观察 `tokenhush status`。
- 还原：删除 `tokenhush` provider 条目。
- 官方文档：<https://github.com/charmbracelet/crush>。

## 🧩 Zed

**集成方式：** `settings.json` → `language_models.openai_compatible.<id>.api_url`（`/v1`）。

添加一个 OpenAI 兼容 provider：

```json
{
  "language_models": {
    "openai_compatible": {
      "tokenhush": {
        "api_url": "http://127.0.0.1:8787/v1",
        "available_models": [
          { "name": "<model-id>", "display_name": "<display-name>", "max_tokens": 200000 }
        ]
      }
    }
  }
}
```

- 设置文件：macOS 与 Linux 为 `~/.config/zed/settings.json`，Windows 为 `%APPDATA%\Zed\settings.json`。
- 合并而非替换：在已有的 `openai_compatible` 对象内加上 `tokenhush`。
- `available_models` 是必需的：Zed 不会自动发现自定义端点，只有声明过的模型才会出现在选择器里。`max_tokens` 是上下文窗口。
- API key：在 provider 的设置 UI 里输入。**不要**把 API key 写进 `settings.json`；若想用环境变量，用 `<PROVIDER_ID>_API_KEY`（`tokenhush` 对应 `TOKENHUSH_API_KEY`）。
- 在 Agent Panel 的模型选择器里选模型。
- 验证：发一次请求，观察 `tokenhush status`。
- 还原：删除 `tokenhush` 条目。
- 官方文档：<https://zed.dev/docs/ai/use-api-access>。

## 🧩 Continue.dev

**集成方式：** `~/.continue/config.yaml` → `models[].apiBase`（`/v1`）。

在配置里添加一个模型：

```yaml
models:
  - name: tokenhush
    provider: openai
    apiBase: "http://127.0.0.1:8787/v1"
```

- 文件位置：`~/.continue/config.yaml`（Windows：`%USERPROFILE%\.continue\config.yaml`）。旧版 Continue 用 `config.json`，键名同为 `apiBase`；若存在 `config.yaml` 则优先加载它。
- 合并而非替换：把该条目追加到已有的 `models:` 列表里。
- 保存文件后 Continue 自动重载，无需重启。
- 验证：发一次请求，观察 `tokenhush status`。
- 还原：删除该模型条目。
- 官方文档：<https://docs.continue.dev/customize/model-providers/top-level/openai>。

## 🧩 Open WebUI

**集成方式：** `OPENAI_API_BASE_URL`（`/v1`），或 Connections 设置。

启动服务前设置端点：

```bash
export OPENAI_API_BASE_URL=http://127.0.0.1:8787/v1
```

- 也可在 UI 里配置：**Admin Settings → Connections → OpenAI**（较新版本标为 **Manage OpenAI API Connections**），然后添加基础 URL 与 key。
- 模型选择器会调用 `GET /v1/models`，网关通过具名例外把它路由出去。
- 验证：刷新模型列表，发一次请求，观察 `tokenhush status`。
- 还原：删除变量或该连接。
- 官方文档：<https://docs.openwebui.com/getting-started/quick-start/connect-a-provider/starting-with-openai-compatible>。

## 🧩 Goose

**集成方式：** `OPENAI_HOST` + `OPENAI_BASE_PATH`。

启动 `goose` 前分别设置主机与基础路径：

```bash
export OPENAI_HOST=http://127.0.0.1:8787
export OPENAI_BASE_PATH=v1
```

- `OPENAI_HOST` 是裸主机，不要给它追加 `/v1`；路径放在 `OPENAI_BASE_PATH`。
- 验证：发一次请求，观察 `tokenhush status`。
- 还原：删除变量。
- 官方文档：<https://goose-docs.ai>。

## 🧩 OpenHands

**集成方式：** `LLM_BASE_URL`（`/v1`），或其配置文件里的 `[llm].base_url`。

用环境变量把 LLM 指向网关：

```bash
export LLM_BASE_URL=http://127.0.0.1:8787/v1
```

- 也可在其 `config.toml` 的 `[llm]` 段里设 `base_url`。
- 模型命名遵循 LiteLLM 约定：OpenAI 兼容端点用 `openai/` 前缀，例如 `openai/<model-id>`。
- 验证：发一次请求，观察 `tokenhush status`。
- 还原：删除变量或配置键。
- 官方文档：<https://docs.openhands.dev/openhands/usage/llms/custom-llm-configs>。

## 🧩 Kilo Code

**集成方式：** VS Code 扩展设置里的 OpenAI Compatible 基础 URL（`/v1`）。

1. 打开扩展设置，找到 API provider 区域。
2. 把 provider 设为 **OpenAI Compatible**。
3. 把 **Base URL** 设为 `http://127.0.0.1:8787/v1`。
4. 填 API key 与模型 ID。

- 不会写入项目文件；设置由扩展自己保存。
- 验证：发一次请求，观察 `tokenhush status`。
- 还原：把 provider 切回原值，或清空 Base URL。
- 官方文档：<https://kilo.ai/docs/ai-providers/openai-compatible>。

## 🛠️ 故障排查

- **工具连不上。** 先用 `tokenhush status` 确认网关在运行，再确认工具里的端口与 `tokenhush run` 打印的一致。
- **404 或 "unknown upstream"。** 基础 URL 形态不对。Anthropic 协议客户端用裸 origin，OpenAI 兼容客户端用 `/v1`。后缀写错是明确报错，不会静默错路由。
- **没有内容被脱敏。** 检查 `tokenhush.yaml` 里检测器是否启用，以及该值是否在 `allowlist` 上（静态或运行期——`tokenhush allowlist list` 打印运行期条目）。见 [`tokenhush.yaml` 参考](#tokenhushyaml-参考)。
- **请求根本没到网关。** 有些工具会缓存 provider 选择；重新选一次。VS Code 扩展的设置保存在扩展里，不在项目文件中。
- **远程、容器或 SSH 会话。** `127.0.0.1` 指工具运行所在的那台机器，不是你的笔记本。请在那台主机上运行网关，或做端口转发。
- **端到端验证。** 任何改动后，发一次请求，观察 `tokenhush status` 的 `requests` 计数增长。想用本机回显上游亲眼看到脱敏本身，见 [verify.zh-CN.md](verify.zh-CN.md)。

## 🔁 会离开本机的内容

网关自身发往厂商的请求，仅限[网络外发披露](generated/network-egress.md)中列出的两个可关、按命令触发的类别：规则同步与更新检查，各自有独立的关闭开关。工具自身的遥测是另一回事，不走这个基础 URL。威胁模型与硬性不变量见 [security.zh-CN.md](security.zh-CN.md)。

## 📚 参见

- [deployment.zh-CN.md](deployment.zh-CN.md) —— 安装、首次运行与交给操作系统后台运行。
- [verify.zh-CN.md](verify.zh-CN.md) —— 用本机回显上游验证脱敏。
- [security.zh-CN.md](security.zh-CN.md) —— 威胁模型与硬性不变量。
