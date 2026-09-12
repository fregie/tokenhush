# 配置

[English](configuration.md) | **中文**

> Status: V1（2026-09）。命令与默认值跟随 `main`；[`scripts/check-docs.sh`](../scripts/check-docs.sh) 校验每个文档化命令和配置键。

把 AI 编程工具指向本地 Tokenhush 网关。脱敏安全模型见 [security.zh-CN.md](security.zh-CN.md)。

## 通用流程

1. `tokenhush run` 启动网关，默认监听 `127.0.0.1:8787`。
2. 把工具的 API 基础 URL 指向网关。
3. `tokenhush env <tool>` 打印可直接粘贴的片段；也可照下面各节手动配置。

网关在环回上读取明文 HTTP 完整请求体并脱敏，无需根证书。

> [!NOTE]
> 支持 Windows、Linux、macOS。`export` 片段是 POSIX；Windows PowerShell 请用 `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"`，并用 `setx` 持久化。`tokenhush env` 自动选对写法。

## Claude Code CLI

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
# 需要自定义鉴权头时，Claude Code 也接受 ANTHROPIC_AUTH_TOKEN
```

> [!NOTE]
> Claude Max/Pro 订阅的推理请求会遵循 `ANTHROPIC_BASE_URL`（见 [Anthropic LLM gateway 文档](https://code.claude.com/docs/en/llm-gateway)），网关必须逐字转发 `anthropic-beta`。OAuth 刷新与授权始终发往 `platform.claude.com` 和 `claude.ai`，不经过网关。实时会话捕获见 [`scripts/oauth-matrix.sh`](../scripts/oauth-matrix.sh) `--capture`。

## Codex CLI

编辑 `~/.codex/config.toml`：

```toml
model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }
```

Codex 默认用 **Responses API**（`/v1/responses`）。Tokenhush 支持它，也支持增量式 SSE 回填。

> [!WARNING]
> 经网关的 ChatGPT 订阅登录（非 API 密钥）**目前不支持**：订阅 token 只对 ChatGPT 服务路径有效，转发到 OpenAI 平台 API 会返回 401（见 [openai/codex#34608](https://github.com/openai/codex/issues/34608)）。请改用 API 密钥模式。

## Aider

```bash
export OPENAI_API_BASE=http://127.0.0.1:8787/v1
export ANTHROPIC_API_BASE=http://127.0.0.1:8787
# 或在命令行中：
aider --openai-api-base http://127.0.0.1:8787/v1
```

## Cline / Roo Code

VS Code 扩展：在设置里选 "OpenAI Compatible"（或 Anthropic）并填基础 URL：

```text
Base URL: http://127.0.0.1:8787/v1
```

## Continue

编辑 `~/.continue/config.json`，在 `models` 里设 `apiBase`：

```json
{
  "models": [
    {
      "apiBase": "http://127.0.0.1:8787/v1"
    }
  ]
}
```

## Open WebUI

在 **Connections** 里添加 OpenAI 兼容端点：

```text
Base URL: http://127.0.0.1:8787/v1
```

## `tokenhush.yaml` 参考

配置文件在平台配置目录（`pkg/platform.ConfigDir()`）：macOS `~/Library/Application Support/tokenhush/`，Linux `${XDG_CONFIG_HOME:-~/.config}/tokenhush/`，Windows `%AppData%\tokenhush\`。用 `--config PATH` 覆盖，或用 `TOKENHUSH_HOME` 同时搬走配置和数据目录。文件不存在即用默认值。**未知键会被拒绝**，拼错不会悄悄关掉保护：`listen` 写成 `listenn`，加载直接失败。

完整默认值：

<!-- check-docs:config:start -->
```yaml
listen:
  host: 127.0.0.1      # 仅允许 127.0.0.1 / ::1 / localhost；0.0.0.0 会被拒绝
  port: 8787           # 1..65535
detectors:
  prefixes: true       # 已知密钥前缀（sk-、AKIA、ghp_、...）
  high_entropy: true   # 高熵字符串
  jwt: true            # JWT
  private_keys: true   # PEM 私钥头
  luhn: true           # 卡号（Luhn）
  email: true          # 电子邮件地址
allowlist: []          # 永不脱敏的字面量
log:
  level: info          # debug | info | warn | error
upstreams:             # 主机或路径前缀 -> 上游基础 URL
  api.example.com: https://api.example.com
```
<!-- check-docs:config:end -->

要点：

- `listen.host` 只接受环回地址。网关**绝不**绑定 `0.0.0.0` 或空主机，只绑双栈环回（`127.0.0.1` 和 `[::1]`）。
- 六个确定性检测器，高精度：密钥前缀、高熵字符串、JWT、PEM 私钥头、Luhn 卡号、电子邮件。命中生成稳定占位符，如 `__PII_email_9f2c8a4b6d1e__`，上游拿不到原始值。
- `prefixes` 对应检测器 id `prefix`，`private_keys` 对应 `private_key`（见 `pkg/config` 注释）。
- `allowlist` 放永不脱敏的字面量。
- 核心配置里没有 `audit` 键。仍带该键的配置会加载失败，并提示查看 [migration-v0.2.0.zh-CN.md](migration-v0.2.0.zh-CN.md)。
- `upstreams:` 把主机或路径前缀映射到你的 OpenAI 兼容上游。没配到的请求走内置路由：`/v1/messages` 去 Anthropic；`/v1/chat/completions` 和 `/v1/responses` 去 OpenAI。未知路径明确报错，不会静默错路由。

## 已知限制

> [!IMPORTANT]
> 依赖网关做订阅登录前，先读这一节。

- **订阅 OAuth 登录**
  - **Claude Code（订阅登录）：** 推理会遵循基础 URL。鉴权和刷新留在 `platform.claude.com` 等域，不经过网关。实时会话流程见 [`scripts/oauth-matrix.sh`](../scripts/oauth-matrix.sh)。
  - **Codex CLI（ChatGPT 订阅登录）：** V1 不支持。见上面 Codex 一节，改用 API 密钥。
- **遥测端点绕过基础 URL：** 有些工具会向 PostHog、Sentry 等服务发遥测。内容很少，但确实存在。
- **未覆盖：** Cursor agent 流量（发往 `api2.cursor.sh`）、ChatGPT 和 Claude 桌面应用、浏览器 Web UI。这些要系统级方案，公开核心未实现。

## 连通性自检

```bash
<!-- check-docs:commands:start -->
tokenhush version       # 确认二进制可运行
tokenhush doctor        # 诊断配置、密钥环和端口问题
tokenhush env claude    # 打印设置片段，包含当前端口
<!-- check-docs:commands:end -->
```

`run` 启动时打印监听地址和控制 token 文件路径。`tokenhush status` 报告网关是否在运行。`env` 和 `doctor` 都接受 `--config PATH` 和 `--port N`，自检能对上实际启动的网关。`GET /status` 需要 bearer token，每次 `run` 重新生成。
