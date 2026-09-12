# 配置

[English](configuration.md) | **中文**

> Status: V1 已实现（2026-09）。命令与默认值跟随 `main`；[`scripts/check-docs.sh`](../scripts/check-docs.sh) 会校验每个文档化的命令和配置键确实存在。

本页说明如何将你的 AI 编程工具指向本地 Tokenhush 网关。关于脱敏背后的安全模型，见 [security.zh-CN.md](security.zh-CN.md)。

## 通用流程

1. 在前台启动网关：`tokenhush run`。默认监听 `127.0.0.1:8787`。
2. 将工具的 API 基础 URL 指向网关。
3. 用 `tokenhush env <tool>` 打印可直接粘贴的片段，或按下方各节手动配置工具。

所有请求都以明文 HTTP 发往环回地址，因此网关能读取完整请求体并对其脱敏。无需根证书。

> [!NOTE]
> Windows、Linux 和 macOS 均受支持。下面的 `export` 片段是 POSIX（macOS / Linux）。在 Windows PowerShell 中，使用 `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"`，并用 `setx` 持久化。`tokenhush env` 会为当前平台自动选择正确的方言。

## Claude Code CLI

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
# 若需要自定义鉴权头，Claude Code 也接受 ANTHROPIC_AUTH_TOKEN
```

> [!NOTE]
> 使用 Claude Max/Pro 订阅时，推理请求会遵循 `ANTHROPIC_BASE_URL`（见 [Anthropic LLM gateway 文档](https://code.claude.com/docs/en/llm-gateway)），网关必须逐字转发 `anthropic-beta`。OAuth 刷新与授权始终发往 `platform.claude.com` 和 `claude.ai`，绝不经过网关。实时会话捕获流程见 [`scripts/oauth-matrix.sh`](../scripts/oauth-matrix.sh) `--capture`。

## Codex CLI

编辑 `~/.codex/config.toml`：

```toml
model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }
```

Codex 默认使用 **Responses API**（`/v1/responses`）。Tokenhush 支持该协议，包括增量式 SSE 回填。

> [!WARNING]
> 目前经网关的 ChatGPT 订阅登录（非 API 密钥）**不受支持**。订阅 token 仅对 ChatGPT 服务路径有效，将其转发到 OpenAI 平台 API 会返回 401（见 [openai/codex#34608](https://github.com/openai/codex/issues/34608)）。请改用 API 密钥模式。

## Aider

```bash
export OPENAI_API_BASE=http://127.0.0.1:8787/v1
export ANTHROPIC_API_BASE=http://127.0.0.1:8787
# 或在命令行中：
aider --openai-api-base http://127.0.0.1:8787/v1
```

## Cline / Roo Code

二者是 VS Code 扩展。在扩展设置中选择 "OpenAI Compatible"（或 Anthropic）并设置基础 URL：

```text
Base URL: http://127.0.0.1:8787/v1
```

## Continue

编辑 `~/.continue/config.json`，在 `models` 中设置 `apiBase`：

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

在 **Connections** 下添加一个 OpenAI 兼容端点，并使用以下 URL：

```text
Base URL: http://127.0.0.1:8787/v1
```

## `tokenhush.yaml` 参考

配置文件位于平台配置目录（`pkg/platform.ConfigDir()`）：macOS `~/Library/Application Support/tokenhush/`，Linux `${XDG_CONFIG_HOME:-~/.config}/tokenhush/`，Windows `%AppData%\tokenhush\`。可用 `--config PATH` 覆盖，或用 `TOKENHUSH_HOME` 同时移动配置目录和数据目录。文件缺失意味着"使用默认值"；**未知键会被拒绝**，因此拼写错误不会静默地关闭保护。

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

- `listen.host` 仅接受环回地址。网关**绝不**绑定 `0.0.0.0` 或空主机；它绑定双栈环回（`127.0.0.1` 和 `[::1]`）。
- 六个检测器是确定性的，并为高精度而调优：已知密钥前缀、高熵字符串、JWT、PEM 私钥头、Luhn 卡号、电子邮件。
- 有两个 YAML 键有意与其检测器 id 不同：`prefixes` 映射到 id `prefix`，`private_keys` 映射到 id `private_key`（见 `pkg/config` 注释）。
- `allowlist` 保存永不脱敏的字面量。
- 核心配置中没有 `audit:` 块。审计配置已移至私有 Pro 层；仍包含 `audit:` 的配置会加载失败，并给出可操作的迁移错误。见 [migration-v0.2.0.zh-CN.md](migration-v0.2.0.zh-CN.md)。
- `upstreams:` 将主机或路径前缀转发到你自己的 OpenAI 兼容上游。未匹配的请求回退到内置路由：`/v1/messages` 路由到 Anthropic；`/v1/chat/completions` 和 `/v1/responses` 路由到 OpenAI。未知路径会返回明确错误，绝不会被静默地错误路由。

## 已知限制

> [!IMPORTANT]
> 在你依赖网关进行订阅登录之前，请先阅读本节。

- **订阅 OAuth 登录**
  - **Claude Code（订阅登录）：** 推理请求会遵循基础 URL（Anthropic 文档已确认；网关必须逐字转发 `anthropic-beta`）。鉴权与刷新留在 `platform.claude.com` 及类似域上，因此绝不经过网关。实时会话流程见 [`scripts/oauth-matrix.sh`](../scripts/oauth-matrix.sh)。
  - **Codex CLI（ChatGPT 订阅登录）：** V1 不支持。见上方 Codex 一节，改用 API 密钥。
- **遥测端点绕过基础 URL：** 部分工具会向 PostHog、Sentry 及类似服务发送遥测。它携带的内容很少，但你应当知道这会发生。
- **未覆盖：** Cursor agent 流量（发往 `api2.cursor.sh`）、ChatGPT 和 Claude 桌面应用，以及浏览器 Web UI。这些需要系统级方案，公开核心中未实现。

## 连通性自检

```bash
<!-- check-docs:commands:start -->
tokenhush version       # 确认二进制可运行
tokenhush doctor        # 诊断配置、密钥环和端口问题
tokenhush env claude    # 打印设置片段，包含当前端口
<!-- check-docs:commands:end -->
```

`run` 启动时会打印监听地址和控制 token 文件路径。`tokenhush status` 报告网关是否在运行。`env` 和 `doctor` 都接受 `--config PATH` 和 `--port N`，因此自检会匹配你实际启动的网关。控制面暴露 `GET /status`，并需要 bearer token，该 token 在每次 `run` 时重新生成。具体审计存储、`audit` 子命令和审计端点位于私有 Pro 层。
