# Configuration — 各 AI 工具接入 Tokenhush

> 状态：设计稿（2026-09）。以下为计划支持的接入方式，命令与端口以实际实现为准。

## 通用流程

1. 启动本地网关：`tokenhush serve`（默认监听 `127.0.0.1:8787`）。
2. 把目标工具的 API base URL 指向网关。
3. 用 `tokenhush status` 或工具的连通性自检确认生效。

所有请求走**明文 HTTP 到 localhost**，因此网关能看到完整内容做脱敏——**无需安装任何根证书**。

> **平台**：Windows / Linux / macOS 均支持。下方 `export` 为 POSIX（mac/Linux）；Windows PowerShell 用 `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"`（持久化用 `setx`）。

## Claude Code CLI

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
# 如需自定义鉴权头，Claude Code 支持 ANTHROPIC_AUTH_TOKEN
```

## Codex CLI

编辑 `~/.codex/config.toml`：

```toml
model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }
```
> 注意：Codex 默认走 **Responses API**（`/v1/responses`），Tokenhush 必须适配该协议。

## Aider

```bash
export OPENAI_API_BASE=http://127.0.0.1:8787/v1
export ANTHROPIC_API_BASE=http://127.0.0.1:8787
# 或命令行：aider --openai-api-base http://127.0.0.1:8787/v1
```

## Cline / Roo Code（VS Code 扩展）

在扩展设置中选择 "OpenAI Compatible"（或 Anthropic），把 **Base URL** 设为 `http://127.0.0.1:8787/v1`。

## Continue

编辑 `~/.continue/config.json`，在 `models` 中设置 `apiBase: "http://127.0.0.1:8787/v1"`。

## Open WebUI

在「连接」中添加 OpenAI 兼容端点，URL 填 `http://127.0.0.1:8787/v1`。

## 已知限制（重要）

- **订阅式 OAuth 登录可能绕过 base URL**：使用 Claude Max / ChatGPT 登录（而非 API key）时，工具是否遵守 base URL **需实测**。API-key 模式是安全路径。
- **遥测端点不走 base URL**：部分工具会向 PostHog / Sentry 等发送遥测，含内容较少但需知晓。
- **不覆盖**：Cursor agent 流量（走 `api2.cursor.sh`）、ChatGPT/Claude 桌面版、浏览器网页版——需系统级方案（见 `../tokenhush-pro/docs/06-roadmap.md` 的 V2/V3）。

## 连通性自检（规划）

```bash
tokenhush status        # 显示网关是否在跑、最近请求数、脱敏命中数
tokenhush env claude    # 打印可直接复制的接入片段
```
