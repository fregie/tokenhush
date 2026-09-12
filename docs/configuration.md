# Configuration — 各 AI 工具接入 Tokenhush

> 状态：V1 已实现（2026-09）。命令与默认值以本仓库 `main` 为准；`scripts/check-docs.sh` 会校验文中命令与配置键确实存在。

## 通用流程

1. 启动本地网关：`tokenhush run`（默认监听 `127.0.0.1:8787`）。
2. 把目标工具的 API base URL 指向网关。
3. 用 `tokenhush env <tool>` 打印可复制片段，或按下方各节手动配置。

所有请求走**明文 HTTP 到 localhost**，因此网关能看到完整内容做脱敏——**无需安装任何根证书**。

> **平台**：Windows / Linux / macOS 均支持。下方 `export` 为 POSIX（mac/Linux）；Windows PowerShell 用 `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"`（持久化用 `setx`）。`tokenhush env` 会按当前平台自动选择方言。

## Claude Code CLI

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
# 如需自定义鉴权头，Claude Code 支持 ANTHROPIC_AUTH_TOKEN
```

> 订阅登录（Claude Max/Pro）：推理请求遵守 `ANTHROPIC_BASE_URL`（见 [Anthropic LLM gateway 文档](https://code.claude.com/docs/en/llm-gateway)），网关需原样转发 `anthropic-beta`。OAuth 刷新/授权固定走 `platform.claude.com` / `claude.ai`，不经网关。真人会话实测流程见 `scripts/oauth-matrix.sh --capture`。

## Codex CLI

编辑 `~/.codex/config.toml`：

```toml
model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }
```
> 注意：Codex 默认走 **Responses API**（`/v1/responses`），Tokenhush 已适配该协议（含 SSE 增量回填）。
> **ChatGPT 订阅登录（非 API key）当前不支持经网关使用**：订阅令牌只对 ChatGPT 服务路径有效，转发到 OpenAI 平台 API 会 401（[openai/codex#34608](https://github.com/openai/codex/issues/34608)）。请使用 API key 模式。

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

## `tokenhush.yaml` 参考

配置文件按平台放在配置目录（`pkg/platform.ConfigDir()`）：macOS `~/Library/Application Support/tokenhush/`，Linux `$XDG_CONFIG_HOME/tokenhush/`（默认 `~/.config/tokenhush/`），Windows `%AppData%\tokenhush\`。可用 `--config PATH` 覆盖。文件缺失即使用默认值；**未知键会被拒绝**（防止拼写错误静默失效）。

完整默认配置：

<!-- check-docs:config:start -->
```yaml
listen:
  host: 127.0.0.1      # 只允许 127.0.0.1 / ::1 / localhost；0.0.0.0 会被拒绝
  port: 8787           # 1..65535
detectors:
  prefixes: true       # 已知 key 前缀（sk-、AKIA、ghp_ …）
  high_entropy: true   # 高熵串
  jwt: true            # JWT
  private_keys: true   # PEM 私钥头
  luhn: true           # 卡号（Luhn 校验）
  email: true          # 邮箱
allowlist: []          # 永不脱敏的字面量列表
audit:
  enabled: true        # 本地审计（默认仅元数据）
  retention_days: 14   # >= 1；7..30 为建议区间
log:
  level: info          # debug | info | warn | error
upstreams:             # host/路径前缀 → 上游 base URL（自定义/兼容端点）
  api.example.com: https://api.example.com
```
<!-- check-docs:config:end -->

要点：

- `listen.host` 只接受 loopback；网关**绝不**绑定 `0.0.0.0` 或空 host。
- 同名 key 的 YAML 名与检测器 id 有意不同：`prefixes` → `prefix`，`private_keys` → `private_key`（见 `pkg/config` 注释）。
- `upstreams:` 用于把某个 host 或路径前缀转发到你自己的 OpenAI 兼容上游；未命中的请求走内建解析（`/v1/messages` → Anthropic，`/v1/chat/completions`、`/v1/responses` → OpenAI）。未知路径返回明确错误，绝不静默错转。

## 已知限制（重要）

- **订阅式 OAuth 登录**：
  - Claude Code（订阅登录）：推理请求遵守 base URL（Anthropic 官方文档已确认；网关须原样转发 `anthropic-beta`）。认证/刷新固定走 `platform.claude.com` 等域名，不经网关。真人会话实测流程见 `scripts/oauth-matrix.sh --capture`。
  - Codex CLI（ChatGPT 订阅登录）：**V1 不支持**，见上方 Codex 小节；请用 API key。
- **遥测端点不走 base URL**：部分工具会向 PostHog / Sentry 等发送遥测，含内容较少但需知晓。
- **不覆盖**：Cursor agent 流量（走 `api2.cursor.sh`）、ChatGPT/Claude 桌面版、浏览器网页版——需系统级方案，不在公开核心实现。

## 连通性自检

```bash
tokenhush version       # 确认二进制可用
tokenhush doctor        # 诊断配置 / 密钥环 / 端口等常见问题
tokenhush env claude    # 打印接入片段，含当前配置端口
```

`run` 启动后会打印监听地址与控制 token 文件路径；`tokenhush status` 报告运行状态，`tokenhush audit [--json]` 读取本地审计时间线。控制面 `GET /status`、`GET /audit` 需携带 bearer token（`run` 每次启动重新生成）。
