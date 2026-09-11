# Tokenhush

> A local gateway that redacts secrets and sensitive data from your AI coding tools' requests — before they reach the model. Audit everything. Leak nothing. 100% local.

Tokenhush 是一个**本地 base-URL 网关**：把你使用的 AI 编码工具（Claude Code、Codex CLI、Aider、Cline、Roo Code、Continue…）的 API 请求指向本机，它在转发到云端模型之前检测并脱敏敏感内容（API key、`.env`、PII、客户数据…），并留下一份**本地审计时间线**。**你的数据永不离开你的机器。**

---

## 为什么需要它

AI 编码代理会把整个仓库、`.env`、密钥发给云端。2026 年有开发者用抓包（mitmproxy）实锤 **Grok Build CLI 上传完整 repo（含 git 历史与 `.env`），且 opt-out 无效**（社区帖 593 赞）。同类隐私质疑在 OpenCode、Claude Code 等工具上反复出现。

Tokenhush 给这类工具加一道**本地关卡**：看得见、管得住、不误伤。

## 工作原理

```
你的 AI 工具 ──HTTP──▶ 127.0.0.1 网关 ──脱敏后──▶ 云端模型
                          │
                          └──▶ 本地审计日志（默认仅元数据）
```

- **出站请求**：检测 → 占位符替换（如 `__PII_email_3f9a2b__`）→ 转发上游
- **入站响应**：占位符 → 原文回填（**仅回客户端**）
- **硬不变量**：绝不向出站方向回填占位符（防 prompt injection 诱导外泄）

## 覆盖范围（V1 规划）

**平台**：Windows / Linux / macOS（跨平台）。

| 工具 | 接入方式 | 状态 |
|---|---|---|
| Claude Code CLI | `ANTHROPIC_BASE_URL` | 规划 |
| Codex CLI | `~/.codex/config.toml` → `base_url` | 规划 |
| Aider | `OPENAI_API_BASE` / `ANTHROPIC_API_BASE` | 规划 |
| Cline / Roo Code | 设置内 Base URL | 规划 |
| Continue | `config.json` → `apiBase` | 规划 |
| Open WebUI | OpenAI 连接 Base URL | 规划 |

**不覆盖（V1 明确排除）**：Cursor 的 agent 流量、ChatGPT/Claude 桌面应用、浏览器网页版——这些需要系统级 MITM，属于后续阶段（见路线图）。

## 安装（规划中）

> ⚠️ 项目处于**设计定稿 / 待实现阶段**。预期安装方式：
> - Homebrew（mac/Linux）：`brew install tokenhush`
> - Scoop（Windows）：`scoop install tokenhush`
> - 安装脚本：`curl -fsSL https://…/install.sh | sh`
> - 包管理器 wrapper 延后（V1 不分发；见私有仓库 `tokenhush-pro` 的 `docs/13-v1-technical-design.md`）

## 文档

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 核心架构、数据流、模块划分 |
| [docs/extension-api.md](docs/extension-api.md) | 扩展点接口（Router / CostSink / AuditExporter） |
| [docs/configuration.md](docs/configuration.md) | 各 AI 工具的接入配置 |
| [docs/security.md](docs/security.md) | 安全模型、威胁模型、硬不变量 |

## 项目角色

这是**公开核心仓库**（Apache-2.0）。Pro / 企业功能在私有仓库 `tokenhush-pro` 中实现，通过导入本核心的 Go module 构建付费二进制——**Pro 代码不会进入本仓库**。见 [docs/architecture.md](docs/architecture.md) 的「Open-core 边界」。

## 状态

**设计定稿 / 待实现（2026-09）**。请勿用于生产。当前进入 V1 生产编码（跨三平台）；验证改为开发期非阻塞并行（见 `tokenhush-pro` 的 `docs/decisions/0005-skip-gate1-direct-v1.md`）。

## 许可

[Apache License 2.0](LICENSE)。
