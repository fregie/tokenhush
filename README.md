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

- **出站请求**：检测 → 占位符替换（如 `__PII_email_9f2c8a4b6d1e__`）→ 转发上游
- **入站响应**：占位符 → 原文回填（**仅回客户端**）
- **硬不变量**：绝不向出站方向回填占位符（防 prompt injection 诱导外泄）

## 支持的工具

**平台**：Windows / Linux / macOS（同一份纯 Go 代码，`CGO_ENABLED=0`）。

| 工具 | 接入方式 | 状态 |
|---|---|---|
| Claude Code CLI | `ANTHROPIC_BASE_URL` | 已支持 |
| Codex CLI | `~/.codex/config.toml` → `base_url` | 已支持（API key 模式） |
| Aider | `OPENAI_API_BASE` / `ANTHROPIC_API_BASE` | 已支持 |
| Cline / Roo Code | 设置内 Base URL | 已支持 |
| Continue | `config.json` → `apiBase` | 手动配置 |
| Open WebUI | OpenAI 连接 Base URL | 手动配置 |

`tokenhush env <tool>` 可直接打印 claude / codex / aider / cline / roo 的可复制片段。完整的接入说明见 [docs/configuration.md](docs/configuration.md)。

**不覆盖（V1 明确排除）**：Cursor 的 agent 流量、ChatGPT/Claude 桌面应用、浏览器网页版——这些需要系统级 MITM，不在本仓库实现。

## 安装

### 从源码构建（当前可用）

需要 Go 1.25 或更高版本。

```bash
go install github.com/fregie/tokenhush/cmd/tokenhush@latest
# 或在仓库内构建：
go build -o bin/tokenhush ./cmd/tokenhush
```

### 发行版安装包

打上 `v0.1.0` 标签后，发布流水线产出 Homebrew cask、Scoop manifest 与 `curl|sh` 脚本：

| 平台 | 命令 |
|---|---|
| macOS | `brew install --cask fregie/tap/tokenhush` |
| Linux | `curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh \| bash` |
| Windows | `scoop bucket add fregie https://github.com/fregie/scoop-bucket && scoop install tokenhush` |

每个 release 附带 `checksums.txt`（sha256）与 SBOM（SPDX JSON）。`install.sh` 会下载对应 OS/arch 的归档、校验 sha256 后再安装（默认装到 `~/.local/bin`，支持 `--dry-run`）。

> 在 `v0.1.0` 发布之前，请使用上面的**源码构建**方式；仓库中的 `main` 即 V1 实现。

#### macOS：Gatekeeper

发布二进制未做 Apple notarization。首次运行若被拦截：

- 右键（或 Control-点击）二进制 → **Open** → 在弹窗中再次确认 **Open**；或
- 清除隔离属性：`xattr -dr com.apple.quarantine "$(command -v tokenhush)"`

#### Windows：SmartScreen

手动下载 `.zip`、解压并首次运行 `tokenhush.exe` 时，SmartScreen 可能提示 “Windows protected your PC”：点击 **More info** → **Run anyway**。通过 Scoop 安装不会触发该提示。

## 快速开始

```bash
# 1. 启动网关（前台；默认监听 127.0.0.1:8787）
tokenhush run

# 2. 另开一个终端，把 Claude Code 指向网关
eval "$(tokenhush env claude)"
claude
```

## CLI

```text
<!-- check-docs:commands:start -->
    tokenhush run         启动网关（前台，Ctrl-C 退出）
    tokenhush version     打印版本与构建信息
    tokenhush env <tool>  打印工具接入片段（claude/codex/aider/cline/roo）
<!-- check-docs:commands:end -->
```

daemon 的控制面 API（`GET /status`、`GET /audit`）已就绪，需 `run` 启动时生成的 bearer token。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 核心架构、数据流、模块划分 |
| [docs/extension-api.md](docs/extension-api.md) | 扩展点接口（Router / CostSink / AuditExporter） |
| [docs/plugins.md](docs/plugins.md) | 编写内容插件（Inspector / Transformer） |
| [docs/configuration.md](docs/configuration.md) | 各 AI 工具的接入配置 + `tokenhush.yaml` 参考 |
| [docs/security.md](docs/security.md) | 安全模型、威胁模型、硬不变量 |

## 项目角色

这是**公开核心仓库**（Apache-2.0）。Pro / 企业功能在私有仓库中实现，通过导入本核心的 Go module 构建付费二进制——**Pro 代码不会进入本仓库**。见 [docs/architecture.md](docs/architecture.md) 的「Open-core 边界」。

## 状态

V1 核心已实现并通过测试：`tokenhush run`（前台网关 + 双栈 loopback）、`tokenhush version`、`tokenhush env <tool>`，以及本地审计（SQLite + HMAC 链）。纯 Go，`CGO_ENABLED=0`，CI 在 Linux / macOS / Windows 三平台运行单元测试与端到端 smoke test。

## 许可

[Apache License 2.0](LICENSE)。
