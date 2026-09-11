# Architecture — tokenhush (public core)

> 状态：V1 已实现（2026-09）。本文描述已落地的核心架构与 open-core 边界。

## 1. 目标与非目标

**目标**
- 在 AI 编码工具的请求离开本机之前，检测并脱敏敏感内容（密钥、`.env`、PII）。
- 提供**本地审计时间线**，默认仅记录元数据。
- 对所有认 `*_BASE_URL` / custom endpoint 的工具，**零配置摩擦**地接入。
- **跨平台**：Windows / Linux / macOS 均可运行。
- 纯本地处理，**数据永不离开设备**。

**非目标（V1 明确排除）**
- 系统级 MITM / 根证书安装
- 覆盖 Cursor agent、ChatGPT/Claude 桌面版、浏览器
- 团队协作 / 云端 / SSO
- 三平台的系统级拦截（系统扩展 / MITM 仍 macOS-first，见 `../../tokenhush-pro/docs/decisions/0006-cross-platform-v1.md`）
- NER 或本地小模型做语义检测

## 2. 数据流

```
┌──────────────┐   HTTP (localhost, 明文)   ┌────────────────────────────┐   HTTPS   ┌──────────────┐
│ AI 编码工具  │ ─────────────────────────▶ │  tokenhush 本地网关        │ ────────▶ │ 模型 provider │
│ (Claude Code │                            │                            │           │ (Anthropic/  │
│  Codex/Aider │ ◀───────────────────────── │  ┌──────────────────────┐  │ ◀──────── │  OpenAI/…)   │
│  Cline/…)    │   HTTP 响应（已回填）      │  │ 1 解析叶子           │  │           └──────────────┘
└──────────────┘                            │  │ 2 检测敏感          │  │
                                            │  │ 3 占位符替换(出站)  │  │
                                            │  │ 4 转发上游          │  │
                                            │  │ 5 流式回填(入站)    │  │
                                            │  └──────────────────────┘  │
                                            │            │               │
                                            │            ▼               │
                                            │   本地审计 (SQLite,        │
                                            │   仅元数据 + HMAC 链)      │
                                            └────────────────────────────┘
```

**关键洞察**：敏感方向是**请求**，而请求是**非流式**的——转发前可拿到完整 JSON body，因此可以完整脱敏、无流式改写难题。响应方向通常只含占位符，回填是"占位符 → 原文"的有限替换。

## 3. 组件

| 包 | 职责 |
|---|---|
| `pkg/proxy` | 本地 HTTP 反向代理：监听、路由到上游、SSE 透传、生命周期 |
| `pkg/redact` | 检测器（确定性规则）+ 占位符生成/映射 + 回填 |
| `pkg/protocol` | 协议无关的 JSON 叶子遍历；SSE 增量解析；tool-call 双重编码 JSON 递归 |
| `pkg/audit` | append-only SQLite + HMAC 哈希链；仅元数据；保留策略 |
| `pkg/config` | 配置加载与默认值（`tokenhush.yaml`） |
| `pkg/platform` | 跨平台抽象：路径 / 密钥环 / 服务（导出让 Pro 复用） |
| `pkg/extension` | 内容插件接口（Inspector / Transformer / Registry）+ 跨层扩展点（见 `extension-api.md`、`plugins.md`） |
| `pkg/license` | 只读 Pro 许可校验与展示（隔离、fuzz 测试） |
| `cmd/tokenhush` | 免费 CLI：`run`（前台网关）/ `version` / `env`（打印接入片段）+ 控制面 API |

## 4. 关键设计决策

### 4.1 协议无关的叶子遍历（不做 API 归一化）
不建立 Anthropic/OpenAI/Responses 的中间表示——那会随 API 演进持续腐烂。改为**递归遍历 JSON，对 string 叶子运行检测/替换**；对 tool-call 里双重编码的 JSON 字符串递归处理；对 SSE 做增量叶子解析。对 API 变化鲁棒。

### 4.2 占位符与回填
- 格式：JSON 安全 + tokenizer 友好 + 高熵，如 `__PII_email_3f9a2b__`。
- 映射：同一 secret 用 **HMAC 确定性**映射到同一占位符，避免多会话碰撞导致"错误回填泄露另一个 secret"。
- 存储：**仅内存、会话级**。重启失忆 → 回填失败时用户看到占位符（**安全降级，非泄露**）。
- **硬不变量**：只在**回客户端**方向回填，**绝不出站回填**。

### 4.3 流式处理
- 出站：完整读取 body 后脱敏，无缓冲问题。
- 入站：用**定长滑动窗口**（= 最长占位符长度）处理占位符跨 SSE chunk 截断；无需整段缓冲。延迟可忽略。

### 4.4 检测策略（V1）
确定性规则，**高精确率优先**：已知 key 前缀（`sk-`/`AKIA`/`ghp_`…）、高熵串、JWT、私钥头、Luhn、邮箱/卡号校验和。提供 allow 列表 + 一键放行。措辞诚实："高置信 secrets 拦截"，不宣称"绝不泄露"。

## 5. Open-core 边界

公开核心（本仓库，Apache-2.0）提供**单用户完整可用**的能力：代理、脱敏、审计、CLI、扩展点接口。

私有 Pro（`../../tokenhush-pro`）通过 **import 本仓库的 Go module** 构建付费二进制，提供：
- 系统扩展 / MITM power mode（在闭源 macOS App 侧）
- 多 provider / 多账号路由
- 成本追踪
- 团队审计导出 / SSO
- Dashboard / 菜单栏 UI

**规则**：Pro 的代码与算法**永不进入本仓库**；本仓库不出现 `if license { ... }` 的付费实现分支。详见 `../../tokenhush-pro/docs/05-distribution-and-open-core.md`。

## 6. 能力阶梯（跨仓库）

| 阶段 | 能力 | 渠道 |
|---|---|---|
| V1 | base-URL 网关：内容级脱敏 + 审计（覆盖 CLI/IDE 工具） | 开源核心 + 免费 CLI |
| V2 | 系统扩展元数据模式：全域域名/进程级拦截 + 审计（**无 CA**） | Pro（直下载） |
| V3 | 透明代理 + 本地 CA：内容级脱敏覆盖 Cursor/浏览器/桌面应用 | Pro（显式 opt-in） |

> V2/V3 依赖 macOS Network Extension 系统扩展（Developer ID 签名 + 用户批准 + Apple capability 审批），不在本仓库实现。
