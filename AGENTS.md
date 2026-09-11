# AGENTS.md — tokenhush (public core)

**项目**：Tokenhush —— 本地 AI 流量安全网关（公开核心仓库）
**状态**：设计定稿（无生产代码；V1 编码即将开始，跨三平台）
**最后更新**：2026-09-11

## 这是什么

本地 base-URL 网关：AI 编码工具把 API 请求指向本机（如 `ANTHROPIC_BASE_URL=http://127.0.0.1:PORT`），Tokenhush 负责**出站脱敏**（密钥 / PII / 敏感文本）+ **本地审计**，响应**回填**后返回客户端。纯本地处理，数据不出设备。

本仓库是 **Apache-2.0 开源核心**。私有 Pro 层在 `../tokenhush-pro`，通过导入本仓库的 Go module 构建。**绝不要把 Pro 代码放进本仓库。**

## 结构与未来布局

```
tokenhush/
├── README.md
├── LICENSE                 # Apache-2.0
├── CONTRIBUTING.md
├── AGENTS.md               # 本文件
├── docs/
│   ├── architecture.md     # 核心架构 + open-core 边界
│   ├── extension-api.md    # 公开扩展点接口
│   ├── configuration.md    # 各工具接入配置
│   └── security.md         # 安全/威胁模型 + 硬不变量
├── cmd/tokenhush/          # 免费 CLI 入口（规划）
└── pkg/
    ├── proxy/              # 本地反向代理
    ├── redact/             # 检测 / 占位符 / 回填引擎
    ├── protocol/           # 协议无关 JSON 叶子遍历 + SSE 增量解析
    ├── audit/              # SQLite 审计（元数据 + HMAC 哈希链）
    ├── config/             # 配置加载
    ├── platform/           # 跨平台抽象：paths / keyring / service（导出让 Pro 复用）
    └── extension/          # 扩展点接口（Router / CostSink / AuditExporter + 内容插件 Inspector/Transformer/Registry）
```

## Where to Look

| 任务 | 位置 |
|---|---|
| 架构 / 数据流 / open-core 边界 | `docs/architecture.md` |
| 新增/修改扩展点接口 | `docs/extension-api.md` + `pkg/extension/` |
| 新增工具接入方式 | `docs/configuration.md` |
| 安全不变量 / 威胁模型 | `docs/security.md` |
| 产品/市场/路线图/定价 | `../tokenhush-pro/docs/` |

## 硬约定（不可违反）

1. **绝不向出站方向回填占位符**——只回客户端。这是防 prompt-injection 外泄的核心不变量。
2. **协议层不做归一化**：采用协议无关的 JSON 叶子遍历（递归 string 叶子检测/替换），不要为每个 API 建 IR。
3. **V1 检测器只用确定性规则**（前缀 / 高熵 / JWT / 私钥头 / Luhn / 邮箱），**不引入 NER 或本地小模型**。
4. **本地服务只绑双栈 loopback（127.0.0.1 + [::1]）**，并校验 `Host` 头（防 DNS rebinding）；若未来支持网关注入 key，必须加 gateway token + Origin 校验。
5. **审计默认仅元数据**（provider/端点/时间/字节数/脱敏计数/类型），不存值；内容日志必须显式开启且加密。
6. **Pro 能力不进本仓库**：不要在这里写 `if license { ... }` 的完整实现或 Pro 算法。
7. **依赖许可**：核心依赖只允许 MIT / Apache-2.0 / BSD 等宽松许可，**禁止 GPL / AGPL**（会污染闭源 Pro 层）。
8. **跨平台**：OS 差异收敛进 `pkg/platform`，不散落 `runtime.GOOS` 分支；绝不写 CWD / 二进制目录（安装前缀只读）；用纯 Go SQLite（`modernc.org/sqlite`）保持 `CGO_ENABLED=0` 交叉编译。

## Anti-Patterns（不要做）

- ❌ 在开源代码里放付费功能的完整实现或开关分支。
- ❌ 默认开启 MITM / 安装根证书。
- ❌ 在 V1 引入 NER / 小模型做语义检测（误报与体积代价高）。
- ❌ 用 `as any` 式绕过类型/错误处理。
- ❌ 在无用户反馈时扩大配置 / 接口表面（Gate 1 已改为非阻塞并行、见私有仓库 ADR-0005；应对之道是「更少、更有主见」）。

## 命令（规划）

```bash
# 构建（规划）
go build -o bin/tokenhush ./cmd/tokenhush
# 运行（规划）
./bin/tokenhush run --port 8787
# 测试
go test ./...
```

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。提交需签署 DCO。安全漏洞请勿公开 issue，见 CONTRIBUTING 的披露流程。
