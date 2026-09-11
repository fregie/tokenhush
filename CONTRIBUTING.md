# Contributing to Tokenhush

Thanks for your interest in making AI coding tools safer.

## 开发状态

V1 核心已实现（`run` / `version` / `env`），跨 Windows / Linux / macOS。当前最有价值的贡献：

- 反馈各 AI 工具的 base-URL 接入方式与坑（见 `docs/configuration.md`）
- 报告脱敏漏报 / 误报，和安全/隐私风险
- 评审 `docs/architecture.md`、`docs/security.md`、`docs/plugins.md`
- 编写与分享内容插件（Inspector / Transformer，见 `docs/plugins.md`）

## 本地开发

需要 Go 1.25 或更高版本。

```bash
go build ./...          # 构建
go vet ./...            # 静态检查
go test ./...           # 单元测试 + 端到端 smoke
bash scripts/check-docs.sh   # 文档与 CLI / 配置一致性校验
```

## 提交贡献

1. Fork 本仓库并创建分支（`feat/...`、`fix/...`）。
2. 遵循项目约定（Go：`gofmt`/`golangci-lint`；错误用 `fmt.Errorf("context: %w", err)` 包装）。
3. 每个提交信息使用中文或英文均可，需清晰说明动机。
4. 提交须包含 **DCO 签名**（`git commit -s`）。**请勿在开源核心中提交任何 Pro / 付费功能实现。**
5. 提交 PR，描述：改了什么、为什么、验证方式。

## 代码规范（Go）

- 构造函数 `NewX(...)` 返回指针；所有 I/O 方法接受 `context.Context`
- 错误必须包装：`fmt.Errorf("redact request: %w", err)`
- 不吞错（禁止空 `catch`/忽略 error）
- 新增行为需配套单元测试（stdlib `testing`，无需第三方断言库）
- 改动 CLI 命令或 `pkg/config` 的键时，同步更新文档并让 `scripts/check-docs.sh` 通过

## 安全披露

**请勿**通过公开 issue 报告漏洞。请邮件联系维护者（地址待补），或在私有安全渠道披露，并在修复发布后再公开。
