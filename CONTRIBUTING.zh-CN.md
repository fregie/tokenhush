# 为 Tokenhush 贡献

[English](CONTRIBUTING.md) | **中文**

> 状态：V1 核心已作为 `v0.1.0` 发布。欢迎提交 bug 报告、文档、测试和内容插件。

感谢你帮助让 AI 编码工具更安全。这里是 Apache-2.0 公开核心。

## 当前优先级

V1 核心已在 Windows、Linux 和 macOS 上实现（`run` / `status` / `env` / `doctor` / `version`）。目前最有价值的贡献：

- 关于各 AI 工具如何通过 base URL 连接的反馈，以及你遇到的坑（见 `docs/configuration.zh-CN.md`）。
- 漏报脱敏（假阴性）和过度脱敏（假阳性）的报告，以及安全和隐私风险。
- 审阅 `docs/architecture.zh-CN.md`、`docs/security.zh-CN.md` 和 `docs/plugins.zh-CN.md`。
- 内容插件（Inspector / Transformer，见 `docs/plugins.zh-CN.md`）。

## 本地开发

需要 Go 1.25 或更新版本。

```bash
go build ./...          # 构建
go vet ./...            # 静态分析
go test ./...           # 单元测试加端到端冒烟测试
bash scripts/check-docs.sh   # 校验文档与 CLI 和配置一致
```

> [!IMPORTANT]
> 不要向本仓库贡献任何 Pro 或付费功能的实现。Pro 代码位于单独的私有仓库；公开核心只包含开源实现。

## 提交流程

1. Fork 仓库并创建分支（`feat/...`、`fix/...`）。
2. 遵循项目约定（Go：`gofmt` / `golangci-lint`；用 `fmt.Errorf("context: %w", err)` 包装错误）。
3. 写清晰的提交信息。中文或英文均可；说明动机。
4. 用 DCO 对每个提交签名：`git commit -s`。
5. 提交 pull request，说明改了什么、为什么改、你如何验证。

> [!WARNING]
> 必须对提交签名。没有 DCO 签名的 pull request 不会被合并。

## 代码约定（Go）

- 构造函数 `NewX(...)` 返回指针；每个 I/O 方法都接受 `context.Context`。
- 用上下文包装错误：`fmt.Errorf("redact request: %w", err)`。
- 绝不吞掉错误：不要空分支，不要忽略错误值。
- 新行为需要单元测试（标准库 `testing`；不使用第三方断言库）。
- 当你修改 CLI 命令或 `pkg/config` 配置键时，更新文档并让 `scripts/check-docs.sh` 通过。
- 用 `gofmt` 格式化，并保持 `golangci-lint` 干净。

## 许可边界

公开核心以 Apache-2.0 发布。付费和企业能力在另一个导入本模块的私有仓库中实现。为保持两层清晰隔离：

- 不要向本仓库贡献任何 Pro 或付费功能的实现、算法或开关。
- 核心依赖只保留宽松许可（MIT、Apache-2.0、BSD）。不允许 GPL 和 AGPL，因为它们会污染闭源 Pro 层。

## 安全披露

> [!CAUTION]
> 不要通过公开 issue 报告漏洞。

请通过仓库主页列出的联系方式或其他私密渠道向维护者私密报告。我们会协调修复，并且只有在某个发行版包含修复后才公布细节。
