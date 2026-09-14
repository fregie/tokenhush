# 为 Tokenhush 贡献

[English](CONTRIBUTING.md) | **中文**

> 状态：V1 核心已发布，版本 `v0.1.0`。欢迎提交 bug 报告、文档、测试和内容插件。

感谢你让 AI 编程工具更安全。这里是 Apache-2.0 公开核心。

## 🎯 当前优先级

V1 核心（`run` / `status` / `env` / `doctor` / `version`）已在 Windows、Linux 和 macOS 上实现。目前最值得做的：

- 反馈各 AI 工具通过 base URL 连接的情况，以及你踩过的坑（见 `docs/tool-setup.zh-CN.md`）。
- 报告漏报脱敏（假阴性）和过度脱敏（假阳性），以及其他安全和隐私风险。
- 审阅 `docs/architecture.zh-CN.md`、`docs/security.zh-CN.md` 和 `docs/plugins.zh-CN.md`。
- 编写内容插件（Inspector / Transformer，见 `docs/plugins.zh-CN.md`）。

## 🏗️ 本地开发

需要 Go 1.25 或更新版本。

```bash
go build ./...          # 构建
go vet ./...            # 静态分析
go test ./...           # 单元测试加端到端冒烟测试
bash scripts/check-docs.sh   # 校验文档与 CLI 和配置是否一致
```

> [!IMPORTANT]
> 不要在本仓库提交任何 Pro 或付费功能的实现。Pro 代码放在单独的私有仓库；公开核心只包含开源实现。

## 🤝 提交流程

1. Fork 仓库并新建分支（`feat/...`、`fix/...`）。
2. 遵守项目约定（Go：`gofmt` / `golangci-lint`；用 `fmt.Errorf("context: %w", err)` 包装错误）。
3. 写清提交信息（中英文都行），说明为什么改。
4. 用 DCO 给每个提交签名：`git commit -s`。
5. 发起 pull request，说明改了什么、为什么改、你怎么验证。

> [!WARNING]
> 提交必须签名。没有 DCO 签名的 pull request 不会被合并。

## 📌 代码约定（Go）

- `NewX(...)` 返回指针；每个 I/O 方法都接收 `context.Context`。
- 用上下文包装错误：`fmt.Errorf("redact request: %w", err)`。
- 绝不吞掉错误：不写空分支，不忽略错误值。
- 新行为要配单元测试（标准库 `testing`；不引入第三方断言库）。
- 改动 CLI 命令或 `pkg/config` 配置键时，同步更新文档，并让 `scripts/check-docs.sh` 通过。
- 用 `gofmt` 格式化，保持 `golangci-lint` 无告警。

## 📄 许可边界

核心采用 Apache-2.0。付费和企业能力由另一个私有仓库发布，该仓库导入本模块。为把两层分干净：

- 不要提交任何 Pro 或付费功能的实现、算法或开关。
- 核心依赖只用宽松许可（MIT、Apache-2.0、BSD）。禁用 GPL 和 AGPL，否则会污染闭源 Pro 层。

## 🛡️ 安全披露

> [!CAUTION]
> 不要通过公开 issue 报告漏洞。

请通过仓库主页的联系方式，或其他私密渠道，私下报告给维护者；支持版本、私密报告渠道与响应时间见 [SECURITY.md](SECURITY.md)（英文）。我们会协调修复，等某个发行版包含修复后再公布细节。
