# 参与 Tokenhush 贡献

**中文** | [English](CONTRIBUTING.md)

Tokenhush 是公开的 Apache-2.0 内核，仅以英文维护。欢迎提交 bug 报告、文档、测试与新规则。

Pro 与企业版层位于一个单独的私有仓库，它导入本 Go module。不要在这里贡献付费功能的代码、算法或门控开关。

## 环境要求

- Go 1.25 或更高版本。`go.mod` 钉住 `go 1.25.0`。
- `git`。
- 可选：`golangci-lint` 与 `gitleaks`，用于在本地跑下面 CI 步骤的等价物。

## 构建与测试

```sh
go build ./...                          # build every package
go build -o tokenhush ./cmd/tokenhush   # build the binary
go test ./...                           # unit, invariant, and guard tests
go vet ./...                            # static analysis
./tokenhush version                     # confirm the binary runs
```

项目是纯 Go，以 `CGO_ENABLED=0` 构建。发布矩阵为 macOS arm64、Linux amd64 与 Windows amd64。

## CI 会运行什么

`.github/workflows/ci.yml` 运行以下步骤。在开 pull request 之前先在本地复现它们：

```sh
go build ./...
go vet ./...
go test ./... -count=1
golangci-lint run
bash scripts/check-layering.sh
TOKENHUSH_GUARD_FULL_GRAPH=1 go test ./internal/guards/... ./internal/layering/... -count=1
```

- `golangci-lint` 读取 `.golangci.yml`：`errcheck`、`govet`、`staticcheck`、`ineffassign`、`nilnil`、`errorlint` 与 `unused`。
- `bash scripts/check-layering.sh` 从仓库根目录运行与 `internal/layering` 包相同的依赖图检查。
- 全图步骤导出 `TOKENHUSH_GUARD_FULL_GRAPH=1`，它会把缺失的预期包或缺失的必需依赖边变成失败。这是同一批守卫的严格模式。
- 另一个独立 job 用 `CGO_ENABLED=0` 交叉构建 darwin/arm64、linux/amd64 与 windows/amd64。
- `secret scan` job 用 `.gitleaks.toml` 里的仓库规则集运行 gitleaks。如果你装了 gitleaks，也在本地跑一遍；绝不把真实的密钥、token 或凭据提交进代码树，包括 fixture 与测试数据。

## 你的改动必须遵守的不变量

这些由测试强制，而不是靠代码评审的礼节。破坏其中一条的改动会让 CI 失败。

1. **每个生产 Go 文件 250 纯 LOC。** `internal/guards/size_guard_test.go` 统计严格的纯 LOC：空行与仅含注释的行不计，其余每一行都计，包括单独一个右花括号。上限是 250。超限的文件要被拆分，而不是被豁免。测试文件、`testdata/`、生成文件与 vendored 代码不在范围内。
2. **依赖只朝一个方向。** `internal/layering` 与 `scripts/check-layering.sh` 强制允许的包依赖图。没有环，同级包之间也互不深入。`pkg/filter` 与 `pkg/redact` 是同级包，`internal/cli` 是唯一把各包装配成产品的装配器。
3. **CLI 表面是冻结的。** 恰好七个命令：`run`、`rules`、`update`、`status`、`env`、`version`、`privacy`。退出码冻结为 `0`（成功）、`1`（某项检查或操作失败）与 `2`（用法错误）。`internal/guards/docs_guard_test.go` 从 `internal/cli` 读取注册项，出现第八个命令即失败。新增命令是产品决策，不是随手接错线。
4. **文档树是冻结的，且必须与真实 CLI 一致。** `docs/` 只容纳已知的文件集合，且文档记录的命令集必须等于注册的命令集。同一个守卫强制这两点。行为变更要在同一次改动里更新文档。
5. **`pkg/filter` 导出的 `Rule` 接口是冻结的。** `internal/guards/shape_guard_test.go` 钉住它的八个方法（`ID`、`Type`、`Category`、`Scope`、`Action`、`Priority`、`Confidence`、`Inspect`），并拒绝第二个导出的扩展接口。通过规则来扩展，而不是拓宽契约。
6. **永不提供证书安装路径。** `internal/guards/absence_guard_test.go` 扫描生产 Go 源码中的 TLS 终止、根证书与信任库形状，一旦出现即失败。Tokenhush 不安装根证书、不终止 TLS，也不改动信任库。需要其中任何一项的改动都会被拒绝。
7. **绝不持久化请求或响应明文。** `internal/guards/ondisk_guard_test.go` 驱动真实二进制，并扫描一次运行可能写入的一切。磁盘上只允许元数据：会话文件、规则缓存与防回滚标记。body、检测到的密钥以及占位符到密钥的映射都留在内存中。脱敏日志经过掩码、只写 stderr，且永不持久化。

还有一条规则是结构性的，而不是单个守卫：在响应路径上，规则只能 `Block` 或 `Warn`，而 `redact` 仅限请求路径。作用域包含响应的 `redact` 规则会在编译期与注册期两处被拒绝。保持这个方向契约完整。完整安全模型与残余风险清单见 [docs/security.zh-CN.md](docs/security.zh-CN.md)。

## Pull request

- 保持改动小而聚焦。一个 pull request 只做一种行为，胜过一大杂烩。
- 每个行为变更都要新增或更新测试。`TestInvariant*` 名字是安全契约的一部分，不要随手改名。
- 让每个守卫保持绿色。守卫失败时，修它检查的代码或文档。不要在未于 pull request 中说明原因的情况下放松守卫。
- 使用约定式提交：`feat(scope):`、`fix(scope):`、`docs(scope):`、`test(scope):`。在正文里解释为什么。
- 绝不提交密钥、token 或真实凭据。gitleaks 在 CI 中用 `.gitleaks.toml` 运行。
- 在 pull request 描述里说明改了什么、为什么改，以及你如何验证。

## 依赖

- 新增依赖需要理由。module 依赖图刻意保持很小。
- 不允许任何 copyleft 依赖进入 module 依赖图：GPL、LGPL 与 AGPL 都在禁止之列，且 `go.mod` 里的每个依赖都必须暴露可验证的许可证。

## 先读什么

- [docs/architecture.zh-CN.md](docs/architecture.zh-CN.md)：分层依赖图、单一规则抽象、数据路径与冻结的 CLI。
- [docs/security.zh-CN.md](docs/security.zh-CN.md)：八条不变量、响应阶段的效应与七项残余风险。
- [docs/plugins.zh-CN.md](docs/plugins.zh-CN.md)：`Rule` 扩展点、它的注册语义与一个完整示例。
- [docs/tool-setup.zh-CN.md](docs/tool-setup.zh-CN.md)：逐工具接入、请求路由与 `tokenhush.yaml` 参考。

## 扩展 Tokenhush

扩展点恰好只有一个：`pkg/filter` 里的 `Rule` 接口。内置检测器、签名远程包里的规则，以及第三方从自己包里编译进来的规则，都经由同一个公共注册表到达，并以同一个确定性顺序求值。

本版本中插件仅限编译期。插件就是一个普通的 Go 包，被编译进导入它的二进制。没有运行时插件加载，没有 WASM，没有共享对象，也没有子进程。[docs/plugins.zh-CN.md](docs/plugins.zh-CN.md) 有契约、注册语义与响应阶段限制。

## 许可证

贡献按 Apache License 2.0 接受。见 [LICENSE](LICENSE)。
