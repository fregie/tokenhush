# 更新日志

本文件记录公开版 Tokenhush 核心的所有重要变更。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **关于版本线的说明。** `v0.1.0`–`v0.4.0` 这些 tag 属于重写之前的旧代码线，
> 不在此记录。本仓库是从零重写的核心，其历史从 `v0.5.0` 开始。

## [0.7.1] - 2026-09-22

### 新增

- **请求体积守卫。** 新增 `max_body_bytes` 配置项（默认 `67108864`，64 MiB），
  约束请求体总量。超限的请求体在共享读取接缝处以 `403 body_too_large` 拒绝，
  发生在任何遍历或上游拨号之前，绝不截断、也绝不部分转发。
- **仅含元数据的拒绝日志。** 网关本地生成的每个请求侧拒绝现在恰好向 stderr 写
  一行 `tokenhush: refused request <code>`，只携带封闭的拒绝词汇：拒绝码，以及
  该拒绝本已携带的分类 `reason=` 或 `rule_id=`。
- **高精度密钥规则文档。** `rules/high-precision-secrets.json` 增加高精度厂商密钥
  模式（AWS、GCP 及其他服务商令牌形态）。

### 变更

- `scan_budget_bytes` 现在严格为逐叶、逐检测器语义：原始类型检测器对单个叶子最多
  检查这么多字节。原先的聚合扫描预算拒绝（`scan_budget_exceeded`）已移除；超过
  总量的请求体改由 `max_body_bytes` 拒绝。
- 脱敏日志现在会报告 `private_key` 命中的 PEM 头类型（例如 `RSA PRIVATE KEY`），
  对 `email` 命中只暴露域名（例如 `****@example.com`）。PEM 头类型取自固定白名单
  字面量，因此捕获到的头部文本绝不会被回显。
- README 首屏品牌区刷新。

## [0.7.0] - 2026-09-20

### 新增

- **敏感键（sensitive_keys）。** 规则文档或签名规则包可声明 `sensitive_keys`
  （最多 256 个键名，`case_sensitive` 默认 false）；命中的直接对象成员键（例如
  `password`）其值会在请求路径上被脱敏，对象深度不限。
- **整响应缓冲。** 完整响应（含 SSE）在任何字节提交前被整体缓冲，受
  `response_buffer_bytes`（默认 32 MiB，超限返回 `502`）与 `response_timeout`
  （默认 5m，超时返回 `504`）约束。
- protocol：JSON 字符串叶的通道标识与对象成员键捕获，并补充标量成员捕获的模糊
  测试种子。
- redact：持有至解析（hold-until-parse）的叶通道占位符重组。

### 变更

- 响应路径：缓冲式 SSE 的求值与还原；敏感键渲染接入签名包路径。

### 修复

- redact：carry 分支前缀长度计入联合上界；任意合法 JSON 事件前无条件交接原始
  尾字节；联合持有上界与中止/冲刷生命周期复位；SSE 信封内容分割处理。
- CLI 与 filter：F2 复审的阻断项与门控调用时机；`golangci-lint` v2 报告的三处
  问题。

### 文档

- `docs/security.md`：敏感键、整响应缓冲、重写的 R6 行，以及 SSE 还原延迟契约。

## [0.6.0] - 2026-09-19

### 新增

- **默认启用精确 email 检测器**，按地址域名的公共后缀参数化。
- **逐检测器规则选项（rule options）**，严格解码与校验。当前唯一选项是
  `email`：`suffixes` 扩充内置后缀集，`replace` 将其替换；仅限本地文档，
  远程规则包会被 floor 拒绝。
- 签名规则包可携带规则选项；编译后的规则通过逐规则匹配器分发。
- 分层 `AGENTS.md` 知识库。

### 变更

- 文档树守卫允许 `docs/AGENTS.md` 作为智能体元数据存在。

## [0.5.1] - 2026-09-18

### 新增

- 六平台交叉构建发布矩阵（macOS、Linux、Windows × `arm64`/`amd64`）；版本在发布
  时由 git tag 注入。
- 启动横幅与响应侧还原日志。
- README、参考文档、egress 披露、Pro 迁移说明、`CONTRIBUTING` 与 `SECURITY` 的
  中文（`*.zh-CN.md`）孪生版。

### 变更

- 固定 `golangci-lint` v2 并清理其报告；`gitleaks` allowlist 覆盖合成样本与
  占位符语法。
- 安装器与部署文档反映已发布的六平台版本。

## [0.5.0] - 2026-09-18

从零重写的核心：仅回环监听的网关，七命令 CLI，六个检测器，签名规则同步，签名
自更新，以及守卫测试套件。

### 新增

- **CLI：** `run`、`rules`、`update`、`status`、`env`、`version`、`privacy`
  （冻结的动词集，退出码 `0`/`1`/`2`）。
- **Proxy：** 仅回环监听器；Host、Origin 与控制令牌守卫；绝不误路由的解析器；
  对压缩/不可遍历请求体 fail-closed；SSE 回填；仅元数据的控制 API。
- **Supply：** Ed25519 签名基座；密钥列表轮换与撤销；原子 serial 高水位存储；
  带 OD 门控的签名规则同步；崩溃安全的签名自更新。
- **Redact：** 确定性占位符铸造与仅入站回填；规范化 SSE 重组器；感知
  JSON 转义深度的还原。
- **安装：** 校验 sha256 的 Linux 与 Windows 安装器；tag 触发的 GoReleaser 流水线。
- **文档与守卫：** 参考文档、双语文档集，以及结构化守卫测试套件。

[未发布]: https://github.com/fregie/tokenhush/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/fregie/tokenhush/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/fregie/tokenhush/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/fregie/tokenhush/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/fregie/tokenhush/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/fregie/tokenhush/releases/tag/v0.5.0
