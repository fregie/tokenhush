# 迁移到 v0.3.0

[English](migration-v0.3.0.md) | **中文**

> 状态：适用于 `v0.3.0` 核心发行版。从 `v0.2.0` 升级**无需修改配置**。

## 变更内容

- **共享装配层（`pkg/gateway`）。** 请求路径的装配——双栈环回监听器、每会话控制 token 与 `run.json`、Host 允许列表与按请求统计的中间件链、数据面、有界优雅关闭——从 `internal/cli` 移入导出的 `pkg/gateway` 包。CLI（`tokenhush run`）行为不变；私有 Pro 构建在同一装配层上落地。契约见 [extension-api.zh-CN.md](extension-api.zh-CN.md)。
- **`GET /v1/models` 成为具名例外。** 此前它是未知路径，返回类型化错误；现在默认走 OpenAI：模型发现不携带提示词或载荷，且两家 provider 暴露相同的形状。配置的 `upstreams:` 覆盖仍然优先；其他所有未知路径——包括 `/v1/model`、`/v1/models/foo` 这类近似路径——仍是显式错误。见 [security.zh-CN.md](security.zh-CN.md)。
- **`tokenhush env` 覆盖 14 个工具。** 新增 9 个片段：`opencode`、`qwen`、`crush`、`zed`、`continue`、`openwebui`、`goose`、`openhands`、`kilo`；原有 5 个为 `claude`、`codex`、`aider`、`cline`、`roo`。见 [configuration.zh-CN.md](configuration.zh-CN.md)。

## 无需修改配置

`tokenhush.yaml` 的键自 `v0.2.0` 起未变：`listen`、`detectors`、`allowlist`、`log`、`upstreams`。照常安装并启动：

```bash
tokenhush run
```

如果你仍在 `v0.1.x`，请先删除已移除的 `audit:` 块再启动 `v0.3.0`；见 [migration-v0.2.0.zh-CN.md](migration-v0.2.0.zh-CN.md)。

## 发布说明（GitHub Release v0.3.0）

推送 `v0.3.0` 标签会自动发布 GitHub Release。建议要点：

- **新增**：共享 `pkg/gateway` 装配层，导出给私有 Pro 构建使用。
- **更改**：`GET /v1/models` 是唯一的具名路由例外，默认走 OpenAI；其余未识别路径仍是显式的类型化错误。
- **新增**：`tokenhush env` 支持另外 9 个工具（`opencode`、`qwen`、`crush`、`zed`、`continue`、`openwebui`、`goose`、`openhands`、`kilo`）。
- **未变**：配置键、CLI 命令、审计接缝、硬不变量以及扩展 API 的其余部分。

## 参见

- [extension-api.zh-CN.md](extension-api.zh-CN.md)：`pkg/gateway` 装配契约。
- [security.zh-CN.md](security.zh-CN.md)：具名路由例外与硬不变量。
- [configuration.zh-CN.md](configuration.zh-CN.md)：各工具接入与 `tokenhush.yaml` 参考。
