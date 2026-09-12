# 迁移到 v0.2.0

[English](migration-v0.2.0.md) | **中文**

> 状态：适用于 `v0.2.0` 核心发行版。在升级 `v0.1.x` 安装之前请先阅读本文。

## 变更内容

在 `v0.2.0` 中，具体的审计实现已从公开核心移出，进入私有 Pro 层。核心只保留审计接缝：

- `pkg/audit` 仍定义 `Record` 和 `Query` 类型，以及 `AuditSink` / `AuditQuerier` 接口和一个 no-op sink。
- 代理与插件策略引擎仍通过注入的 `AuditSink` 发出仅元数据的审计记录；核心默认 sink 会丢弃它们。
- 核心不再包含：
  - 本地审计存储（持久化、防篡改 HMAC 链、保留策略）；
  - `tokenhush audit` 子命令；
  - `GET /audit` 控制端点；
  - `audit:` 配置块。

私有 Pro 层拥有具体存储、审计子命令、审计端点和审计配置。接口公开并不意味着实现公开：公开二进制中不包含任何审计存储，因此不存在可供解锁的实现。

诚实的产品宣称保持不变：**“高置信密钥拦截 + 全程可审计”**，绝不使用“永不泄露”。

## 必须修改的配置

从 `tokenhush.yaml` 中删除 `audit:` 块。块写法与内联写法都会被拒绝：

```yaml
# 在 v0.2.0 中删除此块
audit:
  enabled: true
  retention_days: 14
```

```yaml
# 同样会被拒绝：
audit: {enabled: true}
```

如果保留该键，`tokenhush run` 以及所有会加载配置的命令都会在启动时失败，抛出 `unknown field` 错误，并给出指明该键、指向 Pro 层的可操作提示。删除该块后重新启动网关即可。其余键（`listen`、`detectors`、`allowlist`、`log`、`upstreams`）保持不变。

## 数据不迁移

已有审计数据不会迁移。`v0.2.0` 不读取、不转换、不复制 `v0.1.x` 的本地审计数据库，核心也不再打开它。把这次升级视为一次干净的切换：如果需要旧数据，请在升级前自行导出或归档。

## Pro 中的审计

具体审计能力（持久化、防篡改链、保留策略、查询命令、审计端点和审计配置）位于导入本核心模块的私有 Pro 层。安装、运维以及如何重新启用审计，请参见该层自己的文档。

## 发布说明（GitHub Release v0.2.0）

推送 `v0.2.0` 标签会自动发布 GitHub Release。建议要点：

- **破坏性变更：** 移除了 `audit:` 配置块；仍包含它的配置会因迁移错误而加载失败。请在升级前删除该块。
- **破坏性变更：** 从公开核心移除了 `tokenhush audit`、`GET /audit` 控制端点和本地审计存储。
- **变更：** 核心现在只暴露仅元数据的审计接缝（`pkg/audit` 类型以及 `AuditSink` / `AuditQuerier` 接口），默认 no-op。
- **注意：** 已有本地审计数据不迁移。
- 具体审计实现现在随私有 Pro 层发布。
- 其余内容（`run`、`status`、`env`、`doctor`、`version`、脱敏、检测器和扩展 API）保持不变。

## 另见

- [configuration.zh-CN.md](configuration.zh-CN.md)：`tokenhush.yaml` 参考。
- [architecture.zh-CN.md](architecture.zh-CN.md)：接缝与开源核心边界。
- [security.zh-CN.md](security.zh-CN.md)：审计接缝与完整性模型。
