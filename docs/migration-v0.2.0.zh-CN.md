# 迁移到 v0.2.0

[English](migration-v0.2.0.md) | **中文**

> 状态：适用于 `v0.2.0` 核心发行版。升级 `v0.1.x` 安装前请先读本文。

## 变更内容

`v0.2.0` 把具体的审计实现从公开核心移到了私有 Pro 层。核心只保留审计接缝：

- `pkg/audit` 仍定义 `Record` 和 `Query` 类型、`AuditSink` / `AuditQuerier` 接口，以及一个 no-op sink。
- 代理和插件策略引擎仍通过注入的 `AuditSink` 发出仅含元数据的审计记录；核心默认 sink 直接丢弃。
- 核心不再包含：
  - 本地审计存储（持久化、防篡改 HMAC 链、保留策略）；
  - `tokenhush audit` 子命令；
  - `GET /audit` 控制端点；
  - `audit:` 配置块。

具体存储、子命令、端点和审计配置都由私有 Pro 层负责。接口公开不等于实现公开：公开二进制里没有审计存储，也就没有可解锁的东西。

诚实的产品宣称不变：**“高置信密钥拦截 + 全程可审计”**，绝不写成“永不泄露”。

## 必须修改的配置

从 `tokenhush.yaml` 中删除 `audit:` 块。块写法和内联写法都会被拒绝：

```yaml
# 在 v0.2.0 中删除这一块
audit:
  enabled: true
  retention_days: 14
```

```yaml
# 内联写法同样会被拒绝：
audit: {enabled: true}
```

迁移就两步：删掉这个块，再重启网关。

```yaml
# 改前：tokenhush.yaml
audit: {enabled: true}   # <-- 删掉这一行
listen:
  port: 8787
```

```yaml
# 改后：tokenhush.yaml
listen:
  port: 8787
```

```bash
tokenhush run   # 重启，配置即可正常加载
```

如果保留该键，`tokenhush run` 以及所有加载配置的命令都会在启动时失败，报 `unknown field` 错误，并给出指明该键、指向 Pro 层的可操作提示。删掉这个块再启动网关即可。其余键（`listen`、`detectors`、`allowlist`、`log`、`upstreams`）不变。

## 数据不迁移

已有审计数据不会迁移。`v0.2.0` 不读取、不转换、不复制 `v0.1.x` 的本地审计数据库，核心也不再打开它。把这次升级当成一次干净的切换：需要旧数据，就在升级前自行导出或归档。

## Pro 中的审计

具体审计能力（持久化、防篡改链、保留策略、查询命令、端点和配置）位于私有 Pro 层，该层导入本核心模块。安装、运维，以及如何重新启用审计，请看该层自己的文档。

## 发布说明（GitHub Release v0.2.0）

推送 `v0.2.0` 标签会自动发布 GitHub Release。建议要点：

- **破坏性变更：** 移除了 `audit:` 配置块；仍包含它的配置会因迁移错误而加载失败。请在升级前删掉该块。
- **破坏性变更：** 从公开核心移除了 `tokenhush audit`、`GET /audit` 控制端点和本地审计存储。
- **变更：** 核心现在只暴露仅含元数据的审计接缝（`pkg/audit` 类型以及 `AuditSink` / `AuditQuerier` 接口），默认 no-op。
- **注意：** 已有本地审计数据不迁移。
- 具体审计实现现在随私有 Pro 层发布。
- 其余内容（`run`、`status`、`env`、`doctor`、`version`、脱敏、检测器和扩展 API）不变。

## 另见

- [configuration.zh-CN.md](configuration.zh-CN.md)：`tokenhush.yaml` 参考。
- [architecture.zh-CN.md](architecture.zh-CN.md)：接缝与开源核心边界。
- [security.zh-CN.md](security.zh-CN.md)：审计接缝与完整性模型。
