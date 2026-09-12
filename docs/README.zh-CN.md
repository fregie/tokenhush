# Tokenhush 文档

[English](README.md) | **中文**

> Status: V1（2026-09）。如果你正在了解全貌，从这里开始；下方每个链接都指向一份专题文档。路径与陈述与 `v0.1.0` 发行版和 `main` 一致。

Tokenhush 是一个本地基础 URL 网关：你的 AI 编程工具将请求发送到 `http://127.0.0.1:8787`，网关在将请求转发到上游之前对密钥和敏感数据脱敏，然后把仅元数据的审计事件转发到一个接缝（具体存储位于私有 Pro 层）。一切都在你的机器上运行，公开核心从不安装根证书或执行 MITM。这些文档涵盖如何安装和运维它、它如何构建，以及如何扩展它。

## 文档

| 文档 | 内容 |
|---|---|
| [deployment.zh-CN.md](deployment.zh-CN.md) | 在 macOS、Linux 和 Windows 上安装；首次运行；前台标志；由操作系统管理的后台运行；目录；升级与卸载；故障排查 |
| [configuration.zh-CN.md](configuration.zh-CN.md) | 各工具配置（Claude Code、Codex、Aider、Cline、Roo、Continue、Open WebUI）与 `tokenhush.yaml` 参考 |
| [architecture.zh-CN.md](architecture.zh-CN.md) | 请求路径、模块布局、审计接缝与开源核心边界 |
| [security.zh-CN.md](security.zh-CN.md) | 威胁模型、硬性不变量、检测器取舍与披露 |
| [plugins.zh-CN.md](plugins.zh-CN.md) | 编写内容插件（Inspector / Transformer） |
| [extension-api.zh-CN.md](extension-api.zh-CN.md) | 跨层扩展点（Router、CostSink、AuditExporter）与注册契约 |
| [migration-v0.2.0.zh-CN.md](migration-v0.2.0.zh-CN.md) | 从 v0.1.x 迁移：审计能力已移至 Pro 层 |
| [../CONTRIBUTING.zh-CN.md](../CONTRIBUTING.zh-CN.md) | 构建、测试与贡献流程，包括私有漏洞披露流程 |

## 建议阅读路径

**新用户。** 阅读 [deployment.zh-CN.md](deployment.zh-CN.md) 以安装并启动网关，然后阅读 [configuration.zh-CN.md](configuration.zh-CN.md) 将工具指向它。如果你只运行 Claude Code，[../README.zh-CN.md](../README.zh-CN.md) 中的快速开始就足够了。

**运维者。** 阅读 [security.zh-CN.md](security.zh-CN.md) 了解不变量与威胁模型，然后阅读 [deployment.zh-CN.md](deployment.zh-CN.md) 第 5 节了解控制 token 和会话文件的位置，第 10 节了解部署约束。

**集成者。** 阅读 [architecture.zh-CN.md](architecture.zh-CN.md) 了解请求路径，然后阅读 [extension-api.zh-CN.md](extension-api.zh-CN.md) 和 [plugins.zh-CN.md](plugins.zh-CN.md) 以添加路由器、成本接收器、审计导出器或内容插件。
