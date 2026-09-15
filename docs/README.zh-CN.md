# Tokenhush 文档

[English](README.md) | **中文**

> 状态：V1（2026-09）。先看这里；下方每个链接对应一份专题文档。路径与说明与 `v0.4.0` 发行线和 `main` 保持一致。

Tokenhush 是一个本地基础 URL 网关。把 AI 编程工具指向 `http://127.0.0.1:8787`，它先给密钥和敏感数据脱敏，再转发到上游。一切都在你自己的机器上运行。公开核心从不安装根证书，也不做 MITM。

## 📚 文档

| 文档 | 内容 |
|---|---|
| [deployment.zh-CN.md](deployment.zh-CN.md) | 在 macOS、Linux 和 Windows 上安装；首次运行；前台标志；交给操作系统后台运行；目录；升级与卸载；故障排查 |
| [tool-setup.zh-CN.md](tool-setup.zh-CN.md) | 各工具配置（Claude Code、Codex、Aider、Cline、Roo、opencode、Qwen Code、Charm Crush、Zed、Continue.dev、Open WebUI、Goose、OpenHands、Kilo Code）：配置写在哪、填什么值、如何不覆盖现有配置地合并、如何验证与还原，另附路由可达性矩阵与 `tokenhush.yaml` 参考 |
| [architecture.zh-CN.md](architecture.zh-CN.md) | 请求路径、模块布局与开源核心边界 |
| [security.zh-CN.md](security.zh-CN.md) | 威胁模型、硬性不变量、检测器取舍与披露 |
| [verify.zh-CN.md](verify.zh-CN.md)（[English](verify.md)） | 在本机自己验证脱敏：回环回显上游展示离开的占位符与回来的原值 |
| [plugins.zh-CN.md](plugins.zh-CN.md) | 编写内容插件（Inspector / Transformer） |
| [extension-api.zh-CN.md](extension-api.zh-CN.md) | 跨层扩展点与注册契约 |
| [../CONTRIBUTING.zh-CN.md](../CONTRIBUTING.zh-CN.md) | 构建、测试与贡献流程，包括私有漏洞披露流程 |
| [../SECURITY.md](../SECURITY.md) | 漏洞披露政策：支持版本、私密报告渠道与响应时间（英文） |

## 📚 建议阅读路径

**新用户。** 先读 [deployment.zh-CN.md](deployment.zh-CN.md) 装好并启动，再读 [tool-setup.zh-CN.md](tool-setup.zh-CN.md) 连上工具。如果你只用 Claude Code，[../README.zh-CN.md](../README.zh-CN.md) 里的快速开始就够了。

**运维者。** 先读 [security.zh-CN.md](security.zh-CN.md) 搞清不变量和威胁模型，再读 [deployment.zh-CN.md](deployment.zh-CN.md) 第 5 节（控制 token、会话文件）和第 10 节（部署约束）。

**集成者。** 先读 [architecture.zh-CN.md](architecture.zh-CN.md) 了解请求路径，再读 [extension-api.zh-CN.md](extension-api.zh-CN.md) 和 [plugins.zh-CN.md](plugins.zh-CN.md) 添加路由器、成本接收器或内容插件。
