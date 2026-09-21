# 部署

**中文** | [English](deployment.md)

Tokenhush 是一个在前台运行的单文件二进制。本页介绍如何构建或安装它、它把配置与
数据放在哪里、如何用操作系统自带的工具让它持续运行，以及当前的发布状态究竟是
什么。

## 安装

| 平台 | 一行安装 |
|---|---|
| macOS | `brew install --cask fregie/tap/tokenhush` |
| Linux | `curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh \| bash` |
| Windows | `irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 \| iex` |

Linux 与 Windows 的安装脚本会下载对应的发布压缩包，用发布页的 `checksums.txt` 校验
sha256，再把二进制装进用户目录，无需管理员权限，也不依赖包管理器：

| 平台 | 默认安装目录 | 覆盖方式 |
|---|---|---|
| Linux | `~/.local/bin` | `TOKENHUSH_INSTALL_DIR` 或 `--dir` |
| Windows | `%LOCALAPPDATA%\Programs\tokenhush` | `TOKENHUSH_INSTALL_DIR` 或 `-Dir` |

两者都接受固定版本（`--version X.Y.Z` / `-Version X.Y.Z`），以及下载并校验但不安装的
`--dry-run` / `-DryRun` 模式。

安装脚本会下载你所在平台的已发布二进制，并用发布页的 `checksums.txt` 校验。默认运行
会拒绝低于最低线的已发布版本，改为从源码构建当前线；见[发布状态](#发布状态)。

### 从源码构建

需要 Go 1.25 或更新版本：

```sh
go build -o tokenhush ./cmd/tokenhush
./tokenhush version
```

`tokenhush version` 打印版本、目标操作系统与架构、Go 工具链、提交号与构建时间。

### `go install`

```sh
go install github.com/fregie/tokenhush/cmd/tokenhush@main
```

当前代码线用 `@main`。`@latest` 仍解析到更早的已发布 tag，给不了你从零重写的版本。

### 放进 `PATH`

这些文档里的示例直接调用 `tokenhush`。如果 `go install` 把二进制装在了 `PATH` 覆盖
不到的地方，把那个目录加进去，例如 `$HOME/go/bin`。或者把构建出的二进制移到已在
`PATH` 上的目录，比如 macOS 与 Linux 上的 `/usr/local/bin`。

## 平台矩阵

Tokenhush 是纯 Go 实现，以 `CGO_ENABLED=0` 构建，所以二进制没有 C 依赖，可以干净地
交叉编译。固定的目标集合是：

| 操作系统 | 架构 |
|---|---|
| macOS | arm64、amd64 |
| Linux | arm64、amd64 |
| Windows | arm64、amd64 |

`.goreleaser.yaml` 固定了这套构建矩阵以及 `checksums.txt` 制品，
`.github/workflows/release.yml` 在 `v*` tag 上构建并发布它们。

## 配置目录与数据目录

| 平台 | 配置目录 | 数据目录 |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/config/` | `~/Library/Application Support/tokenhush/Data/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LocalAppData%\tokenhush\` |

`TOKENHUSH_HOME` 会把两者移到一个根下：配置在 `<TOKENHUSH_HOME>/config`，数据在
`<TOKENHUSH_HOME>/data`。空值视为未设置。指向运行中可执行文件所在目录、或该目录
内部的 `TOKENHUSH_HOME` 会被拒绝，因为那里的数据目录可能变成可写代码。

数据目录只保存会话元数据：`run.json` 与 `control.token`，以及 `rules/` 下的规则缓存
和 `update/` 下的更新防回滚标记。请求与响应 body、检测到的密钥、占位符到密钥的映射
都永不落盘。完整的磁盘内容清单见 [security.zh-CN.md](security.zh-CN.md)。

## 运行它

在前台启动网关：

```sh
tokenhush run
```

它监听 `http://127.0.0.1:8787`，按 Ctrl-C 退出。常用 flag：`--config PATH`、
`--port N`（1..65535）、`--log-level debug|info|warn|error`，以及 `--log-redactions`
（默认开启；`--log-redactions=false` 会静默掩码的 stderr 行）。

**没有内置的服务命令。** Tokenhush 不安装、不管理、也不控制后台服务。若要让它跨
登录与重启持续运行，请用操作系统自带的服务工具包装 `tokenhush run`。下面的例子是
普通的 launchd、systemd 与任务计划程序配置；把二进制路径改成你实际安装的位置。

### macOS：launchd agent

创建 `~/Library/LaunchAgents/com.tokenhush.gateway.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.tokenhush.gateway</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/local/bin/tokenhush</string>
      <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
```

加载它：

```sh
launchctl load -w ~/Library/LaunchAgents/com.tokenhush.gateway.plist
```

### Linux：systemd user unit

创建 `~/.config/systemd/user/tokenhush.service`：

```ini
[Unit]
Description=Tokenhush loopback gateway
After=network.target

[Service]
ExecStart=%h/go/bin/tokenhush run
Restart=on-failure

[Install]
WantedBy=default.target
```

启用并启动它：

```sh
systemctl --user daemon-reload
systemctl --user enable --now tokenhush.service
```

### Windows：任务计划程序条目

注册一个在登录时启动网关的任务：

```powershell
schtasks /Create /TN Tokenhush /TR "C:\path\to\tokenhush.exe run" /SC ONLOGON
```

把 `/TR` 改成你机器上 `tokenhush.exe` 的完整路径。

## 发布状态

发行版已发布。`.goreleaser.yaml` 固定构建矩阵与校验和制品，
`.github/workflows/release.yml` 在 `v*` tag 上构建并发布它们，并在同一次运行中推送
Homebrew cask 与 Scoop manifest。

`install.sh` 与 `install.ps1` 会下载并校验对应平台的已发布二进制，无需 Go 工具链。
默认运行会拒绝低于 v0.5.0 重写基线的已发布版本；显式传 `--version` 才会安装旧版本。

## Tokenhush 在部署时绝不做的事

- 它绝不终止 TLS。没有证书监听器，也没有 MITM。
- 它不安装根证书，也不改动系统信任库。
- 它只绑定回环：始终 `127.0.0.1`，主机有 IPv6 回环时再加 `[::1]`。非回环绑定从
  构造上被拒绝。

## 另见

- [tool-setup.zh-CN.md](tool-setup.zh-CN.md)：把工具指向网关。
- [verify.zh-CN.md](verify.zh-CN.md)：本地 echo 上游检查。
- [generated/network-egress.zh-CN.md](generated/network-egress.zh-CN.md)：两个
  厂商绑定的出口类别。
- [security.zh-CN.md](security.zh-CN.md)：完整的安全模型。
