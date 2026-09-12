# 部署

[English](deployment.md) | **中文**

> 状态：V1（2026-09）。本指南涵盖发行版安装、首次运行，以及如何在操作系统服务管理器下运行网关。下文所有命令、标志、路径都与 V1 CLI 一致；`scripts/check-docs.sh` 会用构建出的二进制核对命令列表。

Tokenhush 以单个静态二进制形式分发。它没有运行时依赖，自身不带后台守护进程，也不安装根证书。安装后，你在前台启动它，然后把 AI 工具指向 `http://127.0.0.1:8787`。

## 1. 环境要求

| 要求 | 值 |
|---|---|
| 操作系统 | macOS、Linux、Windows |
| 架构 | amd64 或 arm64 |
| Go（仅从源码构建） | Go 1.25 或更新版本 |
| 网络 | 仅环回。网关绑定 `127.0.0.1` 和 `[::1]`。 |
| 磁盘 | 存放运行时会话文件的空间（核心不保留审计数据库） |

发行版二进制是纯 Go（`CGO_ENABLED=0`），因此无需 C 工具链即可运行。网关拒绝绑定 `0.0.0.0` 或空主机：只接受 `127.0.0.1`、`::1` 和 `localhost`。这是有意为之。网关是本地组件，不是网络服务。

## 2. 安装

### macOS（Homebrew cask）

```bash
brew install --cask fregie/tap/tokenhush
```

### Windows（Scoop）

```powershell
scoop bucket add fregie https://github.com/fregie/scoop-bucket
scoop install tokenhush
```

### Linux（install.sh）

```bash
curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh | bash
```

脚本会下载匹配你操作系统和架构的归档，用发行版的 `checksums.txt`（sha256）校验，默认把二进制安装到 `~/.local/bin`。如果校验和不匹配，它会拒绝安装。

| 标志 | 含义 |
|---|---|
| `--dry-run` | 下载并校验，但不安装 |
| `--version VERSION` | 安装指定版本，不带前导 `v` |
| `--dir PATH` | 目标目录（默认 `~/.local/bin`） |
| `--base-url URL` | 供镜像或测试使用的下载基础 URL（需要显式指定 `--version`） |

| 环境变量 | 含义 |
|---|---|
| `TOKENHUSH_VERSION` | 要安装的版本（默认：最新发行版） |
| `TOKENHUSH_INSTALL_DIR` | 目标目录（默认 `~/.local/bin`） |
| `TOKENHUSH_BASE_URL` | 供镜像或测试使用的下载基础 URL |

退出码为：成功 `0`，运行时失败 `1`，用法错误 `2`。当脚本输出 `note: ~/.local/bin is not on your PATH` 时，把该目录加入你的 shell 配置文件，让 `tokenhush` 能被解析到。Windows 不支持该脚本；请改用 Scoop。

### 从源码构建

需要 Go 1.25 或更新版本。

```bash
go install github.com/fregie/tokenhush/cmd/tokenhush@latest
```

或者，从本地检出构建：

```bash
go build -o bin/tokenhush ./cmd/tokenhush
```

`go install` 会把二进制放到 `$(go env GOPATH)/bin`，该目录必须在你的 `PATH` 上。

### 验证安装

每个发行版都会发布 `checksums.txt`（sha256）和每个归档的 SPDX SBOM。`install.sh` 会在安装前为你校验校验和；Homebrew 和 Scoop 会各自校验自己的产物。

要检查手动下载，把归档哈希与 `checksums.txt` 中对应行比对：

```bash
curl -fsSLO https://github.com/fregie/tokenhush/releases/latest/download/checksums.txt
sha256sum tokenhush_0.1.0_linux_amd64.tar.gz
grep tokenhush_0.1.0_linux_amd64.tar.gz checksums.txt
```

归档命名遵循 `tokenhush_<version>_<os>_<arch>.tar.gz`。在 macOS 上，`shasum -a 256 <archive>` 完成同样的事。

最后，确认二进制能运行：

```bash
tokenhush version
```

`version` 打印版本和构建信息，不接受任何标志。

> [!NOTE]
> macOS Homebrew 和 Windows Scoop 渠道在 `v0.1.0` 下仍在手动验证中。如果某个渠道安装失败，按上文从源码构建；`main` 携带相同的 V1 实现。

## 3. 首次运行

在前台启动网关：

```bash
tokenhush run
```

成功时它会打印监听地址和控制令牌文件：

```text
tokenhush: gateway listening on http://127.0.0.1:8787
tokenhush: control token file: <data-dir>/control.token
```

第一行是工具要使用的 base URL。第二行是控制面 API 的每会话 bearer 令牌文件；令牌在每次 `run` 时重新生成，并以 `0600` 写入。

如果配置的端口已被占用，`run` 会失败，而不是随机挑一个。用 `tokenhush status` 检查运行状态，或用 `tokenhush doctor` 运行诊断，然后要么停止另一个进程，要么用 `--port` 换个端口启动。

### 运行诊断

```bash
tokenhush doctor
```

`doctor` 检查配置文件、目录权限、密钥存储，以及配置端口是否匹配正在运行的会话。无检查失败时退出 `0`，任一检查失败时退出 `1`，用法错误时退出 `2`。

### 让工具指向网关

打印可直接粘贴的片段：

```bash
tokenhush env claude
```

`env` 支持 `claude`、`codex`、`aider`、`cline` 和 `roo`，并打印你当前平台的方言。完整的按工具设置（包括 `tokenhush.yaml` 上游映射）见 [configuration.zh-CN.md](configuration.zh-CN.md)。在确定工作流之前，请注意下面的 V1 限制。

> [!IMPORTANT]
> Codex CLI 仅在 API key 模式下可用。ChatGPT 订阅登录无法通过网关。Cursor 智能体流量、ChatGPT 和 Claude 桌面应用，以及浏览器 Web UI 在 V1 中未覆盖；它们需要系统级 MITM，而公开核心不实现该能力。

## 4. 运行模式

V1 中唯一的运行模式是前台网关：`tokenhush run`。它保持附着在终端上，按 `Ctrl-C` 退出。没有守护进程模式，也没有 service 子命令。

| 标志 | 值 | 说明 |
|---|---|---|
| `--config PATH` | `tokenhush.yaml` 的路径 | 覆盖平台默认位置 |
| `--port N` | `1` 到 `65535` | 默认 `8787`（或配置的 `listen.port`） |
| `--log-level LEVEL` | `debug`、`info`、`warn`、`error` | 默认 `info` |

在自定义端口上启动：

```bash
tokenhush run --port 9000
```

使用显式配置启动：

```bash
tokenhush run --config ~/.config/tokenhush/tokenhush.yaml
```

调试时提高日志级别：

```bash
tokenhush run --log-level debug
```

控制面 API 保持仅环回，并需要来自 `<data-dir>/control.token` 的 bearer 令牌。请求路径见 [architecture.zh-CN.md](architecture.zh-CN.md)。

### 让它在后台持续运行

> [!WARNING]
> 诸如 `tokenhush service install` 的内置 service 命令**在 V1 中未实现**。后台运行由用户自行管理：你把前台 `tokenhush run` 包装进操作系统原生的服务管理器。下面三个示例只是起点，不是已发布的功能。请按你的安装位置和配置调整路径。

每个管理器都应在进程退出时重启它，并且都必须传入二进制的绝对路径。示例显式传入 `--port 8787`，让意图更清晰。

#### macOS（launchd agent）

创建 `~/Library/LaunchAgents/com.tokenhush.gateway.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.tokenhush.gateway</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/tokenhush</string>
    <string>run</string>
    <string>--config</string>
    <string>/Users/you/Library/Application Support/tokenhush/tokenhush.yaml</string>
    <string>--port</string>
    <string>8787</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/tokenhush.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/tokenhush.err</string>
</dict>
</plist>
```

加载它：

```bash
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.tokenhush.gateway.plist
```

卸载它：

```bash
launchctl bootout "gui/$(id -u)/com.tokenhush.gateway"
```

#### Linux（systemd user unit）

创建 `~/.config/systemd/user/tokenhush.service`：

```ini
[Unit]
Description=Tokenhush local gateway
After=default.target

[Service]
ExecStart=%h/.local/bin/tokenhush run --config %h/.config/tokenhush/tokenhush.yaml --port 8787
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

启用并启动它：

```bash
systemctl --user daemon-reload
systemctl --user enable --now tokenhush.service
```

查看状态和日志：

```bash
systemctl --user status tokenhush.service
journalctl --user -u tokenhush.service -f
```

要在你未登录时仍保持网关运行，为你的用户开启 lingering：

```bash
sudo loginctl enable-linger "$USER"
```

#### Windows（任务计划程序）

注册一个在登录时启动网关的任务。通过 Scoop shim 解析可执行文件，确保路径正确：

```powershell
$exe = (Get-Command tokenhush).Source
$action  = New-ScheduledTaskAction -Execute $exe -Argument "run --port 8787"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "Tokenhush Gateway" -Action $action -Trigger $trigger -Settings $settings
```

立即启动它，无需等待下次登录，并检查它：

```powershell
Start-ScheduledTask -TaskName "Tokenhush Gateway"
Get-ScheduledTask -TaskName "Tokenhush Gateway" | Get-ScheduledTaskInfo
```

移除它：

```powershell
Unregister-ScheduledTask -TaskName "Tokenhush Gateway" -Confirm:$false
```

## 5. 目录与环境

Tokenhush 使用两个目录：存放 `tokenhush.yaml` 的配置目录，以及存放运行时状态的数据目录。在 macOS 上两者是同一路径；在 Linux 和 Windows 上不同。

| 操作系统 | 配置目录 | 数据目录 |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/` | `~/Library/Application Support/tokenhush/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LOCALAPPDATA%\tokenhush\` |

`TOKENHUSH_HOME` 设为非空值时，会同时覆盖两个目录。这在测试和保持隔离配置时很方便。

数据目录包含：

| 文件 | 用途 |
|---|---|
| `control.token` | 控制面 API 的每会话 bearer 令牌，以 `0600` 写入，每次 `run` 重新生成 |
| `run.json` | 会话元数据（pid、端口、启动时间）。不携带任何秘密和请求内容。 |

`run.json` 和 `control.token` 是会话文件。`run` 在干净关闭时删除它们，陈旧的 `run.json` 只影响诊断，不影响数据安全。核心不写入审计数据库；具体审计存储位于私有 Pro 层。

## 6. 配置

Tokenhush 从配置目录读取 `tokenhush.yaml`，或从传给 `--config` 的路径读取。文件缺失表示使用默认值。未知键会被拒绝，因此拼写错误会大声失败，而不是被忽略。

你最可能调整的设置是监听端口、六个检测器、白名单、日志级别，以及把主机或路径前缀路由到你自己的 OpenAI 兼容端点的 `upstreams` 映射。

完整的带注释默认值和所有受支持的键见 [configuration.zh-CN.md](configuration.zh-CN.md)。该文件是参考；本指南不重复 YAML 示例。

## 7. 升级

| 渠道 | 命令 |
|---|---|
| Homebrew | `brew upgrade --cask tokenhush` |
| Scoop | `scoop update tokenhush` |
| install.sh | 重新运行安装命令；它会解析最新发行版 |
| 源码 | `go install github.com/fregie/tokenhush/cmd/tokenhush@latest` |

配置键在加载时校验，因此添加键的升级不会破坏旧文件，删除键的升级会以 "unknown field" 错误快速失败。`v0.2.0` 升级就是一个具体例子：`audit:` 块已被移除，审计能力移至私有 Pro 层，因此请在重启前删除该块。见 [migration-v0.2.0.zh-CN.md](migration-v0.2.0.zh-CN.md)。升级后重启网关，让新二进制接管流量。

## 8. 卸载

通过安装时使用的渠道移除二进制：

```bash
brew uninstall --cask tokenhush
```

```powershell
scoop uninstall tokenhush
```

对于 `install.sh` 或源码安装，直接删除二进制：

```bash
rm "$(command -v tokenhush)"
```

如果你添加过 launchd agent、systemd unit 或计划任务，先移除该条目（见[让它在后台持续运行](#让它在后台持续运行)）。然后，如果你想彻底清理，删除配置和数据目录。在 macOS 上两者都位于 `~/Library/Application Support/tokenhush/`；在 Linux 上它们是 `~/.config/tokenhush/` 和 `~/.local/share/tokenhush/`；在 Windows 上它们是 `%AppData%\tokenhush\` 和 `%LOCALAPPDATA%\tokenhush\`。删除数据目录会丢弃会话文件（控制令牌和 `run.json`）。

## 9. 故障排查

先用 `tokenhush doctor`。它一次性报告配置路径、目录权限、密钥存储和会话状态，其退出码告诉你是否有任何失败。

| 症状 | 原因与修复 |
|---|---|
| `run` 报告端口已被占用 | 另一个进程（可能是先前的 `tokenhush run`）占用了端口。检查 `tokenhush status`，停止另一个进程，或用 `--port` 启动 |
| 安装后找不到 `tokenhush` | `~/.local/bin` 或 `$(go env GOPATH)/bin` 不在 `PATH` 上。把它加入你的 shell 配置文件，然后打开新 shell |
| 仅在公司网络内请求失败 | HTTP 代理拦截了环回流量。把 `127.0.0.1,localhost,::1` 加入 `NO_PROXY`（以及 `no_proxy`），或在代理设置中排除它 |
| macOS 首次运行阻止该二进制 | 发行版二进制未公证。右键点击二进制并选择"打开"，然后确认。或运行 `xattr -dr com.apple.quarantine "$(command -v tokenhush)"` |
| Windows SmartScreen 阻止 `tokenhush.exe` | 点击"更多信息"，然后点击"仍要运行"。Scoop 安装不会触发该提示 |
| `status` 报控制令牌错误 | 没有活跃会话，或令牌已陈旧。再次启动 `tokenhush run`；令牌按会话重新生成 |

## 10. 安全说明

这些属性是承重的。不要绕过它们。

- **仅环回。** 网关绑定 `127.0.0.1` 和 `[::1]`，并校验 `Host` 头。它绝不绑定 `0.0.0.0`。
- **无根证书，无 MITM。** 公开核心不安装 CA，也不拦截 TLS。请求以纯 HTTP 到达 localhost 上的网关，这正是它能看到并脱敏内容的方式。
- **仅元数据的审计接缝。** 核心把提供方、端点、时间、字节数、脱敏计数和检测器类型转发到注入的审计 sink，并默认使用 no-op sink。具体存储、其防篡改 HMAC 链和内容日志选项位于私有 Pro 层。
- **绝不向出站方向回填。** 占位符只在返回客户端的响应中恢复。网关绝不把占位符在出站请求中改写回其秘密，这阻断了提示注入外泄。
- **失败安全，而非失败开放（fail-open）。** 当检测器无法判断时，Tokenhush 会过度脱敏或阻断并记录告警，而不是静默放出一个秘密。

完整的威胁模型和不变量见 [security.zh-CN.md](security.zh-CN.md)。请求路径和模块布局见 [architecture.zh-CN.md](architecture.zh-CN.md)。

## 命令参考

```text
<!-- check-docs:commands:start -->
    tokenhush run          start the gateway in the foreground
    tokenhush status       show whether the gateway is running
    tokenhush env <tool>   print tool setup snippets
    tokenhush doctor       diagnose common setup problems
    tokenhush version      print version and build information
<!-- check-docs:commands:end -->
```

常用标志：

| 命令 | 标志 |
|---|---|
| `run` | `--config PATH`、`--port N`、`--log-level debug\|info\|warn\|error` |
| `status` | `--json` |
| `env <tool>` | `--config PATH`、`--port N`；工具：`claude`、`codex`、`aider`、`cline`、`roo` |
| `doctor` | `--config PATH`、`--port N`、`--json` |
| `version` | 无 |

项目概览见 [../README.zh-CN.md](../README.zh-CN.md)，工具设置见 [configuration.zh-CN.md](configuration.zh-CN.md)。
