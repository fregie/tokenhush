# 部署

[English](deployment.md) | **中文**

> 状态：V1（2026-09）。涵盖安装、首次运行，以及用系统服务管理器后台运行。下文命令、标志、路径与 V1 CLI 一致；`scripts/check-docs.sh` 用构建出的二进制核对命令列表。

Tokenhush 就是一个静态二进制：无运行时依赖，不起后台守护进程，也不装根证书。前台启动后，把 AI 工具指向 `http://127.0.0.1:8787`。

## 1. 环境要求

| 要求 | 值 |
|---|---|
| 操作系统 | macOS、Linux、Windows |
| 架构 | amd64 或 arm64 |
| Go（仅从源码构建） | Go 1.25 或更新版本 |
| 网络 | 仅环回。网关绑定 `127.0.0.1` 和 `[::1]`。 |
| 磁盘 | 存放运行时会话文件的空间（核心不保存请求/响应内容） |

发行版二进制是纯 Go（`CGO_ENABLED=0`），不需要 C 工具链。网关拒绝 `0.0.0.0` 和空主机，只绑定 `127.0.0.1`、`::1`、`localhost`；它是本地组件，不是网络服务。

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

脚本按系统和架构下载归档，用 `checksums.txt`（sha256）校验后装到 `~/.local/bin`；校验和不匹配就拒绝。

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

退出码：成功 `0`，运行时失败 `1`，用法错误 `2`。脚本若输出 `note: ~/.local/bin is not on your PATH`，就把该目录写进 shell 配置，让 `tokenhush` 能被找到。Windows 请改用 Scoop。

### 从源码构建

需要 Go 1.25 或更新版本。

```bash
go install github.com/fregie/tokenhush/cmd/tokenhush@latest
```

从本地检出构建也行：

```bash
go build -o bin/tokenhush ./cmd/tokenhush
```

`go install` 会把二进制放进 `$(go env GOPATH)/bin`，该目录要在 `PATH` 上。

### 验证安装

每个发行版都发布 `checksums.txt`（sha256）和每个归档的 SPDX SBOM。`install.sh` 装前就校验，Homebrew 和 Scoop 各自校验产物。

手动下载的，把归档哈希和 `checksums.txt` 对应行比一比：

```bash
curl -fsSLO https://github.com/fregie/tokenhush/releases/latest/download/checksums.txt
sha256sum tokenhush_0.1.0_linux_amd64.tar.gz
grep tokenhush_0.1.0_linux_amd64.tar.gz checksums.txt
```

归档命名是 `tokenhush_<version>_<os>_<arch>.tar.gz`。macOS 上换成 `shasum -a 256 <archive>`。

确认二进制能跑：

```bash
tokenhush version
```

`version` 打印版本和构建信息，不接受任何标志。

> [!NOTE]
> macOS Homebrew 和 Windows Scoop 渠道在 `v0.1.0` 下仍在手动验证。渠道装不上就按上文从源码构建；`main` 携带相同的 V1 实现。

## 3. 首次运行

前台启动网关：

```bash
tokenhush run
```

成功后打印监听地址和控制令牌文件：

```text
tokenhush: gateway listening on http://127.0.0.1:8787
tokenhush: control token file: <data-dir>/control.token
```

第一行是工具要用的 base URL。第二行是控制面 API 的每会话 bearer 令牌文件，每次 `run` 重新生成，写入权限 `0600`。

端口被占用时 `run` 直接失败，不会随机换一个。先 `tokenhush status` 看状态，或 `tokenhush doctor` 做诊断；然后停掉占用进程，或用 `--port` 换端口。

### 运行诊断

```bash
tokenhush doctor
```

`doctor` 检查配置文件、目录权限、密钥存储，以及配置端口是否匹配运行中的会话。无检查失败退出 `0`，任一失败退出 `1`，用法错误退出 `2`。

### 让工具指向网关

打印可直接粘贴的片段：

```bash
tokenhush env claude
```

`env` 支持 `claude`、`codex`、`aider`、`cline`、`roo`，按当前平台打印对应写法。各工具的完整配置（含 `tokenhush.yaml` 上游映射）见 [configuration.zh-CN.md](configuration.zh-CN.md)。定工作流前先看清下面的 V1 限制。

> [!IMPORTANT]
> Codex CLI 只能用 API key 模式，ChatGPT 订阅登录无法走网关。Cursor 智能体流量、ChatGPT 和 Claude 桌面应用、浏览器 Web UI 在 V1 都不覆盖；它们要系统级 MITM，而公开核心不实现。

## 4. 运行模式

V1 只有一种运行模式：前台网关 `tokenhush run`，挂在终端上，按 `Ctrl-C` 退出。没有守护进程模式，也没有 service 子命令。

| 标志 | 值 | 说明 |
|---|---|---|
| `--config PATH` | `tokenhush.yaml` 的路径 | 覆盖平台默认位置 |
| `--port N` | `1` 到 `65535` | 默认 `8787`（或配置的 `listen.port`） |
| `--log-level LEVEL` | `debug`、`info`、`warn`、`error` | 默认 `info` |

在自定义端口启动：

```bash
tokenhush run --port 9000
```

用显式配置启动：

```bash
tokenhush run --config ~/.config/tokenhush/tokenhush.yaml
```

调试时提高日志级别：

```bash
tokenhush run --log-level debug
```

控制面 API 只在环回可用，需要 `<data-dir>/control.token` 里的 bearer 令牌。请求路径见 [architecture.zh-CN.md](architecture.zh-CN.md)。

### 让它在后台持续运行

> [!WARNING]
> 像 `tokenhush service install` 这样的内置 service 命令**在 V1 中未实现**。后台运行由你自己管：把前台 `tokenhush run` 包进操作系统原生的服务管理器。下面三个示例只是起点，不是已发布功能，请按你的安装位置和配置改路径。

每个管理器都应在进程退出后重启它，且必须传二进制的绝对路径。示例都显式写 `--port 8787`，让意图更清楚。

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

想在你未登录时也让网关运行，给用户开启 lingering：

```bash
sudo loginctl enable-linger "$USER"
```

#### Windows（任务计划程序）

注册一个登录时启动网关的任务。通过 Scoop shim 解析可执行文件，确保路径正确：

```powershell
$exe = (Get-Command tokenhush).Source
$action  = New-ScheduledTaskAction -Execute $exe -Argument "run --port 8787"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "Tokenhush Gateway" -Action $action -Trigger $trigger -Settings $settings
```

不用等下次登录，立刻启动并查看它：

```powershell
Start-ScheduledTask -TaskName "Tokenhush Gateway"
Get-ScheduledTask -TaskName "Tokenhush Gateway" | Get-ScheduledTaskInfo
```

移除它：

```powershell
Unregister-ScheduledTask -TaskName "Tokenhush Gateway" -Confirm:$false
```

## 5. 目录与环境

Tokenhush 用两个目录：存 `tokenhush.yaml` 的配置目录，存运行时状态的数据目录。macOS 上两者同路径，Linux 和 Windows 上分开。

| 操作系统 | 配置目录 | 数据目录 |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/` | `~/Library/Application Support/tokenhush/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LOCALAPPDATA%\tokenhush\` |

`TOKENHUSH_HOME` 非空时会覆盖这两个目录，测试和隔离配置时很好用。

数据目录里有：

| 文件 | 用途 |
|---|---|
| `control.token` | 控制面 API 的每会话 bearer 令牌，以 `0600` 写入，每次 `run` 重新生成 |
| `run.json` | 会话元数据（pid、端口、启动时间）。不携带任何秘密和请求内容。 |

`run.json` 和 `control.token` 都是会话文件。干净关闭时 `run` 会删掉；`run.json` 残留只影响诊断，不影响数据安全。核心不保存请求或响应内容。

## 6. 配置

Tokenhush 从配置目录读 `tokenhush.yaml`，或从 `--config` 指定的路径读。文件不存在就用默认值。未知键会被拒绝，所以拼错会直接报错，不会悄悄忽略。

最常改的设置：监听端口、六个检测器、白名单、日志级别，以及把主机或路径前缀路由到你自己的 OpenAI 兼容端点的 `upstreams` 映射。

完整的带注释默认值和全部受支持的键见 [configuration.zh-CN.md](configuration.zh-CN.md)，本指南不重复 YAML 示例。

## 7. 升级

| 渠道 | 命令 |
|---|---|
| Homebrew | `brew upgrade --cask tokenhush` |
| Scoop | `scoop update tokenhush` |
| install.sh | 重新运行安装命令；它会解析最新发行版 |
| 源码 | `go install github.com/fregie/tokenhush/cmd/tokenhush@latest` |

配置键在加载时校验：新增键的升级不会弄坏旧文件，删键的升级会以 "unknown field" 错误立刻失败。`v0.2.0` 就是例子：重启前先删掉被移除的 `audit:` 块。见 [migration-v0.2.0.zh-CN.md](migration-v0.2.0.zh-CN.md)。升级后重启网关，让新二进制接管流量。

## 8. 卸载

用当初安装的渠道移除二进制：

```bash
brew uninstall --cask tokenhush
```

```powershell
scoop uninstall tokenhush
```

`install.sh` 或源码安装的，直接删二进制：

```bash
rm "$(command -v tokenhush)"
```

若加过 launchd agent、systemd unit 或计划任务，先删掉那个条目（见[让它在后台持续运行](#让它在后台持续运行)）。想彻底清干净，再删配置目录和数据目录。macOS 上两者都在 `~/Library/Application Support/tokenhush/`；Linux 上是 `~/.config/tokenhush/` 和 `~/.local/share/tokenhush/`；Windows 上是 `%AppData%\tokenhush\` 和 `%LOCALAPPDATA%\tokenhush\`。删数据目录会丢掉会话文件（控制令牌和 `run.json`）。

## 9. 故障排查

先跑 `tokenhush doctor`。它一次报出配置路径、目录权限、密钥存储和会话状态，退出码直接告诉你有无失败。

| 症状 | 原因与修复 |
|---|---|
| `run` 报告端口已被占用 | 另一个进程（可能是先前的 `tokenhush run`）占用了端口。检查 `tokenhush status`，停掉那个进程，或换 `--port` 启动 |
| 安装后找不到 `tokenhush` | `~/.local/bin` 或 `$(go env GOPATH)/bin` 不在 `PATH` 上。把它写进 shell 配置，再开一个新 shell |
| 仅在公司网络内请求失败 | HTTP 代理拦了环回流量。把 `127.0.0.1,localhost,::1` 加进 `NO_PROXY`（以及 `no_proxy`），或在代理设置里排除 |
| macOS 首次运行拦下二进制 | 发行版二进制未公证。右键点二进制，选“打开”，再确认。或运行 `xattr -dr com.apple.quarantine "$(command -v tokenhush)"` |
| Windows SmartScreen 拦下 `tokenhush.exe` | 点“更多信息”，再点“仍要运行”。Scoop 安装不会触发该提示 |
| `status` 报控制令牌错误 | 没有活跃会话，或令牌已过期。重新启动 `tokenhush run`；令牌按会话重新生成 |

## 10. 安全说明

下面这些是底线，别绕过。

- **仅环回。** 网关绑定 `127.0.0.1` 和 `[::1]`，并校验 `Host` 头，绝不绑定 `0.0.0.0`。
- **不装根证书，不做 MITM。** 公开核心不装 CA，也不拦 TLS。请求以纯 HTTP 打到 localhost 上的网关，它才看得到并脱敏内容。
- **绝不向出站回填。** 占位符只在返回客户端的响应里还原。出站请求里，网关绝不把占位符改回秘密，挡住了提示注入外泄。
- **失败时偏保守，不放行。** 检测器拿不准时，Tokenhush 宁可过度脱敏或直接阻断并记告警，也不悄悄放出一个秘密。

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
