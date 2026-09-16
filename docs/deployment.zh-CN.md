# 部署

[English](deployment.md) | **中文**

> 状态：V1（2026-09）。涵盖安装、首次运行，以及用系统服务管理器后台运行。下文命令、标志、路径与 V1 CLI 一致；`scripts/check-docs.sh` 用构建出的二进制核对命令列表。

Tokenhush 就是一个静态二进制：无运行时依赖，不起后台守护进程，也不装根证书。前台启动后，把 AI 工具指向 `http://127.0.0.1:8787`。

## 🎯 1. 环境要求

| 要求 | 值 |
|---|---|
| 操作系统 | macOS、Linux、Windows |
| 架构 | amd64 或 arm64 |
| Go（仅从源码构建） | Go 1.25 或更新版本 |
| 网络 | 仅环回。网关绑定 `127.0.0.1`，主机有 IPv6 环回时同时绑 `[::1]`。 |
| 磁盘 | 存放运行时会话文件与持久化运行期白名单的空间（核心不保存请求/响应内容） |

发行版二进制是纯 Go（`CGO_ENABLED=0`），不需要 C 工具链。网关拒绝 `0.0.0.0` 和空主机，仅绑环回（始终绑 `127.0.0.1`，主机有 IPv6 环回时同时绑 `[::1]`）；它是本地组件，不是网络服务。

## 📦 2. 安装

### macOS（Homebrew cask）

```bash
brew install --cask fregie/tap/tokenhush
```

### Windows（install.ps1）

```powershell
irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 | iex
```

脚本按架构下载 Windows zip，用 `checksums.txt`（sha256）校验后装到 `%LOCALAPPDATA%\Programs\tokenhush`，并把该目录加入用户 `PATH`。无需管理员权限；校验和不匹配就拒绝。

管道形式的一行命令无法接收参数，需要传参时包进脚本块：

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1))) -DryRun
```

| 参数 | 含义 |
|---|---|
| `-DryRun` | 下载、校验并解包，但不安装 |
| `-Version VERSION` | 安装指定版本，不带前导 `v` |
| `-Dir PATH` | 目标目录（默认 `%LOCALAPPDATA%\Programs\tokenhush`） |
| `-BaseUrl URL` | 供镜像或测试使用的下载基础 URL（需要显式指定 `-Version`） |

| 环境变量 | 含义 |
|---|---|
| `TOKENHUSH_VERSION` | 要安装的版本（默认：最新发行版） |
| `TOKENHUSH_INSTALL_DIR` | 目标目录（默认 `%LOCALAPPDATA%\Programs\tokenhush`） |
| `TOKENHUSH_BASE_URL` | 供镜像或测试使用的下载基础 URL |

退出码：成功 `0`，运行时失败 `1`，用法错误 `2`。脚本会把安装目录加入用户 `PATH`；请新开一个终端使其生效。

### Windows（Scoop，备选）

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

退出码：成功 `0`，运行时失败 `1`，用法错误 `2`。脚本若输出 `note: ~/.local/bin is not on your PATH`，就把该目录写进 shell 配置，让 `tokenhush` 能被找到。该脚本不支持 Windows，Windows 请改用 install.ps1。

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

每个发行版都发布 `checksums.txt`（sha256）和每个归档的 SPDX SBOM。`install.sh` 和 `install.ps1` 装前就校验，Homebrew 和 Scoop 各自校验产物。

手动下载的，把归档哈希和 `checksums.txt` 对应行比一比：

```bash
curl -fsSLO https://github.com/fregie/tokenhush/releases/latest/download/checksums.txt
sha256sum tokenhush_0.1.0_linux_amd64.tar.gz
grep tokenhush_0.1.0_linux_amd64.tar.gz checksums.txt
```

归档命名是 `tokenhush_<version>_<os>_<arch>.tar.gz`（Windows 为 `.zip`）。macOS 上换成 `shasum -a 256 <archive>`；Windows 上用 `Get-FileHash -Algorithm SHA256 <archive>`。

确认二进制能跑：

```bash
tokenhush version
```

`version` 打印版本和构建信息，不接受任何标志。

> [!NOTE]
> macOS Homebrew 和 Windows install.ps1/Scoop 渠道在 `v0.4.0` 线下仍在手动验证。渠道装不上就按上文从源码构建；`main` 携带相同的 V1 实现。

## 🚀 3. 首次运行

前台启动网关：

```bash
tokenhush run
```

成功后先打印生效的上游路由表与 `tokenhush env <tool>` 接入提示，再打印监听地址和控制令牌文件：

```text
tokenhush: upstream routes (a request path selects its upstream; config `upstreams:` overrides win):
tokenhush:   /v1/chat/completions       -> openai     https://api.openai.com
tokenhush:   ... (the effective route table; config `upstreams:` overrides win)
tokenhush: point a tool at the gateway, then run it:
tokenhush:   tokenhush env claude   # ANTHROPIC_BASE_URL=http://127.0.0.1:8787
tokenhush:   tokenhush env codex    # base_url=http://127.0.0.1:8787/v1
tokenhush:   tokenhush env <tool>   # claude, codex, aider, cline, roo, opencode, qwen, crush, zed, continue, openwebui, goose, openhands, kilo
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

`env` 支持 `claude`、`codex`、`aider`、`cline`、`roo`、`opencode`、`qwen`、`crush`、`zed`、`continue`、`openwebui`、`goose`、`openhands` 和 `kilo`，按当前平台打印对应写法。各工具的完整配置（含 `tokenhush.yaml` 上游映射）见 [tool-setup.zh-CN.md](tool-setup.zh-CN.md)。定工作流前先看清下面的 V1 限制。

> [!IMPORTANT]
> Codex CLI 只能用 API key 模式，ChatGPT 订阅登录无法走网关。Cursor 智能体流量、ChatGPT 和 Claude 桌面应用、浏览器 Web UI 在 V1 都不覆盖；它们要系统级 MITM，而公开核心不实现。

## 🚀 4. 运行模式

V1 只有一种运行模式：前台网关 `tokenhush run`，挂在终端上，按 `Ctrl-C` 退出。没有守护进程模式，也没有 service 子命令。

| 标志 | 值 | 说明 |
|---|---|---|
| `--config PATH` | `tokenhush.yaml` 的路径 | 覆盖平台默认位置 |
| `--port N` | `1` 到 `65535` | 默认 `8787`（或配置的 `listen.port`） |
| `--log-level LEVEL` | `debug`、`info`、`warn`、`error` | 默认 `info` |
| `--log-redactions BOOL` | `true`（默认）或 `false` | 为每个被脱敏的值向 stderr 打印一行掩码日志 |

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

### 脱敏日志

`tokenhush run` 默认会为每个被脱敏的值向 stderr 打印一行掩码日志。每行包含检测器类型、匹配到的字节长度与一段掩码片段，绝不打印完整值：

```text
tokenhush: redacted request api_key (len=32) sk-p…j0
```

可用 `--log-redactions=false` 关闭。

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

注册一个登录时启动网关的任务。用 `Get-Command` 解析可执行文件，install.ps1 与 Scoop 安装都适用：

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

## ⚙️ 5. 目录与环境

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
| `allowlist.json` | 运行期白名单条目（在列期间不脱敏的值）。带 `schema_version` 的 JSON，以 `0600` 写入。**非**会话文件：干净退出后保留。 |

`run.json` 和 `control.token` 都是会话文件。干净关闭时 `run` 会删掉；`run.json` 残留只影响诊断，不影响数据安全。`allowlist.json` **不是**会话文件：它保存运行期白名单，跨重启与干净退出都保留，且只包含你显式放行的值。核心不保存请求或响应内容。

## ⚙️ 6. 配置

Tokenhush 从配置目录读 `tokenhush.yaml`，或从 `--config` 指定的路径读。文件不存在就用默认值。未知键会被拒绝，所以拼错会直接报错，不会悄悄忽略。

最常改的设置：监听端口、六个检测器、白名单、日志级别，以及把主机或路径前缀路由到你自己的 OpenAI 兼容端点的 `upstreams` 映射。

完整的带注释默认值和全部受支持的键见 [tool-setup.zh-CN.md](tool-setup.zh-CN.md#tokenhushyaml-参考)，本指南不重复 YAML 示例。

## ⬆️ 7. 升级

| 渠道 | 命令 |
|---|---|
| Homebrew | `brew upgrade --cask tokenhush` |
| Windows（install.ps1） | 重新运行安装命令；它会解析最新发行版 |
| Scoop | `scoop update tokenhush` |
| Linux（install.sh） | 重新运行安装命令；它会解析最新发行版 |
| 源码 | `go install github.com/fregie/tokenhush/cmd/tokenhush@latest` |

配置键在加载时校验：新增键的升级不会弄坏旧文件，删键的升级会以 "unknown field" 错误立刻失败。`v0.2.0` 就是例子：核心配置没有 `audit:` 键，仍带该键的文件会加载失败——重启前请删掉该块。审计块位于私有 Pro 层。`v0.3.0` 升级无需修改配置：它把共享装配层移入导出的 `pkg/gateway` 包。`v0.4.0` 升级同样无需修改配置：它加入签名自更新引擎（`tokenhush update`）、签名规则同步（`tokenhush rules`）与机器可读的外发披露（`tokenhush privacy`）。升级后重启网关，让新二进制接管流量。

## 🗑️ 8. 卸载

用当初安装的渠道移除二进制：

```bash
brew uninstall --cask tokenhush
```

```powershell
scoop uninstall tokenhush
```

`install.sh`、`install.ps1` 或源码安装的，直接删二进制。macOS 和 Linux 上：

```bash
rm "$(command -v tokenhush)"
```

Windows 上删掉安装目录，并从用户 `PATH` 中移除：

```powershell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Programs\tokenhush"
```

若加过 launchd agent、systemd unit 或计划任务，先删掉那个条目（见[让它在后台持续运行](#让它在后台持续运行)）。想彻底清干净，再删配置目录和数据目录。macOS 上两者都在 `~/Library/Application Support/tokenhush/`；Linux 上是 `~/.config/tokenhush/` 和 `~/.local/share/tokenhush/`；Windows 上是 `%AppData%\tokenhush\` 和 `%LOCALAPPDATA%\tokenhush\`。删数据目录会丢掉会话文件（控制令牌和 `run.json`）以及持久化的运行期白名单（`allowlist.json`）。

## 🛠️ 9. 故障排查

先跑 `tokenhush doctor`。它一次报出配置路径、目录权限、密钥存储和会话状态，退出码直接告诉你有无失败。

| 症状 | 原因与修复 |
|---|---|
| `run` 报告端口已被占用 | 另一个进程（可能是先前的 `tokenhush run`）占用了端口。检查 `tokenhush status`，停掉那个进程，或换 `--port` 启动 |
| 安装后找不到 `tokenhush` | 安装目录不在 `PATH` 上：`~/.local/bin`（Linux）、`$(go env GOPATH)/bin`（源码）、`%LOCALAPPDATA%\Programs\tokenhush`（Windows）。加上它，再开一个新 shell 或终端 |
| 仅在公司网络内请求失败 | HTTP 代理拦了环回流量。把 `127.0.0.1,localhost,::1` 加进 `NO_PROXY`（以及 `no_proxy`），或在代理设置里排除 |
| 主机没有 IPv6 / 出现 `[::1]` 绑定提示 | 主机没有 IPv6 环回时，网关只服务 `127.0.0.1`，并打印 `tokenhush: IPv6 loopback [::1] unavailable (<cause>); listening on 127.0.0.1 only`。这是预期行为，不是错误。若想同时服务 `[::1]`，可启用 IPv6 环回（Linux：`sysctl -w net.ipv6.conf.all.disable_ipv6=0`） |
| macOS 首次运行拦下二进制 | 发行版二进制未公证。右键点二进制，选“打开”，再确认。或运行 `xattr -dr com.apple.quarantine "$(command -v tokenhush)"` |
| Windows SmartScreen 拦下 `tokenhush.exe` | 二进制尚未代码签名。点“更多信息”，再点“仍要运行”。Scoop 与已签名发行版不会触发该提示 |
| `status` 报控制令牌错误 | 没有活跃会话，或令牌已过期。重新启动 `tokenhush run`；令牌按会话重新生成 |

## 🛡️ 10. 安全说明

下面这些是底线，别绕过。

- **仅环回。** 网关绑定 `127.0.0.1`，主机有 IPv6 环回时同时绑 `[::1]`，并校验 `Host` 头，绝不绑定 `0.0.0.0`。
- **不装根证书，不做 MITM。** 公开核心不装 CA，也不拦 TLS。请求以纯 HTTP 打到 localhost 上的网关，它才看得到并脱敏内容。
- **绝不向出站回填。** 占位符只在返回客户端的响应里还原。出站请求里，网关绝不把占位符改回秘密，挡住了提示注入外泄。
- **失败时偏保守，不放行。** 检测器拿不准时，Tokenhush 宁可过度脱敏或直接阻断并记告警，也不悄悄放出一个秘密。
- **两个已披露、可关闭的外发类别。** 面向厂商的请求仅有规则同步（已生效；`tokenhush rules sync`，可用 `TOKENHUSH_NO_RULE_SYNC=1` 关闭）与更新检查（已生效；`tokenhush update`，可用 `TOKENHUSH_NO_UPDATE_CHECK=1` 关闭）。每个类别的字段、服务端可见信息、保留期与关闭方法见生成的数据外发披露 [network-egress.md](generated/network-egress.md)，也可用 `tokenhush privacy` 打印。

完整的威胁模型和不变量见 [security.zh-CN.md](security.zh-CN.md)。请求路径和模块布局见 [architecture.zh-CN.md](architecture.zh-CN.md)。

## ⌨️ 命令参考

```text
<!-- check-docs:commands:start -->
    tokenhush run          start the gateway in the foreground
    tokenhush status       show whether the gateway is running
    tokenhush env <tool>   print tool setup snippets
    tokenhush doctor       diagnose common setup problems
    tokenhush privacy      show requests that leave your machine for the vendor
    tokenhush update       upgrade via the owning package manager
    tokenhush rules        sync signed detection rules or roll back
    tokenhush version      print version and build information
<!-- check-docs:commands:end -->
```

常用标志：

| 命令 | 标志 |
|---|---|
| `run` | `--config PATH`、`--port N`、`--log-level debug\|info\|warn\|error`、`--log-redactions true\|false` |
| `status` | `--json` |
| `env <tool>` | `--config PATH`、`--port N`；工具：`claude`、`codex`、`aider`、`cline`、`roo`、`opencode`、`qwen`、`crush`、`zed`、`continue`、`openwebui`、`goose`、`openhands`、`kilo` |
| `doctor` | `--config PATH`、`--port N`、`--json` |
| `privacy` | `--json` |
| `update` | `--check` |
| `rules sync` | `--check` |
| `rules rollback` | 无 |
| `version` | 无 |

项目概览见 [../README.zh-CN.md](../README.zh-CN.md)，工具设置见 [tool-setup.zh-CN.md](tool-setup.zh-CN.md)。
