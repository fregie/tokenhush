# Deployment

**English** | [中文](deployment.zh-CN.md)

> Status: V1 (2026-09). Covers release installs, first run, and OS-managed background operation. Every command, flag, and path matches the V1 CLI; `scripts/check-docs.sh` checks the command list against the built binary.

Tokenhush is one static binary: no runtime dependencies, no daemon, no root certificate. Install it, run it in the foreground, then point your AI tools at `http://127.0.0.1:8787`.

## 1. Requirements

| Requirement | Value |
|---|---|
| Operating system | macOS, Linux, Windows |
| Architecture | amd64 or arm64 |
| Go (source builds only) | Go 1.25 or newer |
| Network | Loopback only. The gateway binds `127.0.0.1` and `[::1]`. |
| Disk | Room for runtime session files (the core stores no request or response content) |

Release binaries are pure Go (`CGO_ENABLED=0`), so no C toolchain is needed. The gateway refuses `0.0.0.0` and empty hosts; it binds only `127.0.0.1`, `::1`, and `localhost`, because it is a local component, not a network service.

## 2. Install

### macOS (Homebrew cask)

```bash
brew install --cask fregie/tap/tokenhush
```

### Windows (Scoop)

```powershell
scoop bucket add fregie https://github.com/fregie/scoop-bucket
scoop install tokenhush
```

### Linux (install.sh)

```bash
curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh | bash
```

The script downloads the archive for your OS and architecture, checks it against the release `checksums.txt` (sha256), and installs to `~/.local/bin`. It refuses to install on a checksum mismatch.

| Flag | Meaning |
|---|---|
| `--dry-run` | Download and verify, but do not install |
| `--version VERSION` | Install a specific version, without the leading `v` |
| `--dir PATH` | Destination directory (default `~/.local/bin`) |
| `--base-url URL` | Download base URL for mirrors or testing (requires an explicit `--version`) |

| Environment variable | Meaning |
|---|---|
| `TOKENHUSH_VERSION` | Version to install (default: latest release) |
| `TOKENHUSH_INSTALL_DIR` | Destination directory (default `~/.local/bin`) |
| `TOKENHUSH_BASE_URL` | Download base URL for mirrors or testing |

Exit codes: `0` success, `1` runtime failure, `2` usage error. If the script prints `note: ~/.local/bin is not on your PATH`, add that directory to your shell profile so `tokenhush` resolves. The script does not support Windows; use Scoop instead.

### Build from source

Go 1.25 or newer is required.

```bash
go install github.com/fregie/tokenhush/cmd/tokenhush@latest
```

Or from a checkout:

```bash
go build -o bin/tokenhush ./cmd/tokenhush
```

`go install` places the binary in `$(go env GOPATH)/bin`, which must be on your `PATH`.

### Verify the installation

Every release publishes `checksums.txt` (sha256) and a per-archive SPDX SBOM. `install.sh` verifies the checksum before installing; Homebrew and Scoop verify their own artifacts.

For a manual download, compare the archive hash with the matching line in `checksums.txt`:

```bash
curl -fsSLO https://github.com/fregie/tokenhush/releases/latest/download/checksums.txt
sha256sum tokenhush_0.1.0_linux_amd64.tar.gz
grep tokenhush_0.1.0_linux_amd64.tar.gz checksums.txt
```

Archive names follow `tokenhush_<version>_<os>_<arch>.tar.gz`. On macOS, use `shasum -a 256 <archive>`.

Confirm the binary runs:

```bash
tokenhush version
```

`version` prints the version and build information, and takes no flags.

> [!NOTE]
> The macOS Homebrew and Windows Scoop channels are still under manual verification for the `v0.3.0` line. If a channel install fails, build from source as above; `main` carries the same V1 implementation.

## 3. First run

Start the gateway in the foreground:

```bash
tokenhush run
```

On success it prints the listening address and the control token file:

```text
tokenhush: gateway listening on http://127.0.0.1:8787
tokenhush: control token file: <data-dir>/control.token
```

The first line is the base URL your tools use. The second is the per-session bearer token file for the control API; it is regenerated on every `run` and written `0600`.

If the port is in use, `run` fails instead of picking a random one. Check state with `tokenhush status`, or diagnose with `tokenhush doctor`; then stop the other process or start with `--port`.

### Run diagnostics

```bash
tokenhush doctor
```

`doctor` checks the config file, directory permissions, the secret store, and whether the configured port matches a running session. It exits `0` when no check fails, `1` when any fails, and `2` on a usage error.

### Point a tool at the gateway

Print a ready-to-paste snippet:

```bash
tokenhush env claude
```

`env` supports `claude`, `codex`, `aider`, `cline`, `roo`, `opencode`, `qwen`, `crush`, `zed`, `continue`, `openwebui`, `goose`, `openhands`, and `kilo`, and prints the dialect for your platform. For full per-tool setup, including the `tokenhush.yaml` upstream map, see [configuration.md](configuration.md). See the V1 limits below.

> [!IMPORTANT]
> Codex CLI works in API key mode only; ChatGPT subscription login cannot pass through the gateway. Cursor agent traffic, the ChatGPT and Claude desktop apps, and browser web UIs are not covered in V1; they need system-level MITM, which the public core does not implement.

## 4. Run modes

V1 has one run mode: the foreground gateway `tokenhush run`, which stays attached to the terminal and exits on `Ctrl-C`. There is no daemon mode and no service subcommand.

| Flag | Value | Notes |
|---|---|---|
| `--config PATH` | Path to a `tokenhush.yaml` | Overrides the platform default location |
| `--port N` | `1` to `65535` | Defaults to `8787` (or the configured `listen.port`) |
| `--log-level LEVEL` | `debug`, `info`, `warn`, `error` | Defaults to `info` |

Start on a custom port:

```bash
tokenhush run --port 9000
```

Start with an explicit config:

```bash
tokenhush run --config ~/.config/tokenhush/tokenhush.yaml
```

Turn up logging while debugging:

```bash
tokenhush run --log-level debug
```

The control API stays loopback-only and needs the bearer token from `<data-dir>/control.token`. See [architecture.md](architecture.md) for the request path.

### Keep it running in the background

> [!WARNING]
> A built-in service command such as `tokenhush service install` is **not implemented in V1**. Background operation is user-managed: wrap the foreground `tokenhush run` in your OS service manager. The three examples below are starting points, not shipped features. Adjust paths to your install and config.

Each manager should restart the process if it exits, and each needs an absolute path to the binary. Each example passes `--port 8787` so the intent is clear.

#### macOS (launchd agent)

Create `~/Library/LaunchAgents/com.tokenhush.gateway.plist`:

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

Load it:

```bash
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.tokenhush.gateway.plist
```

Unload it:

```bash
launchctl bootout "gui/$(id -u)/com.tokenhush.gateway"
```

#### Linux (systemd user unit)

Create `~/.config/systemd/user/tokenhush.service`:

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

Enable and start it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now tokenhush.service
```

Check status and logs:

```bash
systemctl --user status tokenhush.service
journalctl --user -u tokenhush.service -f
```

To keep the gateway running when you are not logged in, allow lingering for your user:

```bash
sudo loginctl enable-linger "$USER"
```

#### Windows (Task Scheduler)

Register a task that starts the gateway at logon. Resolve the executable through the Scoop shim so the path is correct:

```powershell
$exe = (Get-Command tokenhush).Source
$action  = New-ScheduledTaskAction -Execute $exe -Argument "run --port 8787"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "Tokenhush Gateway" -Action $action -Trigger $trigger -Settings $settings
```

Start it now without waiting for the next logon, then inspect it:

```powershell
Start-ScheduledTask -TaskName "Tokenhush Gateway"
Get-ScheduledTask -TaskName "Tokenhush Gateway" | Get-ScheduledTaskInfo
```

Remove it:

```powershell
Unregister-ScheduledTask -TaskName "Tokenhush Gateway" -Confirm:$false
```

## 5. Directories and environment

Tokenhush uses two directories: a config directory for `tokenhush.yaml`, and a data directory for runtime state. On macOS they are the same path; on Linux and Windows they differ.

| OS | Config directory | Data directory |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/` | `~/Library/Application Support/tokenhush/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LOCALAPPDATA%\tokenhush\` |

`TOKENHUSH_HOME`, when non-blank, overrides both directories. Useful for tests and isolated profiles.

The data directory holds:

| File | Purpose |
|---|---|
| `control.token` | Per-session bearer token for the control API, written `0600`, regenerated on every `run` |
| `run.json` | Session metadata (pid, port, start time). Carries no secrets and no request content. |

`run.json` and `control.token` are session files. `run` removes them on clean shutdown, and a stale `run.json` only affects diagnostics, not data safety. The core stores no request or response content.

## 6. Configuration

Tokenhush reads `tokenhush.yaml` from the config directory, or from the path passed to `--config`. A missing file means defaults. Unknown keys are rejected, so a typo fails loudly instead of being ignored.

The settings you are most likely to touch: the listen port, the six detectors, the allowlist, the log level, and the `upstreams` map that routes a host or path prefix to your own OpenAI-compatible endpoint.

Full annotated defaults and every supported key live in [configuration.md](configuration.md); this guide does not repeat the YAML sample.

## 7. Upgrade

| Channel | Command |
|---|---|
| Homebrew | `brew upgrade --cask tokenhush` |
| Scoop | `scoop update tokenhush` |
| install.sh | Re-run the install command; it resolves the latest release |
| Source | `go install github.com/fregie/tokenhush/cmd/tokenhush@latest` |

Config keys are validated on load, so an upgrade that adds a key does not break an older file, and one that removes a key fails fast with an "unknown field" error. The `v0.2.0` upgrade is a concrete case: delete the removed `audit:` block before restarting. See [migration-v0.2.0.md](migration-v0.2.0.md). The `v0.3.0` upgrade needs no config change; see [migration-v0.3.0.md](migration-v0.3.0.md). Restart the gateway after upgrading so the new binary serves traffic.

## 8. Uninstall

Remove the binary through the channel you installed it with:

```bash
brew uninstall --cask tokenhush
```

```powershell
scoop uninstall tokenhush
```

For an `install.sh` or source install, delete the binary directly:

```bash
rm "$(command -v tokenhush)"
```

If you added a launchd agent, systemd unit, or scheduled task, remove that entry first (see [Keep it running in the background](#keep-it-running-in-the-background)). Then delete the config and data directories for a clean slate. On macOS both live under `~/Library/Application Support/tokenhush/`; on Linux they are `~/.config/tokenhush/` and `~/.local/share/tokenhush/`; on Windows they are `%AppData%\tokenhush\` and `%LOCALAPPDATA%\tokenhush\`. Removing the data directory discards the session files (the control token and `run.json`).

## 9. Troubleshooting

Start with `tokenhush doctor`. It reports the config path, directory permissions, secret store, and session state in one pass; the exit code tells you whether anything failed.

| Symptom | Cause and fix |
|---|---|
| `run` reports the port is already in use | Another process (possibly a previous `tokenhush run`) holds the port. Check `tokenhush status`, stop the other process, or start with `--port` |
| `tokenhush` not found after install | `~/.local/bin` or `$(go env GOPATH)/bin` is not on `PATH`. Add it to your shell profile, then open a new shell |
| Requests fail only inside a corporate network | An HTTP proxy is intercepting loopback traffic. Add `127.0.0.1,localhost,::1` to `NO_PROXY` (and `no_proxy`), or exclude it in your proxy settings |
| macOS blocks the binary on first run | The release binaries are not notarized. Right-click the binary and choose Open, then confirm. Or run `xattr -dr com.apple.quarantine "$(command -v tokenhush)"` |
| Windows SmartScreen blocks `tokenhush.exe` | Click More info, then Run anyway. Scoop installs do not trigger this prompt |
| `status` fails with a control token error | No live session, or the token is stale. Start `tokenhush run` again; the token is regenerated per session |

## 10. Security notes

These properties are load-bearing. Do not work around them.

- **Loopback only.** The gateway binds `127.0.0.1` and `[::1]` and validates the `Host` header. It never binds `0.0.0.0`.
- **No root certificate, no MITM.** The public core installs no CA and intercepts no TLS. Requests reach the gateway as plain HTTP on localhost, so it can see and redact content.
- **Never backfill outbound.** Placeholders are restored only on responses returning to the client. The gateway never rewrites a placeholder back to its secret in an outbound request, which blocks prompt-injection exfiltration.
- **Fail-safe, not fail-open.** When a detector cannot decide, Tokenhush over-redacts or blocks and records an alert rather than silently emitting a secret.
- **Two disclosed, switchable egress categories.** The only vendor-bound requests are rule sync (active; `tokenhush rules sync`, switch it off with `TOKENHUSH_NO_RULE_SYNC=1`) and update check (active; `tokenhush update`, switch it off with `TOKENHUSH_NO_UPDATE_CHECK=1`). Each category's fields, what the server observes, retention, and its off switch are in the generated [network egress disclosure](generated/network-egress.md), also printed by `tokenhush privacy`.

The full threat model and invariants are in [security.md](security.md). The request path and module layout are in [architecture.md](architecture.md).

## Command reference

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

Useful flags:

| Command | Flags |
|---|---|
| `run` | `--config PATH`, `--port N`, `--log-level debug\|info\|warn\|error` |
| `status` | `--json` |
| `env <tool>` | `--config PATH`, `--port N`; tools: `claude`, `codex`, `aider`, `cline`, `roo`, `opencode`, `qwen`, `crush`, `zed`, `continue`, `openwebui`, `goose`, `openhands`, `kilo` |
| `doctor` | `--config PATH`, `--port N`, `--json` |
| `privacy` | `--json` |
| `update` | `--check` |
| `rules sync` | `--check` |
| `rules rollback` | none |
| `version` | none |

See [../README.md](../README.md) for the project overview and [configuration.md](configuration.md) for tool setup.
