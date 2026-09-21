# Deployment

**English** | [中文](deployment.zh-CN.md)

Tokenhush is a single binary that runs in the foreground. This page covers how
to build or install it, where it keeps config and data, how to keep it running
with your operating system's own tools, and what the release status actually is
today.

## Install

| Platform | One-line install |
|---|---|
| macOS | `brew install --cask fregie/tap/tokenhush` |
| Linux | `curl -fsSL https://raw.githubusercontent.com/fregie/tokenhush/main/install.sh \| bash` |
| Windows | `irm https://raw.githubusercontent.com/fregie/tokenhush/main/install.ps1 \| iex` |

The Linux and Windows installers download the matching release archive, verify
its sha256 against the release `checksums.txt`, and install the binary into a
per-user directory, with no admin rights and no package manager:

| Platform | Default install directory | Override |
|---|---|---|
| Linux | `~/.local/bin` | `TOKENHUSH_INSTALL_DIR` or `--dir` |
| Windows | `%LOCALAPPDATA%\Programs\tokenhush` | `TOKENHUSH_INSTALL_DIR` or `-Dir` |

Both accept a pinned version (`--version X.Y.Z` / `-Version X.Y.Z`) and a
`--dry-run` / `-DryRun` mode that downloads and verifies without installing.

The installers download the published binary for your platform and verify it
against the release `checksums.txt`. A default run refuses a published release
older than the minimum line rather than installing it, and falls back to
building the current line from source; see [Release status](#release-status).

### Build from source

Needs Go 1.25 or newer:

```sh
go build -o tokenhush ./cmd/tokenhush
./tokenhush version
```

`tokenhush version` prints the version, the target OS and architecture, the Go
toolchain, the commit, and the build time.

### `go install`

```sh
go install github.com/fregie/tokenhush/cmd/tokenhush@main
```

Use `@main` for the current line. `@latest` still resolves to the older
published tag, so it does not give you the from-scratch rewrite.

### Put it on `PATH`

The examples in these docs call `tokenhush` directly. If `go install` placed the
binary somewhere `PATH` does not cover, add that directory, for example
`$HOME/go/bin`. Or move the built binary to a directory already on `PATH`, such
as `/usr/local/bin` on macOS and Linux.

## Platform matrix

Tokenhush is pure Go. It is built with `CGO_ENABLED=0`, so the binary has no C
dependencies and cross-compiles cleanly. The pinned target set is:

| OS | Architecture |
|---|---|
| macOS | arm64, amd64 |
| Linux | arm64, amd64 |
| Windows | arm64, amd64 |

`.goreleaser.yaml` pins exactly this build matrix and the `checksums.txt`
artefact, and `.github/workflows/release.yml` builds and publishes them on a
`v*` tag.

## Config and data directories

| Platform | Config dir | Data dir |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/config/` | `~/Library/Application Support/tokenhush/Data/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LocalAppData%\tokenhush\` |

`TOKENHUSH_HOME` moves both to one root: config at
`<TOKENHUSH_HOME>/config` and data at `<TOKENHUSH_HOME>/data`. An empty value
counts as unset. A `TOKENHUSH_HOME` that points at or inside the directory
holding the running executable is rejected, because a data directory there
could be writable code.

The data directory holds session metadata only: `run.json` and
`control.token`, plus the rule cache under `rules/` and the update
anti-rollback mark under `update/`. Request and response bodies, detected
secrets, and the placeholder-to-secret mapping are never written to disk. See
[security.md](security.md) for the full on-disk list.

## Running it

Start the gateway in the foreground:

```sh
tokenhush run
```

It listens on `http://127.0.0.1:8787` and exits on Ctrl-C. Useful flags:
`--config PATH`, `--port N` (1..65535), `--log-level debug|info|warn|error`, and
`--log-redactions` (on by default; `--log-redactions=false` silences the masked
stderr line).

**There is no built-in service command.** Tokenhush does not install, manage, or
control a background service. To keep it running across logins and restarts,
wrap `tokenhush run` with your operating system's own service tooling. The
examples below are ordinary launchd, systemd, and Task Scheduler configurations;
adjust the binary path to where you installed it.

### macOS: a launchd agent

Create `~/Library/LaunchAgents/com.tokenhush.gateway.plist`:

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

Load it:

```sh
launchctl load -w ~/Library/LaunchAgents/com.tokenhush.gateway.plist
```

### Linux: a systemd user unit

Create `~/.config/systemd/user/tokenhush.service`:

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

Enable and start it:

```sh
systemctl --user daemon-reload
systemctl --user enable --now tokenhush.service
```

### Windows: a Task Scheduler entry

Register a task that starts the gateway at logon:

```powershell
schtasks /Create /TN Tokenhush /TR "C:\path\to\tokenhush.exe run" /SC ONLOGON
```

Adjust `/TR` to the full path of `tokenhush.exe` on your machine.

## Release status

Releases are published. `.goreleaser.yaml` pins the build matrix and the checksum
artefact, and `.github/workflows/release.yml` builds and publishes them on a `v*`
tag, pushing the Homebrew cask and the Scoop manifest from the same run.

`install.sh` and `install.ps1` download and verify the published binary for the
detected platform, so no Go toolchain is needed. A default run refuses a
published release older than the v0.5.0 rewrite baseline instead of installing it; pass an
explicit `--version` to install an older release.

## What Tokenhush never does at deploy time

- It never terminates TLS. There is no certificate listener and no MITM.
- It installs no root certificate and makes no system trust store changes.
- It binds loopback only: `127.0.0.1` always, plus `[::1]` when the host has an
  IPv6 loopback. A non-loopback bind is rejected by construction.

## See also

- [tool-setup.md](tool-setup.md) for pointing a tool at the gateway.
- [verify.md](verify.md) for the local echo-upstream check.
- [generated/network-egress.md](generated/network-egress.md) for the two
  vendor-bound egress categories.
- [security.md](security.md) for the full security model.
