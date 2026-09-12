# Configuration

**English** | [中文](configuration.zh-CN.md)

> Status: V1 implemented (2026-09). Commands and defaults track `main`; [`scripts/check-docs.sh`](../scripts/check-docs.sh) verifies that every documented command and config key actually exists.

This page shows how to point your AI coding tools at the local Tokenhush gateway. For the security model behind redaction, see [security.md](security.md).

## General workflow

1. Start the gateway in the foreground: `tokenhush run`. It listens on `127.0.0.1:8787` by default.
2. Point the tool's API base URL at the gateway.
3. Print a ready-to-paste snippet with `tokenhush env <tool>`, or configure the tool by hand from the sections below.

All requests travel as plaintext HTTP to loopback, so the gateway can read the full body and redact it. No root certificate is needed.

> [!NOTE]
> Windows, Linux, and macOS are all supported. The `export` snippets below are POSIX (macOS / Linux). On Windows PowerShell, use `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"` and `setx` to persist it. `tokenhush env` picks the right dialect for the current platform automatically.

## Claude Code CLI

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
# Claude Code also accepts ANTHROPIC_AUTH_TOKEN if you need a custom auth header
```

> [!NOTE]
> With a Claude Max/Pro subscription, inference requests honor `ANTHROPIC_BASE_URL` (see the [Anthropic LLM gateway docs](https://code.claude.com/docs/en/llm-gateway)), and the gateway must forward `anthropic-beta` verbatim. OAuth refresh and authorization always go to `platform.claude.com` and `claude.ai`, never through the gateway. For a live-session capture flow, see [`scripts/oauth-matrix.sh`](../scripts/oauth-matrix.sh) `--capture`.

## Codex CLI

Edit `~/.codex/config.toml`:

```toml
model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }
```

Codex uses the **Responses API** (`/v1/responses`) by default. Tokenhush supports that protocol, including incremental SSE backfill.

> [!WARNING]
> ChatGPT subscription login (non-API-key) is **not supported** through the gateway today. The subscription token is only valid for ChatGPT service paths, and forwarding it to the OpenAI platform API returns 401 (see [openai/codex#34608](https://github.com/openai/codex/issues/34608)). Use API key mode instead.

## Aider

```bash
export OPENAI_API_BASE=http://127.0.0.1:8787/v1
export ANTHROPIC_API_BASE=http://127.0.0.1:8787
# or on the command line:
aider --openai-api-base http://127.0.0.1:8787/v1
```

## Cline / Roo Code

These are VS Code extensions. In the extension settings choose "OpenAI Compatible" (or Anthropic) and set the base URL:

```text
Base URL: http://127.0.0.1:8787/v1
```

## Continue

Edit `~/.continue/config.json` and set `apiBase` inside `models`:

```json
{
  "models": [
    {
      "apiBase": "http://127.0.0.1:8787/v1"
    }
  ]
}
```

## Open WebUI

Under **Connections**, add an OpenAI-compatible endpoint and use this URL:

```text
Base URL: http://127.0.0.1:8787/v1
```

## `tokenhush.yaml` reference

The config file lives in the platform config directory (`pkg/platform.ConfigDir()`): macOS `~/Library/Application Support/tokenhush/`, Linux `${XDG_CONFIG_HOME:-~/.config}/tokenhush/`, Windows `%AppData%\tokenhush\`. Override it with `--config PATH`, or move both the config and data directories with `TOKENHUSH_HOME`. A missing file means "use defaults"; **unknown keys are rejected**, so a typo cannot silently disable protection.

Full defaults:

<!-- check-docs:config:start -->
```yaml
listen:
  host: 127.0.0.1      # only 127.0.0.1 / ::1 / localhost; 0.0.0.0 is rejected
  port: 8787           # 1..65535
detectors:
  prefixes: true       # known key prefixes (sk-, AKIA, ghp_, ...)
  high_entropy: true   # high-entropy strings
  jwt: true            # JWTs
  private_keys: true   # PEM private-key headers
  luhn: true           # card numbers (Luhn)
  email: true          # email addresses
allowlist: []          # literals that are never redacted
log:
  level: info          # debug | info | warn | error
upstreams:             # host or path prefix -> upstream base URL
  api.example.com: https://api.example.com
```
<!-- check-docs:config:end -->

Key points:

- `listen.host` accepts loopback only. The gateway **never** binds `0.0.0.0` or an empty host; it binds dual-stack loopback (`127.0.0.1` and `[::1]`).
- The six detectors are deterministic and tuned for high precision: known key prefixes, high-entropy strings, JWT, PEM private-key headers, Luhn card numbers, and email.
- Two YAML keys deliberately differ from their detector id: `prefixes` maps to id `prefix`, and `private_keys` maps to id `private_key` (see the `pkg/config` comments).
- `allowlist` holds literals that are never redacted.
- There is no `audit:` block in the core config. Audit configuration moved to the private Pro layer; a config that still contains `audit:` fails to load with an actionable migration error. See [migration-v0.2.0.md](migration-v0.2.0.md).
- `upstreams:` forwards a host or path prefix to your own OpenAI-compatible upstream. Unmatched requests fall back to the built-ins: `/v1/messages` routes to Anthropic; `/v1/chat/completions` and `/v1/responses` route to OpenAI. An unknown path returns an explicit error and is never silently misrouted.

## Known limitations

> [!IMPORTANT]
> Read this section before you rely on the gateway for a subscription login.

- **Subscription OAuth login**
  - **Claude Code (subscription login):** inference requests honor the base URL (Anthropic's docs confirm this; the gateway must forward `anthropic-beta` verbatim). Auth and refresh stay on `platform.claude.com` and similar domains, so they never pass through the gateway. See the live-session flow in [`scripts/oauth-matrix.sh`](../scripts/oauth-matrix.sh).
  - **Codex CLI (ChatGPT subscription login):** not supported in V1. See the Codex section above and use an API key.
- **Telemetry endpoints bypass the base URL:** some tools send telemetry to PostHog, Sentry, and similar services. It carries little content, but you should know it happens.
- **Not covered:** Cursor agent traffic (which goes to `api2.cursor.sh`), the ChatGPT and Claude desktop apps, and browser web UIs. These need a system-level approach and are not implemented in the public core.

## Connectivity self-check

```bash
<!-- check-docs:commands:start -->
tokenhush version       # confirm the binary runs
tokenhush doctor        # diagnose config, keyring, and port problems
tokenhush env claude    # print the setup snippet, including the current port
<!-- check-docs:commands:end -->
```

`run` prints the listening address and the control-token file path when it starts. `tokenhush status` reports whether the gateway is running. `env` and `doctor` accept `--config PATH` and `--port N`, so a self-check matches the gateway you actually started. The control plane exposes `GET /status` and requires the bearer token, which is regenerated on every `run`. The concrete audit store, the `audit` subcommand, and the audit endpoint live in the private Pro layer.
