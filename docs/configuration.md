# Configuration

**English** | [中文](configuration.zh-CN.md)

> Status: V1 (2026-09). Commands and defaults track `main`; [`scripts/check-docs.sh`](../scripts/check-docs.sh) checks every documented command and config key.

Point your AI coding tools at the local Tokenhush gateway. Redaction security model: [security.md](security.md).

## General workflow

1. `tokenhush run` starts the gateway (default `127.0.0.1:8787`).
2. Point the tool's API base URL at it.
3. `tokenhush env <tool>` prints a paste-ready snippet, or configure by hand below.

The gateway reads full plaintext HTTP bodies over loopback and redacts them. No root certificate needed.

> [!NOTE]
> Windows, Linux, macOS supported. The `export` snippets are POSIX; on Windows PowerShell use `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"` and `setx` to persist. `tokenhush env` picks the right dialect automatically.

## Claude Code CLI

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
# Claude Code also accepts ANTHROPIC_AUTH_TOKEN if you need a custom auth header
```

> [!NOTE]
> Claude Max/Pro subscription inference honors `ANTHROPIC_BASE_URL` (see the [Anthropic LLM gateway docs](https://code.claude.com/docs/en/llm-gateway)); the gateway must forward `anthropic-beta` verbatim. OAuth refresh and authorization always go to `platform.claude.com` and `claude.ai`, never through the gateway. Live-session capture: [`scripts/oauth-matrix.sh`](../scripts/oauth-matrix.sh) `--capture`.

## Codex CLI

Edit `~/.codex/config.toml`:

```toml
model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }
```

Codex defaults to the **Responses API** (`/v1/responses`); Tokenhush supports it, including incremental SSE backfill.

> [!WARNING]
> ChatGPT subscription login (non-API-key) is **not supported** through the gateway today: the subscription token is only valid for ChatGPT service paths, and forwarding it to the OpenAI platform API returns 401 (see [openai/codex#34608](https://github.com/openai/codex/issues/34608)). Use API key mode instead.

## Aider

```bash
export OPENAI_API_BASE=http://127.0.0.1:8787/v1
export ANTHROPIC_API_BASE=http://127.0.0.1:8787
# or on the command line:
aider --openai-api-base http://127.0.0.1:8787/v1
```

## Cline / Roo Code

VS Code extensions: pick "OpenAI Compatible" (or Anthropic) in settings and set the base URL:

```text
Base URL: http://127.0.0.1:8787/v1
```

## Continue

Edit `~/.continue/config.json`, `apiBase` inside `models`:

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

Under **Connections**, add an OpenAI-compatible endpoint:

```text
Base URL: http://127.0.0.1:8787/v1
```

## `tokenhush.yaml` reference

Config lives in the platform config directory (`pkg/platform.ConfigDir()`): macOS `~/Library/Application Support/tokenhush/`, Linux `${XDG_CONFIG_HOME:-~/.config}/tokenhush/`, Windows `%AppData%\tokenhush\`. Override with `--config PATH`, or move config and data with `TOKENHUSH_HOME`. Missing file means defaults. **Unknown keys are rejected**, so a typo can't silently disable protection: `listenn:` fails the load.

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

- `listen.host` takes loopback only; the gateway **never** binds `0.0.0.0` or an empty host, and binds dual-stack loopback (`127.0.0.1` and `[::1]`).
- Six deterministic, high-precision detectors: key prefixes, high-entropy strings, JWT, PEM private-key headers, Luhn card numbers, email. A match becomes a stable placeholder like `__PII_email_9f2c8a4b6d1e__`, so upstream never sees the raw value.
- `prefixes` → detector id `prefix`; `private_keys` → `private_key` (see `pkg/config` comments).
- `allowlist` holds literals never redacted.
- The core config has no `audit` key. A config that still contains one fails to load with a message pointing to [migration-v0.2.0.md](migration-v0.2.0.md).
- `upstreams:` maps a host or path prefix to your OpenAI-compatible upstream. Unmatched requests use built-ins: `/v1/messages` routes to Anthropic; `/v1/chat/completions` and `/v1/responses` route to OpenAI. Unknown paths return an explicit error, never a silent misroute.

## Known limitations

> [!IMPORTANT]
> Read this before relying on the gateway for a subscription login.

- **Subscription OAuth login**
  - **Claude Code (subscription login):** inference honors the base URL. Auth and refresh stay on `platform.claude.com` and similar domains, never through the gateway. Live-session flow: [`scripts/oauth-matrix.sh`](../scripts/oauth-matrix.sh).
  - **Codex CLI (ChatGPT subscription login):** not supported in V1. See Codex above; use an API key.
- **Telemetry endpoints bypass the base URL:** some tools send telemetry to PostHog, Sentry, and similar services. Little content, but it happens.
- **Not covered:** Cursor agent traffic (to `api2.cursor.sh`), the ChatGPT and Claude desktop apps, and browser web UIs. These need a system-level approach, absent from the public core.

## Connectivity self-check

```bash
<!-- check-docs:commands:start -->
tokenhush version       # confirm the binary runs
tokenhush doctor        # diagnose config, keyring, and port problems
tokenhush env claude    # print the setup snippet, including the current port
<!-- check-docs:commands:end -->
```

`run` prints the listening address and control-token path at startup. `tokenhush status` reports whether the gateway runs. `env` and `doctor` accept `--config PATH` and `--port N`, so a self-check matches the gateway you started. `GET /status` needs the bearer token, regenerated each `run`.
