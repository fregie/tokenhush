# Tool setup guide

**English** | [中文](tool-setup.zh-CN.md)

> Status: V1 (2026-09). Per-tool, step-by-step setup for every tool `tokenhush env` supports, plus the route reachability matrix and the `tokenhush.yaml` reference.

Tokenhush is a local base-URL gateway: you point an AI coding tool's API base URL at `http://127.0.0.1:8787`, and it redacts secrets before forwarding upstream. This guide covers, for each supported tool, where the setting lives, which value to use, how to merge it without clobbering your existing config, how to select the provider/model, and how to verify and revert.

If you only want the copy-paste one-liner, `tokenhush env <tool>` prints it. This document is the long form of that same snippet.

## 🎯 Before you start

1. **Start the gateway.** `tokenhush run` stays in the foreground and prints `tokenhush: gateway listening on http://127.0.0.1:<port>`. The default port is `8787`. See [deployment.md](deployment.md) for packages, service wrappers, and directories.
2. **Confirm it is up.** `tokenhush status` prints `requests` and `redactions` counters. After a tool sends a request, both let you confirm traffic reached the gateway. `tokenhush status --json` renders the same fields as JSON.
3. **Print the snippet.** `tokenhush env <tool>` renders the current port. Add `--port N` to match a non-default gateway, or `--config PATH` to read `tokenhush.yaml` from another location.
4. **Match your shell.** On macOS and Linux `tokenhush env` prints POSIX `export` lines. On Windows PowerShell it prints `$env:NAME = "..."` for the current session plus `setx` lines to persist. Run `tokenhush env` and copy its exact output when in doubt.

### Two base-URL shapes

Which value you paste depends on the protocol the tool speaks, not on the tool's name:

| Shape | Value | Clients |
|---|---|---|
| Bare origin | `http://127.0.0.1:8787` | Anthropic-protocol clients (`/v1/messages`) |
| `/v1` | `http://127.0.0.1:8787/v1` | OpenAI-compatible clients (`/v1/chat/completions`, `/v1/responses`) |

The gateway routes unmatched paths by protocol: `/v1/messages` to Anthropic, `/v1/chat/completions` and `/v1/responses` to OpenAI. `GET /v1/models` is the one named exception and defaults to OpenAI. Every other unknown path is an explicit error, never a silent misroute. See the [route reachability matrix](#route-reachability-matrix) and [security.md](security.md#named-routing-exceptions).

> [!NOTE]
> **Secrets, keys, and API keys.** Tokenhush sits on loopback and does not change your tool's credentials; you still need a valid key for the upstream model. Where a tool requires an API key field, enter your real upstream key (or a placeholder if your gateway accepts one). Never commit a key to a repository-tracked config file.

### Per-tool summary

| Tool | Snippet command | Base URL | Default upstream | Configure in |
|---|---|---|---|---|
| Claude Code CLI | `tokenhush env claude` | bare origin | Anthropic | Shell env, or `~/.claude/settings.json` |
| Codex CLI | `tokenhush env codex` | `/v1` | OpenAI | `~/.codex/config.toml` |
| Aider | `tokenhush env aider` | `/v1` and bare origin | OpenAI / Anthropic | Shell env, `.env`, or `.aider.conf.yml` |
| Cline | `tokenhush env cline` | `/v1` | OpenAI | VS Code extension settings |
| Roo Code | `tokenhush env roo` | `/v1` | OpenAI | VS Code extension settings |
| opencode | `tokenhush env opencode` | `/v1` | OpenAI | `opencode.json` |
| Qwen Code | `tokenhush env qwen` | `/v1` and bare origin | OpenAI / Anthropic | Shell env |
| Charm Crush | `tokenhush env crush` | `/v1` | OpenAI | `crush.json` |
| Zed | `tokenhush env zed` | `/v1` | OpenAI | `settings.json` |
| Continue.dev | `tokenhush env continue` | `/v1` | OpenAI | `~/.continue/config.yaml` |
| Open WebUI | `tokenhush env openwebui` | `/v1` | OpenAI | Shell env, or Admin → Connections |
| Goose | `tokenhush env goose` | bare host + `v1` path | OpenAI | Shell env |
| OpenHands | `tokenhush env openhands` | `/v1` | OpenAI | Shell env, or `[llm].base_url` |
| Kilo Code | `tokenhush env kilo` | `/v1` | OpenAI / Anthropic | VS Code extension settings |

**Default upstream** is what the tool reaches when no `upstreams:` block is configured. If your provider is not that, read the next section.

<a id="configuring-request-routing-upstreams"></a>
## ⚙️ Configuring request routing (`upstreams:`)

Pointing a tool at the gateway is only half of the setup. The gateway then decides **which provider** each request goes to, and it decides by the **request path** — it never sees the tool's name. This section is the whole routing contract.

### How the gateway picks an upstream

First match wins:

1. **exact path** key in `upstreams:` (for example `/v1/chat/completions`);
2. **exact host** key in `upstreams:` (case-insensitive; a key that names a port is tried before one that does not);
3. **longest path-prefix** key in `upstreams:` (matched on path-segment boundaries, so `/v1` matches `/v1/chat/completions` but not `/v1beta/x`);
4. the **built-in table**: `/v1/messages` and `/v1/messages/count_tokens` → Anthropic; `/v1/chat/completions` and `/v1/responses` → OpenAI;
5. the **named exception**: `GET /v1/models` → OpenAI;
6. otherwise a typed error (`ErrUnknownUpstream`) — never a guess, never a silent misroute.

With no `upstreams:` block, an OpenAI-compatible tool goes to `https://api.openai.com` and an Anthropic tool to `https://api.anthropic.com`. If that is your provider, you are done.

### The `upstreams:` block

`upstreams:` maps a request **host** or **path prefix** to the base URL the gateway forwards to. The request's own path is appended to that base.

```yaml
upstreams:
  # any request path under /v1 goes to this provider
  /v1: https://api.deepseek.com
```

To send only one endpoint to a different provider:

```yaml
upstreams:
  /v1/chat/completions: https://api.deepseek.com
  /v1/models: https://api.deepseek.com
```

The loader validates the block at startup; a bad value is a startup error, never a live route:

- A **key** is a host (`api.example.com`, `api.example.com:443`) or a path starting with `/`. A key must not contain `://`.
- A **value** must be an absolute `http(s)` URL with a host, and must not contain userinfo, a query string, or a fragment.
- Omitting the block, or writing `upstreams: {}`, means "built-ins only".
- Unknown keys anywhere in `tokenhush.yaml` are rejected, so a typo cannot silently disable protection.

**Path joining, precisely.** The gateway forwards to `base + request path`; it only prepends the base, it never rewrites the path. So the base is the provider origin (plus any prefix that comes *before* `/v1`), with no trailing slash. **Do not put `/v1` in the base** — the tool already sends `/v1/chat/completions`:

| Provider endpoint | Base to write |
|---|---|
| `https://host/v1/chat/completions` | `https://host` |
| `https://host/api/v1/chat/completions` | `https://host/api` |

**Host keys vs path keys.** The tool dials `127.0.0.1`, so the request's Host header is `127.0.0.1:8787` and a host key such as `api.example.com` never matches. To route loopback traffic, use a **path** key. Host keys apply only when something in front of the gateway preserves the original authority.

**Credentials.** The tool's auth headers (`Authorization`, `x-api-key`, …) are copied to the upstream byte-for-byte. Put the provider's real API key in the tool's provider settings; the gateway neither adds nor replaces it. Redaction applies to the request **body** only, so the key you send to the provider is the key the provider sees.

### Worked examples

Your provider is OpenAI — nothing to add:

```yaml
# /v1/chat/completions and /v1/responses go to https://api.openai.com
```

An OpenAI-compatible provider (DeepSeek, OpenRouter, Together, a local vLLM/Ollama, …):

```yaml
upstreams:
  /v1: https://api.deepseek.com
```

Split by endpoint: keep Responses on OpenAI, send chat completions to a compatible vendor (exact keys win over the built-in table):

```yaml
upstreams:
  /v1/chat/completions: https://api.deepseek.com
  /v1/models: https://api.deepseek.com
  # /v1/responses is left on the built-in OpenAI route
```

An Anthropic-compatible vendor for Claude Code:

```yaml
upstreams:
  /v1/messages: https://api.example-anthropic-compatible.com
  /v1/messages/count_tokens: https://api.example-anthropic-compatible.com
```

A complete file, for reference:

```yaml
listen:
  host: 127.0.0.1
  port: 8787
upstreams:
  /v1: https://api.deepseek.com
```

### Route reachability matrix

Every tool `tokenhush env` onboards must send a request path the gateway routes. The table lists the paths each integration uses, and `TestToolRouteMatrix` in `internal/cli` asserts each one resolves through `pkg/proxy`:

| Tool | Request path(s) | Upstream |
|---|---|---|
| Claude Code | `/v1/messages` | Anthropic |
| Codex CLI | `/v1/responses` | OpenAI |
| Aider | `/v1/chat/completions` | OpenAI |
| Cline / Roo Code | `/v1/chat/completions` | OpenAI |
| opencode | `/v1/chat/completions`, `/v1/models` | OpenAI |
| Qwen Code | `/v1/chat/completions`, `/v1/messages` | OpenAI / Anthropic |
| Charm Crush | `/v1/chat/completions` | OpenAI |
| Zed | `/v1/chat/completions`, `/v1/models` | OpenAI |
| Continue.dev | `/v1/chat/completions`, `/v1/models` | OpenAI |
| Open WebUI | `/v1/models`, `/v1/chat/completions` | OpenAI |
| Goose | `/v1/chat/completions` | OpenAI |
| OpenHands | `/v1/chat/completions` | OpenAI |
| Kilo Code | `/v1/chat/completions`, `/v1/messages` | OpenAI / Anthropic |

`/v1/models` resolves only because of the named exception (see [security.md](security.md#named-routing-exceptions)). A tool that needs a protocol outside this table — for example Google GenAI `generateContent`, used by Gemini CLI — is marked **未验证 (unverified)** and is not onboarded until the gateway routes it. There are currently no unverified tools.

### Where the file lives, and reloading

| Platform | Config directory |
|---|---|
| macOS | `~/Library/Application Support/tokenhush/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` |

The file is named `tokenhush.yaml`. Override its path with `tokenhush run --config PATH`, or move config and data together with `TOKENHUSH_HOME`. It is read at **startup**, so restart the gateway after editing. `tokenhush doctor` validates the config and the port. For `listen`, `detectors`, `allowlist`, and `log`, see the [`tokenhush.yaml` reference](#tokenhushyaml-reference).

### Limits

- One request path resolves to exactly **one** upstream. A tool that uses a single path therefore reaches a single provider at a time.
- The path cannot be rewritten, only prefixed. Providers that need a non-standard path — for example Azure OpenAI's `/openai/deployments/<deployment>/chat/completions?api-version=…` — are not reachable through `upstreams:` as-is.
- `GET /v1/models` is the only route assigned without a data-bearing signal; an `upstreams:` override still wins over it.

**Verify:** restart, send one request with the tool, then run `tokenhush status`. The `requests` counter should grow; a 4xx/5xx from the upstream usually means the base URL join or the provider key is wrong.

<a id="tokenhushyaml-reference"></a>
## ⚙️ `tokenhush.yaml` reference

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

- `listen.host` takes loopback only; the gateway **never** binds `0.0.0.0` or an empty host. It binds `127.0.0.1` always and `[::1]` as well when the host has an IPv6 loopback; on a host without one it serves `127.0.0.1` only and logs a notice.
- Six deterministic, high-precision detectors: key prefixes, high-entropy strings, JWT, PEM private-key headers, Luhn card numbers, email. A match becomes a stable placeholder like `__PII_email_9f2c8a4b6d1e__`, so upstream never sees the raw value.
- `prefixes` → detector id `prefix`; `private_keys` → `private_key` (see `pkg/config` comments).
- `allowlist` holds literals never redacted.
- The core config has no `audit:` key: a config that still contains one fails to load. The audit block lives in the private Pro layer; the public core keeps only the metadata-only audit seam.
- `upstreams:` maps a host or path prefix to your OpenAI-compatible upstream. Unmatched requests use built-ins: `/v1/messages` routes to Anthropic; `/v1/chat/completions` and `/v1/responses` route to OpenAI. `GET /v1/models` is the single **named exception**: a non-data-bearing model-discovery call that defaults to OpenAI, which an `upstreams:` override can still move. Every other unknown path returns an explicit error (`ErrUnknownUpstream`), never a silent misroute; see [security.md](security.md#named-routing-exceptions).

## 🧩 Claude Code CLI

**Integration:** `ANTHROPIC_BASE_URL` (bare origin).

The quickest path is per-terminal and needs no file edit:

```bash
eval "$(tokenhush env claude)"   # exports ANTHROPIC_BASE_URL
claude
```

To make it persistent, add an `env` block to the user settings file:

- macOS / Linux: `~/.claude/settings.json`
- Windows: `%USERPROFILE%\.claude\settings.json`

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787"
  }
}
```

Merge, do not replace: keep every existing top-level key and add or edit only the `ANTHROPIC_BASE_URL` entry inside `env`. The file is strict JSON (no comments, no trailing commas); a syntax error makes Claude Code ignore it.

- Project scope: the same `env` block also works in a project's `.claude/settings.json` (shared) or `.claude/settings.local.json` (this machine only, usually git-ignored). A user-level `env` block is the least surprising choice.
- Custom auth header: Claude Code also reads `ANTHROPIC_AUTH_TOKEN` if your gateway needs a bearer-style header.
- Verify: start `claude`, run `/status`, and confirm the Anthropic base URL and credential source. Then send one request and watch `tokenhush status` count it.
- Revert: remove `ANTHROPIC_BASE_URL` from the `env` block, or `unset ANTHROPIC_BASE_URL`.
- Tool docs: <https://code.claude.com/docs/en/llm-gateway-connect>.

## 🧩 Codex CLI

**Integration:** `~/.codex/config.toml` → `model_providers.<id>.base_url` (`/v1`).

Codex defaults to the Responses API (`/v1/responses`), which Tokenhush supports.

1. Edit `~/.codex/config.toml` (Windows: `%USERPROFILE%\.codex\config.toml`).
2. Define the provider and select it:

```toml
model_provider = "tokenhush"
model = "<model-id>"

[model_providers.tokenhush]
name = "Tokenhush"
base_url = "http://127.0.0.1:8787/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
```

- `model_provider` selects which provider entry Codex uses; without it, Codex stays on the built-in `openai` provider and never contacts the gateway.
- `env_key` names the environment variable Codex reads for the API key. Export it (or set it in your shell profile) before launching `codex`; it is not read from `config.toml`.
- `wire_api = "responses"` matches Codex's default; Tokenhush supports it, including incremental SSE backfill.
- Merge, do not replace: `model_provider` and `model` are top-level keys, so add them before the first `[table]` line rather than inside a table.

> [!WARNING]
> ChatGPT subscription login (non-API-key) is **not supported** through the gateway: the subscription token is only valid for ChatGPT service paths, and forwarding it to the OpenAI platform API returns 401 (see [openai/codex#34608](https://github.com/openai/codex/issues/34608)). Use API key mode.

- Verify: launch `codex`, send one request, and watch `tokenhush status`.
- Revert: delete the `[model_providers.tokenhush]` table and the `model_provider` key (leave `model` as you like).
- Tool docs: <https://developers.openai.com/codex/config-basic>.

## 🧩 Aider

**Integration:** `OPENAI_API_BASE` (`/v1`) and/or `ANTHROPIC_API_BASE` (bare origin).

Aider is a terminal tool, so the environment-variable route is simplest:

```bash
export OPENAI_API_BASE=http://127.0.0.1:8787/v1
export ANTHROPIC_API_BASE=http://127.0.0.1:8787
aider --model openai/<model-name>
```

- Model prefix matters: an OpenAI-compatible endpoint is selected with the `openai/` prefix; an Anthropic model uses `anthropic/`.
- One-off flag: `aider --openai-api-base http://127.0.0.1:8787/v1`.
- Config file (persistent): put `openai-api-base:` in an `.aider.conf.yml`. Aider looks in the home directory, the git repo root, then the current directory, and later files win.
- Dotenv: keys and settings can also live in the git root's `.env`, which Aider loads automatically.
- Verify: send one edit request and watch `tokenhush status`. `aider --list-models <partial>` confirms a model name is recognized.
- Revert: remove the variables or the YAML key.
- Tool docs: <https://aider.chat/docs/config/aider_conf.html>.

<a id="cline-roo-code"></a>
## 🧩 Cline / Roo Code

**Integration:** OpenAI Compatible base URL in the VS Code extension settings (`/v1`). Roo Code is a Cline fork and uses the same flow.

1. Open the extension's settings panel (the gear icon in the Cline / Roo Code sidebar).
2. Set **API Provider** to **OpenAI Compatible**.
3. Set **Base URL** to `http://127.0.0.1:8787/v1`.
4. Enter your API key (the field is required; use your real upstream key, or a placeholder if your gateway accepts one).
5. Enter the model ID exactly as the upstream expects it.

- Nothing is written to a project file; the extension stores settings itself.
- The extension may still send its own telemetry to its vendor. That traffic does not use this base URL; only model requests do.
- Verify: send one chat request and watch `tokenhush status`.
- Revert: switch **API Provider** back, or clear the base URL.
- Tool docs: [Cline](https://docs.cline.bot/provider-config/openai-compatible) · [Roo Code](https://docs.roocode.com/providers/openai-compatible).

## 🧩 opencode

**Integration:** `opencode.json` → `provider.<id>.options.baseURL` (`/v1`).

Add a provider to the global config (`~/.config/opencode/opencode.json`) or a project-level `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "tokenhush": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Tokenhush",
      "options": { "baseURL": "http://127.0.0.1:8787/v1" }
    }
  }
}
```

- Merge, do not replace: if `provider` already exists, add `tokenhush` as another key inside it and keep the existing providers.
- Select the model: set the top-level `"model": "tokenhush/<model-id>"`, or pass `opencode run -m tokenhush/<model-id>`. The model id must match what the upstream exposes.
- Verify: run `opencode models` to list providers/models, send one request, and watch `tokenhush status`.
- Revert: remove the `tokenhush` provider entry.
- Tool docs: <https://opencode.ai/docs/providers/>.

## 🧩 Qwen Code

**Integration:** `OPENAI_BASE_URL` (`/v1`) and/or `ANTHROPIC_BASE_URL` (bare origin).

Point the CLI at the gateway before launching it. Anthropic-mode requests use the bare origin; OpenAI-mode requests use `/v1`:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
qwen
```

- Put these in your shell profile, or in `~/.qwen/.env`, to avoid retyping them.
- Verify: send one request and watch `tokenhush status`.
- Revert: remove the variables.
- Tool docs: <https://qwenlm.github.io/qwen-code-docs/en/users/configuration/model-providers/>.

## 🧩 Charm Crush

**Integration:** `crush.json` → `providers.<id>.base_url` (`/v1`).

Add a provider to the global config (`~/.config/crush/crush.json`; Windows `%LOCALAPPDATA%\crush\crush.json`) or a project `crush.json` / `.crush.json`:

```json
{
  "$schema": "https://charm.land/crush.json",
  "providers": {
    "tokenhush": {
      "type": "openai",
      "base_url": "http://127.0.0.1:8787/v1"
    }
  }
}
```

- Merge, do not replace: add `tokenhush` alongside the providers already present.
- Select the model in the Crush model picker (or `/models`), after the provider is registered.
- Verify: send one request and watch `tokenhush status`.
- Revert: remove the `tokenhush` provider entry.
- Tool docs: <https://github.com/charmbracelet/crush>.

## 🧩 Zed

**Integration:** `settings.json` → `language_models.openai_compatible.<id>.api_url` (`/v1`).

Add an OpenAI-compatible provider:

```json
{
  "language_models": {
    "openai_compatible": {
      "tokenhush": {
        "api_url": "http://127.0.0.1:8787/v1",
        "available_models": [
          { "name": "<model-id>", "display_name": "<display-name>", "max_tokens": 200000 }
        ]
      }
    }
  }
}
```

- Settings file: `~/.config/zed/settings.json` on macOS and Linux, `%APPDATA%\Zed\settings.json` on Windows.
- Merge, do not replace: add `tokenhush` inside the existing `openai_compatible` object.
- `available_models` is required: Zed does not auto-discover a custom endpoint, so only declared models appear in the picker. `max_tokens` is the context window.
- API key: enter it in the provider's setup UI. Do **not** put an API key in `settings.json`; if you prefer an environment variable, use `<PROVIDER_ID>_API_KEY` (for `tokenhush`, `TOKENHUSH_API_KEY`).
- Select the model in the Agent Panel's model picker.
- Verify: send one request and watch `tokenhush status`.
- Revert: remove the `tokenhush` entry.
- Tool docs: <https://zed.dev/docs/ai/use-api-access>.

## 🧩 Continue.dev

**Integration:** `~/.continue/config.yaml` → `models[].apiBase` (`/v1`).

Add a model to the config:

```yaml
models:
  - name: tokenhush
    provider: openai
    apiBase: "http://127.0.0.1:8787/v1"
```

- File location: `~/.continue/config.yaml` (Windows: `%USERPROFILE%\.continue\config.yaml`). Older Continue builds use `config.json` with the same `apiBase` key; if `config.yaml` exists it is loaded instead.
- Merge, do not replace: append this entry to the existing `models:` list.
- Continue reloads automatically when you save the file — no restart needed.
- Verify: send one request and watch `tokenhush status`.
- Revert: remove the model entry.
- Tool docs: <https://docs.continue.dev/customize/model-providers/top-level/openai>.

## 🧩 Open WebUI

**Integration:** `OPENAI_API_BASE_URL` (`/v1`), or the Connections settings.

Set the endpoint before starting the server:

```bash
export OPENAI_API_BASE_URL=http://127.0.0.1:8787/v1
```

- Or configure it in the UI: **Admin Settings → Connections → OpenAI** (labeled **Manage OpenAI API Connections** in newer builds), then add the base URL and key.
- The model picker calls `GET /v1/models`, which the gateway routes through its named exception.
- Verify: refresh the model list, send one request, and watch `tokenhush status`.
- Revert: remove the variable or the connection.
- Tool docs: <https://docs.openwebui.com/getting-started/quick-start/connect-a-provider/starting-with-openai-compatible>.

## 🧩 Goose

**Integration:** `OPENAI_HOST` + `OPENAI_BASE_PATH`.

Set the host and the base path separately before launching `goose`:

```bash
export OPENAI_HOST=http://127.0.0.1:8787
export OPENAI_BASE_PATH=v1
```

- `OPENAI_HOST` is the bare host; do not append `/v1` to it. The path goes in `OPENAI_BASE_PATH`.
- Verify: send one request and watch `tokenhush status`.
- Revert: remove the variables.
- Tool docs: <https://goose-docs.ai>.

## 🧩 OpenHands

**Integration:** `LLM_BASE_URL` (`/v1`), or `[llm].base_url` in its config file.

Point the LLM at the gateway with an environment variable:

```bash
export LLM_BASE_URL=http://127.0.0.1:8787/v1
```

- Or set `base_url` under the `[llm]` section of its `config.toml`.
- Model naming follows the LiteLLM convention: an OpenAI-compatible endpoint uses the `openai/` prefix, for example `openai/<model-id>`.
- Verify: send one request and watch `tokenhush status`.
- Revert: remove the variable or the config key.
- Tool docs: <https://docs.openhands.dev/openhands/usage/llms/custom-llm-configs>.

## 🧩 Kilo Code

**Integration:** OpenAI Compatible base URL in the VS Code extension settings (`/v1`).

1. Open the extension settings and find the API provider section.
2. Set the provider to **OpenAI Compatible**.
3. Set the **Base URL** to `http://127.0.0.1:8787/v1`.
4. Enter the API key and the model ID.

- Nothing is written to a project file; the extension stores settings itself.
- Verify: send one request and watch `tokenhush status`.
- Revert: switch the provider back, or clear the base URL.
- Tool docs: <https://kilo.ai/docs/ai-providers/openai-compatible>.

## 🛠️ Troubleshooting

- **The tool cannot connect.** Confirm the gateway is running with `tokenhush status`, then confirm the port in the tool matches the port `tokenhush run` printed.
- **404 or "unknown upstream".** The base-URL shape is wrong. Anthropic-protocol clients take the bare origin; OpenAI-compatible clients take `/v1`. A wrong suffix is an explicit error, not a silent misroute.
- **Nothing is redacted.** Check that the detectors are enabled in `tokenhush.yaml` and that the value is not on the `allowlist`. See the [`tokenhush.yaml` reference](#tokenhushyaml-reference).
- **Requests never reach the gateway.** Some tools keep a cached provider selection; reselect the provider. For VS Code extensions, the setting lives in the extension, not in a project file.
- **A remote, container, or SSH session.** `127.0.0.1` refers to the machine the tool runs on, not your laptop. Run the gateway on that host or forward the port.
- **Verify end to end.** After any change, send one request and watch the `requests` counter in `tokenhush status` increase. To see redaction itself with a local echo upstream, follow [verify.md](verify.md).

## 🔁 What leaves your machine

The gateway's own vendor-bound requests are limited to the two switchable, command-scoped categories in the [network egress disclosure](generated/network-egress.md): rule sync and update check, each with its own off switch. A tool's own telemetry is separate and does not use this base URL. See [security.md](security.md) for the threat model and hard invariants.

## 📚 See also

- [deployment.md](deployment.md) — installation, first run, and OS-native background operation.
- [verify.md](verify.md) — prove redaction with a local echo upstream.
- [security.md](security.md) — threat model and hard invariants.
