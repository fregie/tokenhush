# Tool setup and request routing

**English** | [中文](tool-setup.zh-CN.md)

Any tool that lets you override its OpenAI-compatible or Anthropic base URL can
sit behind Tokenhush. Point that URL at the loopback gateway and the tool keeps
working the same way; the gateway redacts the request body on the way out and
restores it on the way back.

The gateway listens on `http://127.0.0.1:8787` by default.

## The one rule

Two client styles, two URL shapes. You only need the one that matches your tool:

- **Anthropic-style clients take the bare origin:** `http://127.0.0.1:8787`.
- **OpenAI-compatible clients take `/v1`:** `http://127.0.0.1:8787/v1`.

`tokenhush env <tool>` prints the right one for the tool you name, in your
shell's dialect. The sections below show the same snippets. If you moved the
port with `--port` or `listen.port`, replace `8787` with your port.

## Tools

The order is the order `tokenhush env` lists them in.

### claude

```sh
export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"
```

### codex

Add to `~/.codex/config.toml`:

```toml
model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }
```

Only API-key mode can pass through the gateway. The ChatGPT subscription login
cannot.

### aider

```sh
export OPENAI_API_BASE="http://127.0.0.1:8787/v1"
export ANTHROPIC_API_BASE="http://127.0.0.1:8787"
```

### cline

In VS Code: Settings, then API Provider, then "OpenAI Compatible", then set the
Base URL to:

```text
http://127.0.0.1:8787/v1
```

### roo

Roo Code uses the same VS Code settings path as Cline: Settings, then API
Provider, then "OpenAI Compatible", then Base URL:

```text
http://127.0.0.1:8787/v1
```

### opencode

Add to `opencode.json` a provider named `tokenhush`:

```json
{
  "provider": {
    "tokenhush": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Tokenhush",
      "options": {
        "baseURL": "http://127.0.0.1:8787/v1"
      }
    }
  }
}
```

### qwen

```sh
export OPENAI_BASE_URL="http://127.0.0.1:8787/v1"
export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"
```

### crush

Add to `crush.json` a provider named `tokenhush`:

```json
{
  "providers": {
    "tokenhush": {
      "type": "openai",
      "base_url": "http://127.0.0.1:8787/v1"
    }
  }
}
```

### zed

In `settings.json`:

```json
{
  "language_models": {
    "openai_compatible": {
      "tokenhush": {
        "api_url": "http://127.0.0.1:8787/v1"
      }
    }
  }
}
```

### continue

In `~/.continue/config.yaml`, add a model named `tokenhush`:

```yaml
models:
  - name: tokenhush
    provider: openai
    apiBase: "http://127.0.0.1:8787/v1"
```

### openwebui

Export the base URL before starting the server:

```sh
export OPENAI_API_BASE_URL="http://127.0.0.1:8787/v1"
```

### goose

```sh
export OPENAI_HOST="http://127.0.0.1:8787"
export OPENAI_BASE_PATH="v1"
```

Note that Goose splits the origin (`OPENAI_HOST`) from the path prefix
(`OPENAI_BASE_PATH`), which is why it does not take `/v1` in the host value.

### openhands

```sh
export LLM_BASE_URL="http://127.0.0.1:8787/v1"
```

The same value can go in the `[llm].base_url` setting instead.

### kilo

Kilo Code uses the same VS Code settings path as Cline: Settings, then API
Provider, then "OpenAI Compatible", then Base URL:

```text
http://127.0.0.1:8787/v1
```

## Any other tool

If your tool is not in the list, you do not need a snippet. Set one of two
values:

- its OpenAI-compatible base URL to `http://127.0.0.1:8787/v1`, or
- its Anthropic base URL to `http://127.0.0.1:8787`.

Then confirm the round trip with the local check in
[verify.md](verify.md).

## Configuring request routing (`upstreams`)

Routing is by **request path**, not provider name. The gateway reads the path,
picks an upstream, appends the request, and sends it. One path maps to one
upstream.

Declare your own upstreams under `upstreams:`. It is a **list** of
`{match, target}` entries, not a map:

- `match` is a path prefix.
- `target` is an origin with no trailing slash and **no `/v1`**.

Use the provider origin. Your tool already sends the full path, and the gateway
appends it. This is what makes a relay work without special handling.

```yaml
upstreams:
  - match: /v1/chat/completions
    target: https://your-provider.example.com
```

A configured `upstreams` entry wins over the built-in table. When no entry
matches, the built-ins apply:

| Request path | Built-in upstream |
|---|---|
| `/v1/messages` | Anthropic |
| `/v1/chat/completions` | OpenAI |
| `/v1/responses` | OpenAI |
| `GET /v1/models` | OpenAI (the one named exception) |
| any other unknown path | explicit error |

`GET /v1/models` is the one named exception: it defaults to OpenAI instead of
being treated as an unknown path. Any other unknown path is an explicit error,
never a silent misroute. Near-miss paths are not guessed at.

Because the route is chosen by path and not by model, a relay that serves many
models behind `/v1` is fine: the model is selected by the request body.

Keep your provider's API key in the tool's own config. The gateway forwards auth
headers untouched and redacts only the request body.

## Configuration reference

Tokenhush reads `tokenhush.yaml`. It uses a strict, closed schema: a missing file
means the defaults, and an unknown key is an error rather than a warning. The
whole surface is:

```yaml
listen:            {host: 127.0.0.1, port: 8787}
log:               {level: info}
detectors:         {prefix: true, email: true, luhn: true, jwt: true, pem: true, entropy: false}
allowlist:         ["literal"]
upstreams:         [{match: "/v1/chat/completions", target: "https://api.openai.com"}]
scan_budget_bytes: 33554432
detector_timeout:  30s
response_buffer_bytes: 33554432
response_timeout:  5m
```

| Key | Type | Default | What it does |
|---|---|---|---|
| `listen.host` | string | `127.0.0.1` | Only `127.0.0.1`, `::1`, or `localhost`. `0.0.0.0` is rejected. |
| `listen.port` | integer | `8787` | 1..65535. |
| `log.level` | string | `info` | One of `debug`, `info`, `warn`, `error`. |
| `detectors.prefix` | boolean | `true` | Known key shapes: `sk-`, `AKIA`, `ghp_`, `glpat-`, `xox*`, `AIza`, `npm_`. |
| `detectors.email` | boolean | `true` | Email addresses; a match requires a domain that ends at a label boundary with a known public suffix. |
| `detectors.luhn` | boolean | `true` | Card numbers, Luhn-checked. |
| `detectors.jwt` | boolean | `true` | JSON Web Tokens. |
| `detectors.pem` | boolean | `true` | PEM private-key headers. |
| `detectors.entropy` | boolean | `false` | High-entropy strings. Off by default and opt-in: false positives on real agent traffic (long tool names, session ids) broke function calling. |
| `allowlist` | list of strings | empty | Literals that are never redacted. |
| `upstreams` | list of `{match, target}` | empty | Path-prefix routes to your own origins. |
| `scan_budget_bytes` | integer | `33554432` (32 MiB) | Deterministic scan budget. |
| `detector_timeout` | duration | `30s` | Detection backstop. |
| `response_buffer_bytes` | integer | `33554432` (32 MiB) | Total cap on one buffered response. An over-cap response is a 502 before any byte is committed. |
| `response_timeout` | duration | `5m` | Overall bound on reading one response. A response past the deadline is a 504 before any byte is committed. If the cap and the deadline trip together, the cap wins. |

Every upstream response is buffered **whole** before any byte reaches the client,
including `text/event-stream`: there is no token-level streaming. A
response-scoped `Block` on the buffered response, SSE included, is a 502 before
any byte is committed, and backfill restores a content-split placeholder exactly
once before that single commit. `response_buffer_bytes` and `response_timeout`
bound the buffered body and the whole read; over the cap is a 502, past the
deadline is a 504, and both are decided before commit.

The detector keys are exactly `prefix`, `email`, `luhn`, `jwt`, `pem`, and
`entropy`. They are not `prefixes`, not `high_entropy`, and not `private_keys`.

The `email` detector matches precisely: an address is a match only when its
domain ends at a label boundary with a known public suffix (`.com`, `.co.uk`),
so subdomains count and a look-alike such as `evilcorp.com` is rejected when the
configured suffix is the narrower `.corp.com` in `replace` mode (an additive
`.corp.com` still carries the built-in `.com`, so `evilcorp.com` would match).
The built-in suffix table is compiled in, frozen, and always on.

## Config and data directories

| Platform | Config dir | Data dir |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/config/` | `~/Library/Application Support/tokenhush/Data/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LocalAppData%\tokenhush\` |

`TOKENHUSH_HOME` moves both to one root: config at
`<TOKENHUSH_HOME>/config` and data at `<TOKENHUSH_HOME>/data`. An empty value
counts as unset.

Pass `--config PATH` to `tokenhush run` or `tokenhush env` to read a specific
`tokenhush.yaml` instead of the default location.

## See also

- [deployment.md](deployment.md) for install paths and service wrappers.
- [verify.md](verify.md) for the local echo-upstream check.
- [security.md](security.md) for the security model behind the loopback bind.
