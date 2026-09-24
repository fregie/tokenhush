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

## Configuration

Tokenhush reads `tokenhush.yaml`. The full reference — every key and its
default, where the file lives, and how to route requests to your own provider —
is in [configuration.md](configuration.md).

The one thing to set before using a relay is an `upstreams` entry. It is a
**list** of `{match, target}` entries: `match` is a request-path prefix and
`target` is the provider origin (plus any prefix before `/v1`) with no trailing
slash and **no `/v1`**.

```yaml
upstreams:
  - match: /v1/chat/completions
    target: https://your-provider.example.com
```

With no `upstreams`, the built-in table applies: `/v1/messages` goes to
Anthropic, and `/v1/chat/completions` and `/v1/responses` go to OpenAI. See
[configuration.md](configuration.md) for the full table, the match rules and
precedence, worked examples, and troubleshooting.

## See also

- [deployment.md](deployment.md) for install paths and service wrappers.
- [verify.md](verify.md) for the local echo-upstream check.
- [security.md](security.md) for the security model behind the loopback bind.
