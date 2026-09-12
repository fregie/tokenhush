# Migration to v0.3.0

**English** | [中文](migration-v0.3.0.zh-CN.md)

> Status: applies to the `v0.3.0` core release. Upgrading from `v0.2.0` requires **no config change**.

## What changed

- **Shared assembly layer (`pkg/gateway`).** The request-path assembly — dual-stack loopback listeners, the per-session control token and `run.json`, the Host-allowlist and per-request stats middleware chain, the data plane, and the bounded graceful shutdown — moved out of `internal/cli` into the exported `pkg/gateway` package. The CLI (`tokenhush run`) behaves the same; the private Pro build assembles on the same layer. The contract is documented in [extension-api.md](extension-api.md).
- **`GET /v1/models` is now a named exception.** It used to be an unknown path and came back as a typed error. It now defaults to OpenAI: model discovery carries no prompt or payload, and both providers expose the same shape. A configured `upstreams:` override still wins, and every other unknown path — including near-misses such as `/v1/model` or `/v1/models/foo` — stays an explicit error. See [security.md](security.md).
- **`tokenhush env` covers 14 tools.** Nine snippets are new: `opencode`, `qwen`, `crush`, `zed`, `continue`, `openwebui`, `goose`, `openhands`, and `kilo`. The original five are `claude`, `codex`, `aider`, `cline`, and `roo`. See [configuration.md](configuration.md).

## No config change required

The `tokenhush.yaml` keys are unchanged from `v0.2.0`: `listen`, `detectors`, `allowlist`, `log`, and `upstreams`. Install and start as usual:

```bash
tokenhush run
```

If you are still on `v0.1.x`, delete the removed `audit:` block before starting `v0.3.0`; see [migration-v0.2.0.md](migration-v0.2.0.md).

## Release notes (GitHub Release v0.3.0)

Pushing the `v0.3.0` tag publishes the GitHub Release automatically. Suggested highlights:

- **Added:** the shared `pkg/gateway` assembly layer, exported for the private Pro build.
- **Changed:** `GET /v1/models` is the one named route exception and defaults to OpenAI; every other unrecognised path remains an explicit typed error.
- **Added:** `tokenhush env` supports nine more tools (`opencode`, `qwen`, `crush`, `zed`, `continue`, `openwebui`, `goose`, `openhands`, `kilo`).
- **Unchanged:** config keys, CLI commands, the audit seam, the hard invariants, and the rest of the extension API.

## See also

- [extension-api.md](extension-api.md) for the `pkg/gateway` assembly contract.
- [security.md](security.md) for the named routing exception and the hard invariants.
- [configuration.md](configuration.md) for the per-tool setup and the `tokenhush.yaml` reference.
