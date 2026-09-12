# Tokenhush documentation

**English** | [中文](README.zh-CN.md)

> Status: V1 (2026-09). Start here; each link goes to one focused document. Paths and claims match the `v0.3.0` release line and `main`.

Tokenhush is a local base-URL gateway. Point your AI coding tools at `http://127.0.0.1:8787`; it redacts secrets and sensitive data before forwarding requests upstream. It all runs on your machine. The public core never installs a root certificate or performs MITM.

## Documents

| Document | What it covers |
|---|---|
| [deployment.md](deployment.md) | Install on macOS, Linux, and Windows; first run; foreground flags; OS-managed background operation; directories; upgrade and uninstall; troubleshooting |
| [configuration.md](configuration.md) | Per-tool setup (Claude Code, Codex, Aider, Cline, Roo, opencode, Qwen Code, Charm Crush, Zed, Continue.dev, Open WebUI, Goose, OpenHands, Kilo Code), the route reachability matrix, and the `tokenhush.yaml` reference |
| [architecture.md](architecture.md) | Request path, module layout, and the open-core boundary |
| [security.md](security.md) | Threat model, hard invariants, detector trade-offs, and disclosure |
| [plugins.md](plugins.md) | Writing content plugins (Inspector / Transformer) |
| [extension-api.md](extension-api.md) | Cross-layer extension points and the registration contract |
| [migration-v0.2.0.md](migration-v0.2.0.md) | Migrating from v0.1.x: the audit capability moved to the Pro layer |
| [migration-v0.3.0.md](migration-v0.3.0.md) | Migrating to v0.3.0: the `pkg/gateway` assembly layer, the `/v1/models` named exception, and 9 more `env` tools |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Build, test, and contribution workflow, including the private vulnerability disclosure process |

## Suggested reading paths

**New user.** Read [deployment.md](deployment.md) to install and start, then [configuration.md](configuration.md) to connect a tool. For Claude Code only, the quick start in [../README.md](../README.md) is enough.

**Operator.** Read [security.md](security.md) for the invariants and threat model, then [deployment.md](deployment.md) section 5 (control token, session files) and section 10 (deployment constraints).

**Integrator.** Read [architecture.md](architecture.md) for the request path, then [extension-api.md](extension-api.md) and [plugins.md](plugins.md) to add a router, cost sink, or content plugin.
