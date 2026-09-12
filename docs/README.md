# Tokenhush documentation

**English** | [中文](README.zh-CN.md)

> Status: V1 (2026-09). Start here if you are orienting yourself; each link below goes to a focused document. Paths and claims match the `v0.1.0` release and `main`.

Tokenhush is a local base-URL gateway: your AI coding tools send requests to `http://127.0.0.1:8787`, and the gateway redacts secrets and sensitive data before forwarding them upstream, then records a local audit timeline. Everything runs on your machine, and the public core never installs a root certificate or performs MITM. These documents cover how to install and operate it, how it is built, and how to extend it.

## Documents

| Document | What it covers |
|---|---|
| [deployment.md](deployment.md) | Install on macOS, Linux, and Windows; first run; foreground flags; OS-managed background operation; directories; upgrade and uninstall; troubleshooting |
| [configuration.md](configuration.md) | Per-tool setup (Claude Code, Codex, Aider, Cline, Roo, Continue, Open WebUI) and the `tokenhush.yaml` reference |
| [architecture.md](architecture.md) | Request path, module layout, audit chain, and the open-core boundary |
| [security.md](security.md) | Threat model, hard invariants, detector trade-offs, and disclosure |
| [plugins.md](plugins.md) | Writing content plugins (Inspector / Transformer) |
| [extension-api.md](extension-api.md) | Cross-layer extension points (Router, CostSink, AuditExporter) and the registration contract |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Build, test, and contribution workflow, including the private vulnerability disclosure process |

## Suggested reading paths

**New user.** Read [deployment.md](deployment.md) to install and start the gateway, then [configuration.md](configuration.md) to point a tool at it. If you only run Claude Code, the quick start in [../README.md](../README.md) is enough.

**Operator.** Read [security.md](security.md) for the invariants and threat model, then [deployment.md](deployment.md) section 5 for where the control token and audit database live, and section 10 for the deployment constraints.

**Integrator.** Read [architecture.md](architecture.md) for the request path, then [extension-api.md](extension-api.md) and [plugins.md](plugins.md) to add a router, a cost sink, an audit exporter, or a content plugin.
