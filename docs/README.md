# Tokenhush documentation

**English** | [中文](README.zh-CN.md)

> Status: V1 (2026-09). Start here; each link goes to one focused document. Paths and claims match the `v0.4.0` release line and `main`.

Tokenhush is a local base-URL gateway. Point your AI coding tools at `http://127.0.0.1:8787`; it redacts secrets and sensitive data before forwarding requests upstream. It all runs on your machine. The public core never installs a root certificate or performs MITM.

## 📚 Documents

| Document | What it covers |
|---|---|
| [deployment.md](deployment.md) | Install on macOS, Linux, and Windows; first run; foreground flags; OS-managed background operation; directories; upgrade and uninstall; troubleshooting |
| [tool-setup.md](tool-setup.md) | Per-tool setup (Claude Code, Codex, Aider, Cline, Roo, opencode, Qwen Code, Charm Crush, Zed, Continue.dev, Open WebUI, Goose, OpenHands, Kilo Code): where each tool's config lives, the exact value to set, how to merge it without clobbering existing config, how to verify and revert, plus the route reachability matrix and the `tokenhush.yaml` reference |
| [architecture.md](architecture.md) | Request path, module layout, and the open-core boundary |
| [security.md](security.md) | Threat model, hard invariants, detector trade-offs, and disclosure |
| [verify.md](verify.md) | Verify redaction on your own machine: a loopback echo upstream shows the placeholder that leaves and the value that comes back |
| [oss-testing.md](oss-testing.md) | Self-test guide for the public core: build from source, connect a real AI tool, run the five-point acceptance checklist, and troubleshoot |
| [plugins.md](plugins.md) | Writing content plugins (Inspector / Transformer) |
| [extension-api.md](extension-api.md) | Cross-layer extension points and the registration contract |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Build, test, and contribution workflow, including the private vulnerability disclosure process |
| [../SECURITY.md](../SECURITY.md) | Vulnerability disclosure policy: supported versions, private reporting channel, and response times |

## 📚 Suggested reading paths

**New user.** Read [deployment.md](deployment.md) to install and start, then [tool-setup.md](tool-setup.md) to connect a tool. For Claude Code only, the quick start in [../README.md](../README.md) is enough.

**Operator.** Read [security.md](security.md) for the invariants and threat model, then [deployment.md](deployment.md) section 5 (control token, session files) and section 10 (deployment constraints).

**Integrator.** Read [architecture.md](architecture.md) for the request path, then [extension-api.md](extension-api.md) and [plugins.md](plugins.md) to add a router, cost sink, or content plugin.
