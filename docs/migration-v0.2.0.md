# Migration to v0.2.0

**English** | [中文](migration-v0.2.0.zh-CN.md)

> Status: applies to the `v0.2.0` core release. Read this before upgrading a `v0.1.x` install.

## What changed

In `v0.2.0`, the concrete audit implementation moved out of the public core and into the private Pro layer. The core keeps only the audit seam:

- `pkg/audit` still defines the `Record` and `Query` types and the `AuditSink` / `AuditQuerier` interfaces, plus a no-op sink.
- The proxy and the plugin policy engine still emit metadata-only audit records through an injected `AuditSink`; the default core sink discards them.
- The core no longer includes:
  - the local audit store (persistence, tamper-evident HMAC chain, retention);
  - the `tokenhush audit` subcommand;
  - the `GET /audit` control endpoint;
  - the `audit:` configuration block.

The private Pro layer owns the concrete store, the audit subcommand, the audit endpoint, and the audit configuration. A public interface is not a public implementation: the public binary contains no audit store, so there is nothing to unlock there.

The honest product claim is unchanged: **"high-confidence secret interception + full auditability"**, never "never leaks".

## Required config change

Delete the `audit:` block from `tokenhush.yaml`. Both the block form and the inline form are rejected:

```yaml
# REMOVE this block in v0.2.0
audit:
  enabled: true
  retention_days: 14
```

```yaml
# Also rejected:
audit: {enabled: true}
```

If you leave the key in place, `tokenhush run` and every other command that loads the config fail at startup with an `unknown field` error and an actionable message that names the key and points to the Pro layer. Remove the block, then start the gateway again. The remaining keys (`listen`, `detectors`, `allowlist`, `log`, `upstreams`) are unchanged.

## Data is not migrated

There is no migration of existing audit data. The `v0.1.x` local audit database is not read, converted, or copied by `v0.2.0`, and the core no longer opens it at all. Treat the upgrade as a clean cut: if you need the old data, export or archive it yourself before upgrading.

## Audit in Pro

The concrete audit capability (persistence, tamper-evident chain, retention policy, query command, audit endpoint, and audit configuration) lives in the private Pro layer, which imports this core module. See that layer's own documentation for setup, operations, and how to bring audit back on.

## Release notes (GitHub Release v0.2.0)

Pushing the `v0.2.0` tag publishes the GitHub Release automatically. Suggested highlights:

- **Breaking:** the `audit:` config block was removed; a config that still contains it fails to load with a migration error. Delete the block before upgrading.
- **Breaking:** `tokenhush audit`, the `GET /audit` control endpoint, and the local audit store were removed from the public core.
- **Changed:** the core now exposes only the metadata-only audit seam (`pkg/audit` types and the `AuditSink` / `AuditQuerier` interfaces) with a no-op default.
- **Note:** existing local audit data is not migrated.
- The concrete audit implementation now ships in the private Pro layer.
- Everything else (`run`, `status`, `env`, `doctor`, `version`, redaction, detectors, and the extension API) is unchanged.

## See also

- [configuration.md](configuration.md) for the `tokenhush.yaml` reference.
- [architecture.md](architecture.md) for the seam and the open-core boundary.
- [security.md](security.md) for the audit seam and integrity model.
