# Security Policy

Tokenhush exists to keep secrets out of AI coding tool requests, so a security report is worth taking seriously. This policy covers the public Apache-2.0 core repository at `github.com/fregie/tokenhush`. It is maintained in English only.

[docs/security.md](docs/security.md) is the operator-facing security contract: the eight invariants, the response-phase effects, the SSE limitation, and the full residual-risk register. This document covers how to report a problem and what to expect afterward.

## Threat model in brief

Tokenhush is a local, loopback-only HTTP gateway between your AI coding tool and the vendor API. It replaces detected secrets in the outbound request body with session-scoped placeholders, forwards the cleaned request, and restores the originals in the response. The model only ever sees placeholders, and placeholders are never filled back in on the way out: only your client receives the originals.

What it guards:

- **Loopback only.** The listener binds `127.0.0.1` always, plus `[::1]` when the host has an IPv6 loopback. A non-loopback bind is impossible by construction.
- **Host and Origin validation.** The Host allowlist is always enforced, and Origin is checked for browser-style requests.
- **A minimal control API.** The control surface is exactly `GET /status`, behind a per-run bearer token stored with `0600` permissions. A missing credential gets `401`, a wrong one gets `403`. A non-GET request gets a JSON `405` with `Allow: GET`, and any other GET gets a JSON `404`. There is no second endpoint and no allowlist mutation endpoint.
- **Nothing persisted.** No request or response bodies, no detected secrets, and no placeholder-to-secret mapping are written to disk. Metadata only: session files, the verified rules cache, and anti-rollback marks. The redaction log is masked, stderr-only, and never persisted.
- **Fail closed, not open.** A detector failure refuses the request with a labelled reason rather than forwarding it unredacted. A request with a non-identity `Content-Encoding` is refused with `415` rather than decoded for detection.
- **No MITM, no root certificate.** Tokenhush terminates no TLS and installs no certificate. An absence guard scans production Go source for any such path and fails the build if one appears.
- **Exactly two vendor-bound egress categories.** Both go to `updates.tokenhush.com`, are command-scoped, and are switchable: update-check (`TOKENHUSH_NO_UPDATE_CHECK=1`) and rule-sync (`TOKENHUSH_NO_RULE_SYNC=1`), with 30-day retention. Beyond those, the only traffic leaving your machine is your own requests to your provider.

## Residual risks

These are known limits of the design, recorded in full in [docs/security.md](docs/security.md). They are not secrets, and reports about them are welcome, but on their own they are known limitations rather than vulnerabilities.

- **R1: encoded secrets are not caught.** A secret that is base64-, hex-, or URL-encoded before it leaves is not detected. There is no normalization pass by design, and a non-identity request `Content-Encoding` is refused with `415` rather than decoded for detection.
- **R2: a secret in a JSON object key is not caught.** A secret placed in a JSON object key rather than a value is forwarded unchanged. Key-position blocking was dropped, so there is no half-working key path.
- **R3: a signed remote pack may weaken detection through its own allowlist.** The non-weakening floor is allowlist-neutral, so a signed pack can suppress matches through its own global or per-rule allowlist. The rule-signing key `rules-2026-09` is the trust root, and a pack that weakens detection is one the holder of that key chose to publish.
- **R4: the OD-2 command-rule rejection is dormant and the v2 manifest bump is backward-incompatible.** The rejection stays dormant until the gate opens, and the gate opens only when the rules manifest `schema_version` reaches 2. That bump breaks clients pinning `== 1`, so the backend must keep serving a v1 manifest until the legacy line is out of support.

The full register carries seven risks, R1 through R7, including the response-path budget limit and the SSE split-envelope shapes. Read them in [docs/security.md](docs/security.md).

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.**

Report privately through GitHub's private vulnerability reporting:

**https://github.com/fregie/tokenhush/security/advisories/new**

That form opens a private security advisory visible only to you and the maintainers. If the form is unavailable, use the contact details on the maintainer's GitHub profile and say you are reporting a vulnerability.

A useful report includes:

- What the issue is, and the impact you believe it has.
- The affected version, commit, or release.
- Steps to reproduce, with a minimal config or request where you can.
- Any proof of concept or logs, with secrets removed.

## Scope

In scope:

- The gateway and its data path: the loopback bind, Host and Origin validation, and the control API.
- The CLI and config parsing.
- Rule sync and self-update verification.
- Redaction correctness: missed secrets, over-redaction that changes behaviour, and restore correctness.
- The published documentation where it misstates a security property.

Out of scope:

- The vendor backend. Report those through the vendor's own channel.
- Third-party tools. Report those to their own projects.
- The documented residual risks above, when a report only restates them without a concrete, exploitable case.
- Missing hardening that needs an already-compromised local account.
- The absence of system-level MITM. The public core does not implement it by design, so it isn't a vulnerability.
- Raw scanner output with no impact analysis.

Don't paste private or customer data into a report.

## What to expect

Reports are handled on a best-effort basis. This is a small project, not a staffed security team.

- We aim to acknowledge a report within **5 business days**.
- We aim to give an initial assessment, with a fix plan or a reason to decline, within **10 business days**.
- We keep you updated when the status changes, and we agree on a disclosure date with you before publishing anything.
- Details go public only after a release contains the fix. We credit reporters unless they ask us not to.

If you don't hear back within those windows, a polite follow-up on the same private advisory is fine.

## Supported versions

Security fixes land on `main` and ship in the next release. Pre-1.0, only the newest release line receives security fixes; if you run an older build, upgrade before reporting unless the report is about the upgrade path itself.

The current line is the `v0.5.0` rewrite on `main`. Older lines, `v0.4.x` and earlier, are not supported.

## Questions

For anything that is not a vulnerability, open a normal issue. For design questions, see [docs/security.md](docs/security.md) and [CONTRIBUTING.md](CONTRIBUTING.md).
