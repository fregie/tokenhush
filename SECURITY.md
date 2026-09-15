# Security Policy

Tokenhush exists to keep secrets out of AI coding tool requests, so a security report is worth taking seriously. This policy covers the public Apache-2.0 core repository at `github.com/fregie/tokenhush`. It is maintained in English only.

For how the gateway is built and which invariants are locked by tests, read [docs/security.md](docs/security.md). That document describes the security model; this one describes how to report a problem and what to expect afterward.

## Supported versions

Security fixes land on the latest release line and on `main`, and ship in the next release.

| Version | Supported |
|---|---|
| `v0.4.x` (current release line) | Yes |
| `main` | Development branch; fixes land here first |
| Older than `v0.4.0` | No |

Pre-1.0, only the newest release line receives security fixes. If you run an older build, upgrade first unless the report is about the upgrade path itself.

## Reporting a vulnerability

Do not open a public issue or pull request for a security problem.

Report privately through GitHub's private vulnerability reporting:

**https://github.com/fregie/tokenhush/security/advisories/new**

That form opens a private advisory visible only to you and the maintainers. If it is unavailable, use the contact details on the maintainer's GitHub profile and say you are reporting a vulnerability.

A useful report includes:

- What the issue is, and the impact you believe it has.
- The affected version, commit, or release.
- Steps to reproduce, with a minimal config or request where you can.
- Any proof of concept or logs, with secrets removed.

## What to expect

Reports are handled on a best-effort basis. This is a small project, not a staffed security team.

- We aim to acknowledge a report within **5 business days**.
- We aim to give an initial assessment, with a fix plan or a reason to decline, within **10 business days**.
- We keep you updated when the status changes, and we agree on a disclosure date with you before publishing anything.
- Details go public only after a release contains the fix. We credit reporters unless they ask us not to.

If you do not hear back within those windows, a polite follow-up on the same private advisory is fine.

## Scope

This policy covers the public core in this repository: the gateway, the redaction pipeline, the CLI, and the published documentation. The private Pro layer is out of scope here. Do not paste Pro code, private configuration, or customer data into a report.

## Out of scope

- Missing hardening that needs an already-compromised local account.
- The absence of system-level MITM: the public core does not implement it by design, so it is not a vulnerability.
- Reports that only restate the known detector trade-offs (false positives and false negatives) without a concrete, exploitable case.
- Raw scanner output with no impact analysis.

## Questions

For anything that is not a vulnerability, open a normal issue. For design questions, see [docs/security.md](docs/security.md) and [CONTRIBUTING.md](CONTRIBUTING.md).
