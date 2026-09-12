# Security Model

**English** | [中文](security.zh-CN.md)

> Status: V1 is implemented (2026-09). The hard invariants are locked by named tests in `pkg/*`, and are restated under Hard invariants below and in `architecture.md`.

Tokenhush is itself a security tool, so **it must be secure first**. This document defines the threat model and the invariants that cannot be broken.

## Threat model

| Threat | Description | Mitigation |
|---|---|---|
| **Prompt injection to exfiltration** | An attacker tricks the model into emitting a placeholder; if the gateway backfills on the outbound direction, the secret leaks | **Hard invariant: never backfill outbound** (see Hard invariants) |
| **Local malicious process/web page reaches the gateway** | Any local process or browser page can `fetch` `127.0.0.1:8787` | Dual-stack loopback (127.0.0.1 + `[::1]`); `Host` header validation; the control plane additionally requires a bearer token generated per `run`, stored `0600` on disk, and same-origin validation for requests carrying `Origin` |
| **DNS rebinding** | A malicious domain resolves to 127.0.0.1 to bypass same-origin | `Host`/`Origin` header validation |
| **Placeholder collision** | Two secrets map to the same placeholder, causing a wrong backfill | HMAC-deterministic mapping + high-entropy suffix |
| **Plaintext read from memory** | Debug or dump by another process under the same user | Sandbox/hardened runtime; no plaintext written to disk |
| **Supply-chain attack** | A dependency is poisoned (see the LiteLLM incident) | Minimal dependencies + pinned versions + signed releases + SBOM |

- **Prompt injection, concretely.** A poisoned file tells the model to print `__PII_email_3f9a2b__`. If the model echoes it and the gateway backfilled outbound, the real email would go upstream. Invariant 1 blocks that: backfill only runs toward the client.
- **Local reachability, concretely.** A random npm `postinstall` script, or a web page you have open, can call `fetch("http://127.0.0.1:8787/...")`. It still fails: loopback-only bind, `Host` check, and a per-`run` bearer token.

## Hard invariants

1. **Never backfill placeholders outbound.** Backfill happens only on responses returned to the client.
2. **Do not store request/response plaintext by default.** The core stores no request or response content.
3. **No root certificate is installed and no MITM is performed by default.** MITM is an explicit opt-in in later stages and is not implemented in the public core.
4. **The local service binds dual-stack loopback only (127.0.0.1 + `[::1]`).**
5. **Fail-safe on detection failure, not fail-open.** When the gateway cannot tell whether content is sensitive, it prefers over-redaction, or allows with a warning, and never silently emits plaintext. The policy is configurable (see below).

> [!IMPORTANT]
> Invariant 1 is why prompt injection cannot turn the gateway into an exfiltration path: placeholders are only ever replaced on the way back to the client.

## Detector trade-offs

- **False positives (over-redaction)** hurt the experience: the model receives a placeholder and code or answers degrade.
- **False negatives (under-redaction)** hurt the promise: sensitive content leaves the machine.

The V1 strategy is **deterministic, high-precision-first detectors** (known key prefixes, high entropy, JWT, private-key headers, Luhn card-number checksums, and email addresses), backed by an allowlist and one-click release. The project does **not** claim "never leaks". The honest claim is **"high-confidence secret interception"**.

## Key handling

- **V1: passthrough.** Tools carry their own provider keys; the gateway only forwards and **does not store** them.
- When multi-account/routing (Pro) needs to store keys, it goes through the cross-platform keyring abstraction (macOS Keychain / Windows Credential Manager / Linux Secret Service plus a fallback chain, a design recorded in the private Pro repository), and adds a gateway token + Origin validation to prevent CSRF.
- **Honest degradation**: without an OS keyring, storage falls back to a restricted file (`0600`), reported **explicitly** through the secret store's `Backend()`, never silently.

## Release and supply chain

- **Dependency audit**: the core allows permissive licenses only (MIT/Apache/BSD); **GPL/AGPL are forbidden**.
- **Release**: signed builds + checksums + SBOM; CI scans dependencies and secrets.
- **Updates**: Homebrew / Scoop / `curl|sh` signed distribution.

## Vulnerability disclosure

> [!CAUTION]
> **Do not open a public issue** for a vulnerability. Follow the disclosure process in [CONTRIBUTING.md](../CONTRIBUTING.md). Details are published only after a fix has been released.
