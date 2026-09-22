# Changelog

All notable changes to the public Tokenhush core are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **A note on the version line.** The `v0.1.0`–`v0.4.0` tags belong to a
> superseded pre-rewrite line and are not documented here. This repository is
> the from-scratch core; its history starts at `v0.5.0`.

## [0.7.1] - 2026-09-22

### Added

- **Request body-size guard.** A new `max_body_bytes` configuration key (default
  `67108864`, 64 MiB) bounds the total request body. A body over it is refused
  with `403 body_too_large` at the shared read seam, before any walk or upstream
  dial, and is never truncated or partially forwarded.
- **A metadata-only refusal log.** Every locally generated request-side refusal
  now writes exactly one `tokenhush: refused request <code>` line to stderr,
  carrying only the closed refusal vocabulary: the code, plus a classified
  `reason=` or `rule_id=` where the refusal already carries one.
- **High-precision secrets rule document.** `rules/high-precision-secrets.json`
  adds high-precision vendor key patterns (AWS, GCP, and other provider token
  shapes).

### Changed

- `scan_budget_bytes` is now strictly per-leaf, per-detector: a primitive
  detector inspects at most this many bytes of one leaf. The former aggregate
  scan-budget refusal (`scan_budget_exceeded`) is removed; a body over the total
  is now refused by `max_body_bytes` instead.
- The redaction log now names the PEM header kind of a `private_key` match (for
  example `RSA PRIVATE KEY`) and reveals only the domain of an `email` match
  (for example `****@example.com`). The PEM kind is a fixed allowlisted literal,
  so captured header text is never echoed.
- README first-screen branding refresh.

## [0.7.0] - 2026-09-20

### Added

- **Sensitive keys.** A rule document or signed pack may declare `sensitive_keys`
  (up to 256 names, `case_sensitive` default false); the value of a matching
  immediate object member key, for example `password`, is redacted at any object
  depth on the request path.
- **Whole-response buffering.** The full response, SSE included, is buffered
  before any byte is committed, bounded by `response_buffer_bytes` (default
  32 MiB, over the cap is a `502`) and `response_timeout` (default 5m, past the
  deadline is a `504`).
- Protocol: JSON string-leaf channel identifiers and object member-key capture,
  with fuzz seeds for scalar member capture.
- Redact: hold-until-parse leaf-channel placeholder reassembly.

### Changed

- Response path: buffered SSE evaluation and restore; sensitive-key rendering
  through the signed-pack path.

### Fixed

- Redact: the carry-branch prefix length now counts toward the joint bound;
  unconditional handoff of the raw tail before any valid JSON event; the joint
  hold bound with an abort/flush lifecycle reset; SSE envelope content-split
  handling.
- CLI and filter: the F2 review blockers and gate call ordering; three
  `golangci-lint` v2 findings.

### Documentation

- `docs/security.md`: sensitive keys, whole-response buffering, the rewritten
  R6 row, and the SSE-restore latency contract.

## [0.6.0] - 2026-09-19

### Added

- **Precise email detector by default**, parameterized by the address domain's
  public suffix.
- **Per-detector rule options**, decoded and strictly validated. The only option
  today is `email`: `suffixes` extends the built-in set and `replace` swaps it
  out, permitted for a local document and refused by the floor for a remote pack.
- Signed packs carry rule options; compiled rules dispatch through per-rule
  matchers.
- The hierarchical `AGENTS.md` knowledge base.

### Changed

- The docs-tree guard permits `docs/AGENTS.md` as agent metadata.

## [0.5.1] - 2026-09-18

### Added

- The six-platform cross-build release matrix (macOS, Linux and Windows on
  `arm64` and `amd64`); the version is stamped from the git tag at release time.
- The startup banner and the response-side restore log.
- Chinese (`*.zh-CN.md`) twins for the README, the reference docs, the egress
  disclosure, the Pro migration note, `CONTRIBUTING` and `SECURITY`.

### Changed

- `golangci-lint` v2 pinned and its findings cleared; the `gitleaks` allowlist
  covers the synthetic fixtures and the placeholder grammar.
- The installer and deployment docs reflect the shipped six-platform wave.

## [0.5.0] - 2026-09-18

The from-scratch core: a loopback-only gateway with a seven-command CLI, six
detectors, signed rule sync, signed self-update, and the guard suites.

### Added

- **CLI:** `run`, `rules`, `update`, `status`, `env`, `version`, `privacy` (the
  frozen verb set, exit codes `0`/`1`/`2`).
- **Proxy:** the loopback-only listener; the Host, Origin and control-token
  guards; a never-misroute resolver; fail-closed on compressed or unwalkable
  bodies; SSE backfill; the metadata-only control API.
- **Supply:** the Ed25519 signing substrate; key-list rotation and revocation;
  atomic serial high-water stores; signed rule sync with the OD gates; the
  crash-safe signed self-update.
- **Redact:** deterministic placeholder minting and inbound-only backfill; the
  canonical SSE reassembler; JSON-escape-depth-aware restore.
- **Install:** checksum-verified Linux and Windows installers; the tag-triggered
  GoReleaser pipeline.
- **Docs and guards:** the reference docs, the bilingual set, and the structural
  guard suites.

[Unreleased]: https://github.com/fregie/tokenhush/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/fregie/tokenhush/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/fregie/tokenhush/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/fregie/tokenhush/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/fregie/tokenhush/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/fregie/tokenhush/releases/tag/v0.5.0
