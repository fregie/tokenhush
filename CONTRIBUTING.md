# Contributing to Tokenhush

**English** | [中文](CONTRIBUTING.zh-CN.md)

> Status: V1 core released as `v0.1.0`. Bug reports, documentation, tests, and content plugins are welcome.

Thanks for helping make AI coding tools safer. This is the public Apache-2.0 core.

## Current priorities

The V1 core is implemented (`run` / `status` / `audit` / `env` / `doctor` / `version`) across Windows, Linux, and macOS. The most valuable contributions right now:

- Feedback on how each AI tool is connected via base URL, and the pitfalls you hit (see `docs/configuration.md`).
- Reports of missed redactions (false negatives) and over-redactions (false positives), plus security and privacy risks.
- Review of `docs/architecture.md`, `docs/security.md`, and `docs/plugins.md`.
- Content plugins (Inspector / Transformer, see `docs/plugins.md`).

## Local development

Go 1.25 or newer is required.

```bash
go build ./...          # build
go vet ./...            # static analysis
go test ./...           # unit tests plus the end-to-end smoke test
bash scripts/check-docs.sh   # verify docs match the CLI and config
```

> [!IMPORTANT]
> Do not contribute any Pro or paid-feature implementation to this repository. Pro code lives in a separate private repository; the public core only ever contains the open-source implementation.

## Submission process

1. Fork the repository and create a branch (`feat/...`, `fix/...`).
2. Follow the project conventions (Go: `gofmt` / `golangci-lint`; wrap errors with `fmt.Errorf("context: %w", err)`).
3. Write a clear commit message. Chinese or English is fine; explain the motivation.
4. Sign off every commit with the DCO: `git commit -s`.
5. Open a pull request describing what changed, why, and how you verified it.

> [!WARNING]
> Commit sign-off is required. A pull request without DCO sign-off will not be merged.

## Code conventions (Go)

- Constructors `NewX(...)` return pointers; every I/O method accepts a `context.Context`.
- Wrap errors with context: `fmt.Errorf("redact request: %w", err)`.
- Never swallow an error: no empty branches and no ignored error values.
- New behavior needs unit tests (stdlib `testing`; no third-party assertion library).
- When you change a CLI command or a `pkg/config` key, update the docs and make `scripts/check-docs.sh` pass.
- Format with `gofmt` and keep `golangci-lint` clean.

## License boundary

The public core ships under Apache-2.0. Paid and enterprise capabilities are implemented in a separate private repository that imports this module. To keep the two layers cleanly separated:

- Do not contribute any Pro or paid-feature implementation, algorithm, or gating switch to this repository.
- Keep core dependencies to permissive licenses only (MIT, Apache-2.0, BSD). GPL and AGPL are not allowed, because they would contaminate the closed Pro layer.

## Security disclosure

> [!CAUTION]
> Do not report vulnerabilities through a public issue.

Send a private report to the maintainer through the contact listed on the repository profile, or another private channel. We will coordinate a fix and only publish details after a release contains the fix.
