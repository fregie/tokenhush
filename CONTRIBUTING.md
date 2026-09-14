# Contributing to Tokenhush

**English** | [中文](CONTRIBUTING.zh-CN.md)

> Status: V1 core released as `v0.1.0`. Bug reports, documentation, tests, and content plugins are welcome.

Thanks for helping make AI coding tools safer. This is the public Apache-2.0 core.

## 🎯 Current priorities

The V1 core (`run` / `status` / `env` / `doctor` / `version`) is implemented on Windows, Linux, and macOS. Most valuable now:

- How each AI tool connects through its base URL, plus pitfalls you hit (see `docs/tool-setup.md`).
- Missed redactions (false negatives), over-redactions (false positives), and other security or privacy risks.
- Reviews of `docs/architecture.md`, `docs/security.md`, and `docs/plugins.md`.
- Content plugins (Inspector / Transformer, see `docs/plugins.md`).

## 🏗️ Local development

Go 1.25 or newer.

```bash
go build ./...          # build
go vet ./...            # static analysis
go test ./...           # unit tests plus the end-to-end smoke test
bash scripts/check-docs.sh   # verify docs match the CLI and config
```

> [!IMPORTANT]
> Do not contribute any Pro or paid-feature implementation here. Pro code lives in a separate private repository; the public core contains only the open-source implementation.

## 🤝 Submission process

1. Fork the repo and create a branch (`feat/...`, `fix/...`).
2. Follow project conventions (Go: `gofmt` / `golangci-lint`; wrap errors with `fmt.Errorf("context: %w", err)`).
3. Write a clear commit message (Chinese or English); explain why.
4. Sign off every commit with the DCO: `git commit -s`.
5. Open a pull request: what changed, why, and how you verified it.

> [!WARNING]
> Commit sign-off is required. A pull request without DCO sign-off will not be merged.

## 📌 Code conventions (Go)

- `NewX(...)` returns pointers; every I/O method takes a `context.Context`.
- Wrap errors with context: `fmt.Errorf("redact request: %w", err)`.
- Never swallow an error: no empty branches, no ignored error values.
- New behavior needs unit tests (stdlib `testing`; no third-party assertion library).
- Change a CLI command or `pkg/config` key? Update the docs and keep `scripts/check-docs.sh` passing.
- Format with `gofmt`; keep `golangci-lint` clean.

## 📄 License boundary

The core is Apache-2.0. Paid and enterprise features ship from a private repo that imports this module. To keep the layers apart:

- Don't contribute any Pro or paid-feature implementation, algorithm, or gating switch.
- Use permissive licenses only (MIT, Apache-2.0, BSD). GPL/AGPL are banned: they would contaminate the closed Pro layer.

## 🛡️ Security disclosure

> [!CAUTION]
> Don't report vulnerabilities in a public issue.

Report privately via the repository profile contact or another private channel. See [SECURITY.md](SECURITY.md) for supported versions, the private reporting channel, and response times. We coordinate a fix and publish details only after a release contains it.
