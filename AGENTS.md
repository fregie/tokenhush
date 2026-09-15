# AGENTS.md: tokenhush (public core)

> Status: V1 implemented; the current release line is `v0.3.0` (`run` / `status` / `env` / `doctor` / `version`). Since `v0.2.0` the core keeps only the audit seam, because the concrete audit store moved to the private Pro layer; `v0.3.0` moves the shared assembly layer into the exported `pkg/gateway` package. Cross-platform (macOS / Linux / Windows).
> Last updated: 2026-09-12

## What this is

A local base-URL gateway. AI coding tools point their API requests at the local machine (for example `ANTHROPIC_BASE_URL=http://127.0.0.1:PORT`). Tokenhush performs outbound redaction (keys / PII / sensitive text), exposes a metadata-only audit seam for the private Pro layer, then backfills the response before returning it to the client. The core itself stores no audit data. Processing is local; sensitive content is redacted before a request leaves the device.

This repository is the Apache-2.0 open-source core. The private Pro layer lives in the private Pro repository and builds by importing this repository's Go module. Never put Pro code in this repository.

## Structure and layout

```text
tokenhush/
├── README.md
├── LICENSE                 # Apache-2.0
├── CONTRIBUTING.md
├── AGENTS.md               # this file
├── docs/
│   ├── README.md           # documentation index
│   ├── architecture.md     # core architecture + open-core boundary
│   ├── extension-api.md    # public extension point interfaces
│   ├── plugins.md          # writing content plugins (Inspector / Transformer)
│   ├── tool-setup.md       # per-tool setup + route matrix + tokenhush.yaml reference
│   ├── deployment.md       # deployment + OS-native auto-start
│   └── security.md         # security/threat model + hard invariants
├── scripts/
│   └── check-docs.sh       # verify docs match the CLI and config
├── cmd/tokenhush/          # free CLI entry point
└── pkg/
    ├── proxy/              # local reverse proxy
    ├── redact/             # detection / placeholder / backfill engine
    ├── protocol/           # protocol-agnostic JSON leaf traversal + SSE incremental parsing
    ├── audit/              # audit seam (Record/Query, AuditSink/AuditQuerier, no-op); store in Pro
    ├── config/             # configuration loading
    ├── platform/           # cross-platform abstraction: paths / keyring / service (exported for Pro reuse)
    ├── extension/          # extension point interfaces (Router / CostSink / AuditExporter + content plugins Inspector/Transformer/Registry)
    ├── gateway/            # shared request-path assembly (Options/Deps hooks, middleware chain, data plane, run.json)
    └── license/            # read-only Pro license display (isolated, fuzz tested)
```

> [!NOTE]
> `docs/README.md` is the documentation index, and `docs/deployment.md` covers deployment and user-managed OS-native auto-start. A built-in service command is not part of V1; the only run mode is the foreground `tokenhush run`.

## Where to look

| Task | Location |
|---|---|
| Architecture / data flow / open-core boundary | `docs/architecture.md` |
| Adding or changing extension point interfaces | `docs/extension-api.md` + `pkg/extension/` |
| Writing content plugins (Inspector / Transformer) | `docs/plugins.md` |
| Adding a tool integration | `docs/tool-setup.md` |
| Deployment and OS-native auto-start | `docs/deployment.md` |
| Documentation index | `docs/README.md` |
| Security invariants / threat model | `docs/security.md` |
| Docs vs CLI / config consistency | `scripts/check-docs.sh` |
| Product, market, roadmap, pricing | the private Pro repository (maintainer-only) |

## Hard conventions (non-negotiable)

1. Never backfill placeholders outbound. Backfill goes only to the client. This is the core anti-prompt-injection invariant.
2. No normalization at the protocol layer: use protocol-agnostic JSON leaf traversal (recursive string-leaf detection and replacement). Do not build an IR per API.
3. V1 detectors use deterministic rules only (prefix / high-entropy / JWT / private-key header / Luhn / email). Do not introduce NER or local small models.
4. Local services bind loopback only (127.0.0.1 always; [::1] as well when the host has an IPv6 loopback) and validate the `Host` header (anti DNS rebinding). The control plane additionally requires a bearer token and an Origin check.
5. The core exposes only a metadata-only audit seam (provider / endpoint / time / byte counts / redaction counts / types); it stores no audit data. The concrete store and any content-logging option live in the private Pro layer.
6. Pro capability never enters this repository. Do not write complete `if license { ... }` implementations or Pro algorithms here, and never merge Pro implementation branches into this repository.
7. Dependency licenses: core dependencies must be permissive only (MIT / Apache-2.0 / BSD). GPL and AGPL are forbidden, because they would contaminate the closed Pro layer.
8. Cross-platform: converge OS differences in `pkg/platform`, not scattered `runtime.GOOS` branches. Never write to the CWD or the binary directory (the install prefix is read-only). Use pure-Go SQLite (`modernc.org/sqlite`) to keep `CGO_ENABLED=0` cross-compilation working.

## Anti-patterns (do not do)

- Shipping a complete implementation of a paid feature, or a switch branch for it, in the open-source code.
- Enabling MITM or installing a root certificate by default.
- Introducing NER or small models for semantic detection in V1 (high false-positive and size cost).
- Bypassing types or error handling (for example an `as any`-style escape).
- Widening the config or interface surface without user feedback. Gate 1 is a non-blocking parallel track; the answer is fewer, more opinionated surfaces. The recorded decision is in the private Pro repository.

## Commands

```bash
# build
go build -o bin/tokenhush ./cmd/tokenhush
# run (foreground gateway)
./bin/tokenhush run --port 8787
# print an integration snippet for a tool
./bin/tokenhush env claude
# version
./bin/tokenhush version
# tests
go test ./...
# docs consistency check
bash scripts/check-docs.sh
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits require DCO sign-off. For security vulnerabilities, do not open a public issue; use the disclosure process in CONTRIBUTING.
