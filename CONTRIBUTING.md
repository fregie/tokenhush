# Contributing to Tokenhush

**English** | [中文](CONTRIBUTING.zh-CN.md)

Tokenhush is the public Apache-2.0 core, maintained in English. Bug reports, documentation, tests, and new rules are welcome.

The Pro and enterprise layer lives in a separate private repository that imports this Go module. Don't contribute paid-feature code, algorithms, or gating switches here.

## Requirements

- Go 1.25 or newer. `go.mod` pins `go 1.25.0`.
- `git`.
- Optional: `golangci-lint` and `gitleaks`, for the local equivalents of the CI steps below.

## Build and test

```sh
go build ./...                          # build every package
go build -o tokenhush ./cmd/tokenhush   # build the binary
go test ./...                           # unit, invariant, and guard tests
go vet ./...                            # static analysis
./tokenhush version                     # confirm the binary runs
```

The project is pure Go and builds with `CGO_ENABLED=0`. The release matrix is macOS arm64, Linux amd64, and Windows amd64.

## What CI runs

`.github/workflows/ci.yml` runs these steps. Reproduce them locally before you open a pull request:

```sh
go build ./...
go vet ./...
go test ./... -count=1
golangci-lint run
bash scripts/check-layering.sh
TOKENHUSH_GUARD_FULL_GRAPH=1 go test ./internal/guards/... ./internal/layering/... -count=1
```

- `golangci-lint` reads `.golangci.yml`: `errcheck`, `govet`, `staticcheck`, `ineffassign`, `nilnil`, `errorlint`, and `unused`.
- `bash scripts/check-layering.sh` runs the same graph check as the `internal/layering` package, from the repo root.
- The full-graph step exports `TOKENHUSH_GUARD_FULL_GRAPH=1`, which turns a missing expected package or a missing required edge into a failure. It's the strict mode of the same guards.
- A separate job cross-builds with `CGO_ENABLED=0` for darwin/arm64, linux/amd64, and windows/amd64.
- A `secret scan` job runs gitleaks with the repository ruleset in `.gitleaks.toml`. Run gitleaks locally too if you have it installed, and never commit a real secret, token, or credential into the tree, including fixtures and test data.

## Invariants your change must respect

These are enforced by tests, not review etiquette. A change that breaks one fails CI.

1. **250 pure LOC per production Go file.** `internal/guards/size_guard_test.go` counts strict pure LOC: blank lines and comment-only lines don't count, and every other line does, including a lone closing brace. The ceiling is 250. A file over it is split, not excused. Test files, `testdata/`, generated files, and vendored code are out of scope.
2. **Dependencies point one way.** `internal/layering` and `scripts/check-layering.sh` enforce the allowed package graph. There are no cycles, and sibling packages don't reach into each other. `pkg/filter` and `pkg/redact` are siblings, and `internal/cli` is the only assembler that wires the packages into a product.
3. **The CLI surface is frozen.** Exactly seven commands: `run`, `rules`, `update`, `status`, `env`, `version`, `privacy`. Exit codes are frozen at `0` (success), `1` (a check or operation failed), and `2` (usage error). `internal/guards/docs_guard_test.go` reads the registrations from `internal/cli` and fails on an eighth command. Adding one is a product decision, not a wiring accident.
4. **The docs tree is frozen and must match the real CLI.** `docs/` holds only the known set of files, and the documented command set must equal the registered one. The same guard enforces both. Update the docs in the same change as the behaviour.
5. **`pkg/filter`'s exported `Rule` interface is frozen.** `internal/guards/shape_guard_test.go` pins its eight methods (`ID`, `Type`, `Category`, `Scope`, `Action`, `Priority`, `Confidence`, `Inspect`) and rejects a second exported extension interface. Extend through a rule, not by widening the contract.
6. **No certificate-install path, ever.** `internal/guards/absence_guard_test.go` scans production Go source for TLS termination, root-certificate, and trust-store shapes, and fails if any appears. Tokenhush installs no root certificate, terminates no TLS, and changes no trust store. A change that needs any of these is rejected.
7. **Never persist request or response plaintext.** `internal/guards/ondisk_guard_test.go` drives the real binary and scans everything a run could have written. Only metadata is allowed on disk: session files, the rules cache, and anti-rollback marks. Bodies, detected secrets, and the placeholder-to-secret mapping stay in memory. The redaction log is masked, stderr-only, and never persisted.

One more rule is structural rather than a single guard: on the response path a rule may only `Block` or `Warn`, and `redact` is request-path only. A response-scoped `redact` rule is rejected at compile time and again at registration. Keep that direction contract intact. See [docs/security.md](docs/security.md) for the full security model and the residual-risk register.

## Pull requests

- Keep changes small and focused. One behaviour per pull request beats a grab bag.
- Add or update a test for every behaviour change. The `TestInvariant*` names are part of the security contract, so don't rename them casually.
- Keep every guard green. If a guard fails, fix the code or the docs it checks. Don't loosen a guard without explaining why in the pull request.
- Use conventional commits: `feat(scope):`, `fix(scope):`, `docs(scope):`, `test(scope):`. Explain why in the body.
- Never commit secrets, tokens, or real credentials. gitleaks runs in CI with `.gitleaks.toml`.
- State what changed, why, and how you verified it in the pull request description.

## Dependencies

- New dependencies need a reason. The module graph is small on purpose.
- No copyleft dependency may enter the module graph: GPL, LGPL, and AGPL are forbidden, and every requirement in `go.mod` must expose a verifiable license.

## What to read first

- [docs/architecture.md](docs/architecture.md): the layered dependency graph, the single rule abstraction, the data path, and the frozen CLI.
- [docs/security.md](docs/security.md): the eight invariants, the response-phase effects, and the seven residual risks.
- [docs/plugins.md](docs/plugins.md): the `Rule` extension point, its registration semantics, and a worked example.
- [docs/configuration.md](docs/configuration.md): every `tokenhush.yaml` key, upstream routing, and where the file lives.
- [docs/tool-setup.md](docs/tool-setup.md): per-tool setup for the 14 tools.

## Extending Tokenhush

There is exactly one extension point: the `Rule` interface in `pkg/filter`. The built-in detectors, the rules in a signed remote pack, and rules a third party compiles in from its own package all arrive through the same public registry and are evaluated in the same deterministic order.

Plugins are compile-time only in this version. A plugin is an ordinary Go package compiled into the binary that imports it. There is no runtime plugin loading, no WASM, no shared objects, and no subprocesses. [docs/plugins.md](docs/plugins.md) has the contract, the registration semantics, and the response-phase restriction.

## License

Contributions are accepted under the Apache License 2.0. See [LICENSE](LICENSE).
