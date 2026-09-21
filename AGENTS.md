# PROJECT KNOWLEDGE BASE

**Generated:** 2026-09-19
**Commit:** 4ba3e54
**Branch:** main

## OVERVIEW
tokenhush is a loopback-only HTTP gateway that replaces secrets in AI-tool request bodies with session-scoped `__PII_<type>_<digest>__` placeholders and restores them on the response. No TLS termination, no root certificate. Pure Go, `CGO_ENABLED=0`, single direct dependency (`goccy/go-yaml`). This repo is the public Apache-2.0 v0.5.0 core; the Pro layer is a separate private repo that imports this module — never add paid-feature code, algorithms, or gates here.

## STRUCTURE
```
tokenhush/
├── cmd/tokenhush/     # process entry only; delegates to internal/cli
├── internal/
│   ├── cli/           # 7-command surface + the ONLY assembler wiring pkg/*
│   ├── guards/        # analysis-only invariant tests (no production .go)
│   └── layering/      # machine-enforced one-way import graph (+ cmd/)
├── pkg/
│   ├── protocol/      # JSON walk, SSE, span, backfill, spelling — leaf
│   ├── audit/         # audit-sink seam, noop default — leaf
│   ├── platform/      # OS config/data dirs — leaf
│   ├── redact/        # placeholder mint + forward-only writer; -> protocol
│   ├── filter/        # Rule contract, 6 detectors, registry; -> protocol, audit
│   ├── config/        # strict tokenhush.yaml loader; -> platform
│   ├── supply/        # signed rule sync + self-update; -> platform, filter
│   └── proxy/         # gateway data plane; -> protocol, redact, filter, audit, config, platform
├── docs/              # frozen docs; every *.md has a *.zh-CN.md twin
├── scripts/           # check-layering.sh (the only script)
├── egress.yaml        # source of truth -> internal/cli/egress_generated.go
└── install.sh / install.ps1   # end-user release installers, NOT dev build scripts
```
`.omo/` (agent plans/evidence/worktree archive) and `.codegraph/` (external SQLite symlink) are NOT product code — ignore them and keep them out of guards.

## WHERE TO LOOK
| Task | Location | Notes |
|---|---|---|
| Add/modify a CLI command | `internal/cli/cli.go` + one file per verb | `register()` from `init()`; adding an 8th verb fails `docs_guard_test.go` |
| Add a detector / rule type | `pkg/filter/` | Frozen `Rule` interface, registry, strict `options` schema |
| Change the data path | `pkg/proxy/dataplane.go` + `pkg/redact/` | Read `docs/architecture.md` first |
| Rule-doc schema / floor | `pkg/filter/{schema,compat_v1,compile}.go` + `pkg/supply/rules*.go` | Frozen wire surfaces |
| Signed sync / self-update | `pkg/supply/` | Ed25519, keylist, manifest, revocation, highwater |
| Allowed import edges | `internal/layering/graph.go` | Single source of truth; closed-world |
| Repo invariants | `internal/guards/*_test.go` | Each guard owns one rule; fix the code, do not loosen the guard |
| Vendor egress disclosure | `egress.yaml` | Regen: `go generate ./internal/cli`; drift caught by `TestEgressGeneratedMatchesYAML` |
| Security model / invariants | `docs/security.md`, `docs/architecture.md` | 8 invariants, named `TestInvariant*` tests |

## CODE MAP
| Symbol | Type | Location | Role |
|---|---|---|---|
| `dispatch` / `Main` | func | `internal/cli/cli.go:57` / `:52` | Command registry lookup; unknown verb -> sorted usage + exit 2 |
| `register` | func | `internal/cli/cli.go:49` | Installs a verb from a command file's `init()` |
| `command` | type | `internal/cli/cli.go:42` | `func(args []string, stdout, stderr io.Writer) int` |
| `Rule` | interface | `pkg/filter/` | THE extension point; exactly 8 methods (frozen) |
| `Registry` / `Evaluate` | type/func | `pkg/filter/registry.go` | Validates a whole batch before storing; deterministic order |
| `CompileWithBudget` | func | `pkg/filter/compile.go` | Document -> compiled rules; strict options decode |
| `CommandSignal` / `DecodeDocumentWithSignal` | struct/func | `pkg/filter/compat_v1.go:12` / `:26` | v1 wire compat; command rules signalled, never dropped |
| `CommandGateError` | struct | `pkg/supply/rules.go:89` | OD-2 gate refusal; `errors.Is(err, ErrCommandGate)` |
| `Walk` | func | `pkg/protocol/walk.go:67` | Walks every nested JSON leaf (values only, not keys) |
| `Apply` | func | `pkg/protocol/span.go:157` | Span-exact raw rewrite |
| `Mint` | func | `pkg/redact/backfill.go:50` | Reverse map lookup -> restore; foreign placeholders untouched |
| `Forwarder` | type | `pkg/proxy/forward.go:57` | Upstream dial + header forwarding |
| `DataPlane` | type | `pkg/proxy/dataplane.go` | Request/response orchestration; exactly one upstream dial |
| `Load` | func | `pkg/config/config.go` | Strict closed-schema YAML (`DisallowUnknownField`) |
| `Load` / `Check` | func | `internal/layering/layering.go:233` / `:87` | `go list` graph -> violations/skips (green vs full-graph) |
| `allowedGraph` | var | `internal/layering/graph.go:24` | Encoded allowed import edges |

Codegraph note: `walkValue`, `walkDocument`, `forward`, `Validate`, `validateListen`, `dispatch` have no direct test refs (covered transitively). `codegraph affected` is empty in this index; use `explore`/`callers` instead.

## CONVENTIONS
- **One-way imports, closed-world.** Allowed edges are in `internal/layering/graph.go`; an unlisted package is a violation in both modes. `pkg/filter` and `pkg/redact` are siblings — neither imports the other. `internal/cli` is the only assembler.
- **250 strict pure LOC per production Go file.** Comments/blanks excluded; lone `}` counts. Split the file, never excuse it. Exempt: `_test.go`, `testdata/`, generated, `.omo/`, `vendor/`.
- **Direction contract.** On the response path a rule may only `Block`/`Warn`; `redact` is request-path only, rejected at compile time AND registration.
- **No decode/normalize before detection.** `encoding/base64|hex`, `compress/gzip|flate|zlib` only in allowlisted sites (`pkg/filter/primitive_jwt.go`, `pkg/redact/placeholder.go`, all `pkg/supply/`, `pkg/redact/digest*.go`, direct children of `pkg/proxy/`). Never feed decoded output to `Inspect`. No `normalize*.go`.
- **Fail closed.** Detector failure refuses the request; non-identity `Content-Encoding` -> 415 before body read; undecodable response -> 502.
- **Placeholders are session-scoped and never backfilled outbound.** Secret->placeholder map is in-memory only.
- **Formatting:** `.editorconfig` — tabs in Go (size 4), 2-space yaml/json/md, LF, final newline, trim trailing space. `.golangci.yml` v2: default none; `errcheck, govet, staticcheck, ineffassign, nilnil, errorlint, unused` (`unused` off in tests).
- **Commits:** conventional (`feat(scope):`, `fix(scope):`, `docs(scope):`, `test(scope):`). Small, focused PRs; test every behavior change.
- **Frozen surfaces (do not change):** CLI verb set (7) and exit codes 0/1/2; the `docs/` file tree; `pkg/filter.Rule` 8-method shape; supply-chain domains/endpoints, embedded key ids, size caps, placeholder grammar, log lines (see `docs/architecture.md`).

## ANTI-PATTERNS (THIS PROJECT)
- **Never** add a certificate-install / TLS-termination / trust-store path (`absence_guard_test.go`). No `net/http`, `net/textproto`, `crypto/tls` in `pkg/{protocol,redact,audit,platform,filter,config}` (`import_guard_test.go`).
- **Never** persist request/response plaintext, detected secrets, or the placeholder map. Metadata only (`ondisk_guard_test.go`).
- **Never** add an 8th CLI command, an undocumented command, or a `docs/` file outside the allowlist (`docs_guard_test.go`).
- **Never** widen `pkg/filter` with a second exported interface or change the 8 `Rule` methods (`shape_guard_test.go`).
- **Never** add a dependency without reason; no indirect deps; no GPL/LGPL/AGPL (`deps_guard_test.go`, `license_guard_test.go`).
- **Never** add a config key outside the closed schema, bind `0.0.0.0`, or add a `proxy` key.
- **Never** commit real secrets/tokens/credentials, including fixtures and testdata (`gitleaks`, `.gitleaks.toml`).
- **Never** loosen or rename a guard/invariant test to make CI pass — fix the code or the docs it checks.

## UNIQUE STYLES
- `internal/guards` is a **test-only package** that scans the repo/product tree (not unit tests); `internal/layering` is analysis-only and imported by nothing.
- `internal/layering/cmd` is a second `main` package used solely by `scripts/check-layering.sh`.
- One codegen step: `//go:generate go run egress_gen.go` in `internal/cli/privacy.go` -> committed `internal/cli/egress_generated.go`.
- Every root/doc markdown has a `.zh-CN.md` twin; keep them in sync.
- README/docs are long and precise; behavior changes must update docs in the same change.

## COMMANDS
```sh
go build ./...                          # build every package
go build -o tokenhush ./cmd/tokenhush   # the binary
go vet ./...
go test ./...                           # local
go test ./... -count=1                  # CI form (no cache)
golangci-lint run                       # reads .golangci.yml
bash scripts/check-layering.sh          # layering guard from repo root
TOKENHUSH_GUARD_FULL_GRAPH=1 go test ./internal/guards/... ./internal/layering/... -count=1   # strict final gate
go generate ./internal/cli              # regenerate egress_generated.go from egress.yaml
go test ./pkg/protocol -fuzz FuzzWalk -fuzztime 30s   # fuzzing
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...  # cross-build (6 ports ship)
```
No Makefile / justfile / Dockerfile / npm. Tests are stdlib `testing`, colocated `*_test.go` (~464 test/fuzz/benchmark funcs). `TestInvariant*` names are part of the security contract — do not rename casually.

## NOTES
- `TOKENHUSH_GUARD_FULL_GRAPH=1` may appear in **exactly one** ci.yml step; `internal/guards/ci_config_test.go` fails otherwise.
- `gofmt` is not enforced by CI (no `formatters:` section in `.golangci.yml`); formatting is convention + `.editorconfig`.
- Product env switches: `TOKENHUSH_HOME`, `TOKENHUSH_NO_UPDATE_CHECK=1`, `TOKENHUSH_NO_RULE_SYNC=1`.
- `bin/` is a stray untracked build artifact and is NOT covered by `.gitignore` — do not commit it.

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

## 5. 语言要求

- 所有回答和交流必须使用中文
- 代码注释使用中文（除非项目规范要求英文）
- Git commit message 使用中文
- TODO 列表和任务描述使用中文