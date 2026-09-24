# DOCS KNOWLEDGE BASE

Child of root `AGENTS.md`. Read that first; this file only adds docs-tree rules.

## OVERVIEW
`docs/` is the frozen, bilingual source of truth for product behavior.

## WHERE TO LOOK
| Topic | File |
|---|---|
| Layering, rule abstraction, frozen wire surfaces | `docs/architecture.md` |
| Threat model, 8 invariants, residual risk | `docs/security.md` |
| Per-tool setup (14 tools) | `docs/tool-setup.md` |
| `tokenhush.yaml` reference, upstream routing, config/data dirs | `docs/configuration.md` |
| Echo-upstream verification recipe | `docs/verify.md` |
| Install/build paths, service wrappers, platforms | `docs/deployment.md` |
| Compile-time `Rule` extension point | `docs/plugins.md` |
| Vendor egress disclosure (generated) | `docs/generated/network-egress.md` |

## THE FROZEN TREE RULE
`internal/guards/docs_guard_test.go` pins the allowed docs file set AND asserts the documented command set equals the 7 registered commands in `internal/cli`. Adding a docs file, or adding/removing a command without updating docs, fails CI. To add a doc you must also change the guard: treat that as a product decision, not a doc cleanup.

## BILINGUAL RULE
Every root/doc markdown has a `.zh-CN.md` twin (`architecture.md` + `architecture.zh-CN.md`, and so on). Keep both in sync in the SAME change. Never ship a doc without its twin; never edit one side alone.

Root twins: `README.zh-CN.md`, `CONTRIBUTING.zh-CN.md`, `SECURITY.zh-CN.md`.

## GENERATED DOC
`docs/generated/network-egress.md` (plus its `.zh-CN.md` twin) is generated from root `egress.yaml` via `go generate ./internal/cli`. Do NOT hand-edit either file: edit `egress.yaml`, regenerate, commit the result. Drift is caught by `TestEgressGeneratedMatchesYAML`.

## WHEN TO UPDATE
Any behavior, CLI, config, or wire-surface change updates the affected doc(s) in the same PR, README included. Update both language twins. Docs in this tree are precise by design: quote endpoints, size caps, placeholder grammar, detector options, and log lines exactly. Do not paraphrase or round numbers.
