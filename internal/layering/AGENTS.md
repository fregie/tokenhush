# LAYERING KNOWLEDGE BASE

## OVERVIEW
Machine-enforced one-way internal import graph; one encoded graph drives both a Go test and a CLI so CI and local runs reach identical verdicts.

## WHERE TO LOOK
| Task | Location | Notes |
|---|---|---|
| Change allowed edges | `graph.go` | `allowedGraph` is the only thing to edit |
| Discovery / graph model | `layering.go` | `Load`, `Check`, `Graph`, `Edge` (defined in graph.go) |
| Test entry point | `layering_test.go` | external package `layering_test` |
| CLI entry point | `cmd/main.go` | second `main`; exit codes 0/1/2 |
| Fixture proving a forbidden edge fails | `testdata/forbiddenedge/fixture.go` | never compiled |

## THE GRAPH (`graph.go`)
`allowedGraph map[string][]string` is the SINGLE source of truth; every key is an expected package, each value the internal suffixes it may import. `ModulePath = "github.com/fregie/tokenhush"` is the prefix suffixes are relative to. `Edge{Source,Target}` is a directed internal edge (suffixes, not full paths); `Edge.String()` renders `src -> tgt`. `ExpectedPackages()` returns sorted keys. `Allowed(pkg)` returns a sorted copy of the allowed imports, or `nil` for an unknown package (closed-world).

```
pkg/platform {}          pkg/audit {}         pkg/protocol {}
pkg/redact {protocol}    pkg/filter {protocol,audit}   pkg/config {platform}
pkg/supply {platform,filter}
pkg/proxy {protocol,redact,filter,audit,config,platform}
internal/guards {}       internal/layering {}
internal/layering/cmd {internal/layering}
internal/cli {all pkg/*}                  cmd/tokenhush {internal/cli}
```

## CHECKING (`layering.go`)
`Load(ctx, dir, run)` shells `go list -f '<import> <imports...>' ./...` exactly once into a `Graph{Present, Edges}`; testdata is filtered out; a nil `run` uses `RunCommand`. `Check(g, Options{FullGraph})` returns `Result{Violations, Skips}`, sorted deterministically. Expected-package misses are skips in green mode and violations in full-graph mode; a missing required edge target follows the same rule. An unknown present package is ALWAYS a violation, and a forbidden edge is ALWAYS a violation, in both modes. `FullGraphEnabled()` reads `TOKENHUSH_GUARD_FULL_GRAPH=1`.

## HOW TO ADD A PACKAGE/EDGE
Edit `allowedGraph` and nothing else, then run `bash scripts/check-layering.sh`. Add the package as a key with its allowed imports, and add it to any parent's value. When no cycle forms and siblings don't cross, prefer the existing shape over a new edge.

## TWO ENTRY POINTS
`go test ./internal/layering/...` (the Go test) and `go run ./internal/layering/cmd`, invoked by `scripts/check-layering.sh`, both call the same `Load`/`Check`/`allowedGraph`, so they always agree. CLI exit codes: `0` pass, `1` at least one violation, `2` graph load failure.

## GOTCHAS
`internal/layering` and `internal/guards` are analysis-only and imported by nothing. `internal/layering/cmd` is the repo's second `main` package. `testdata/` and anything below it are invisible to the graph, so fixtures can model a forbidden edge (`pkg/supply -> pkg/redact`) without tripping the tool.
