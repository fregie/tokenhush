# internal/cli KNOWLEDGE BASE

## OVERVIEW
`internal/cli` is the 7-command dispatcher and the sole assembler that wires `pkg/*` into the product.

## WHERE TO LOOK
| Concern | File(s) | Notes |
|---|---|---|
| `run` | `run.go`, `run_flags.go` | gateway lifecycle + HTTP surface; flags and startup-failure report |
| `rules` | `rules.go`, `rules_rollback.go` | `sync`/`sync --check`; rollback restores the cached pack offline |
| `update` | `update.go` | signed self-update, `--check`; install-source routing |
| `status` | `status.go` | reads running-gateway metadata; `statusPayload`, `--json` |
| `env` | `env.go` | 14-tool setup snippets |
| `version` | `version.go` | version + build info |
| `privacy` | `privacy.go` | renders `egressDisclosure` (generated) |
| registry / dispatch | `cli.go` | `commands` map, `register`, `dispatch`, `Main`, frozen exit codes |
| startup banner | `banner.go` | endpoint, routing, tool hint on stderr |
| counters | `counters.go` | `countRequests`, `(*gateway).redactionTransform` |
| response log | `response_log.go` | `newResponseLog` masked restore lines |
| request redaction | `redact_request.go` | `(*gateway).redactRequest` outbound substitution |
| session backfiller | `exclusion.go` | `sessionBackfiller` wires `pkg/redact` + control token |

## HOW TO ADD/CHANGE A COMMAND
- Each verb file calls `register("<verb>", run)` from its `init()`; there is no central switch to edit.
- `command` is `func(args []string, stdout, stderr io.Writer) int`. Return `exitOK` (0), `exitFailure` (1), or `exitUsage` (2).
- Unknown or empty verb: `dispatch` prints `usage: tokenhush <<sorted verbs>>` to stderr and returns `exitUsage`.
- An 8th verb REQUIRES updating `docs/` and the frozen verb set, or `internal/guards/docs_guard_test.go` fails.
- Inject seams (`runSeams`, `rulesSeams`, `updateSeams`, `envCommandWith`) so tests pin behavior without touching real state.

## CODEGEN
- The one `//go:generate go run egress_gen.go` directive lives in `privacy.go`.
- `egress_gen.go` (`//go:build ignore`) renders repo-root `egress.yaml` into committed `egress_generated.go` (`var egressDisclosure`).
- The generator refuses anything but exactly two categories, so a third vendor-bound category needs a code change, not a YAML edit.
- Drift is caught by `TestEgressGeneratedMatchesYAML` (`privacy_test.go`). Regenerate with `go generate ./internal/cli`.

## STARTUP ORDER (`run.go` `runWith`, never rearranged)
1. crash recovery (`seams.recoverRun` -> `supply.Recover`)
2. config load + run overrides
3. pipeline build (`buildGateway`; reads the rules cache, never the network)
4. loopback bind (`seams.listen`, `proxy.Listen`)
5. session files (`proxy.WriteSession`)
6. serve
Nothing is written before the bind succeeds, so a busy port fails fast and leaves no session file behind.

## ENV HELPER
- `envTools` is the frozen 14-tool list: claude, codex, aider, cline, roo, opencode, qwen, crush, zed, continue, openwebui, goose, openhands, kilo.
- `envSnippet` renders two base-URL forms: bare origin `http://127.0.0.1:<port>` (Anthropic-style) and the same origin plus `/v1` (OpenAI-compatible).
- `envCommandWith` carries the shell-mode and config-loader seams; a missing config file means defaults.

## GOTCHAS
- This package is the only assembler, so the parent import/decoder relaxations apply here and nowhere else.
- `cli.go` also owns the content-policy glue (`EvaluateRequest`/`EvaluateResponse` on `*gateway`) and the client-bound `responseWriter`; `run.go` owns the HTTP surface. Files split at the 250-pure-LOC ceiling: `counters.go`, `run_flags.go`, `redact_request.go` are split-outs, not separate concerns.
- `e2e_test.go`, `agent_scenarios_test.go`, and `precise_email_e2e_test.go` drive the real binary and are slow (61 test funcs here).
- `TestInvariant*` names are part of the security contract; don't rename casually.
