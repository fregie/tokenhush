# pkg/redact

## OVERVIEW
Mints session-scoped `__PII_<type>_<digest>__` placeholders and restores only placeholders this session minted. Import edge: -> `pkg/protocol` only.

## WHERE TO LOOK
| Task | File |
|---|---|
| Mint / substitute on the request path | `substitute.go` (`Substitute`), `forward_writer.go` (`redactBody`) |
| Placeholder mint, digest ladder, grammar | `placeholder.go` (`engine`, `placeholder`, `sanitizeKind`) |
| Reverse map, restore, JSON-aware backfill | `backfill.go` (`Backfiller`, `Map`, `Mint`, `Backfill`, `BackfillCount`) |
| Never restore an allowlisted value | `exclusion.go` (`ExcludeFromBackfill`) |
| SSE reassembly + bounded holdback | `sse_backfill.go` (`SSEBackfiller`, `Write`, `Flush`, `Held`) |
| SSE restore spelling at depth | `sse_spelling.go` (`spellFeed`, `replace`, `leafTokens`) |
| Invariant pins | `invariants_test.go` |

## THE FORWARD-ONLY WRITER (invariant 1, load-bearing)
`ForwardWriter` (forward_writer.go:9) is the sole outbound substitute. It holds only the engine's forward map (secret -> placeholder); it has NO reverse map and NO restore method. Its exported surface is placeholder minting alone: `Placeholder` (forward_writer.go:25). `redactBody` (unexported) replaces each secret with its minted placeholder; re-application is idempotent and a body already carrying a known placeholder is forwarded verbatim. This split from `pkg/filter` is what makes "never backfill outbound" structural, not a convention: the outbound type physically cannot expand a placeholder. `TestInvariant1NeverBackfillOutbound` (invariants_test.go:114) pins the shape.

## RESTORE CONTRACT
- `Backfiller` (backfill.go:14) owns the ONLY reverse map (placeholder -> secret). A restart creates a new empty one, so a stale placeholder surfaces rather than a wrong secret.
- `Mint` (backfill.go:50) = `ForwardWriter.Placeholder` + record reverse mapping; the sole way a secret becomes restorable. `Map` (backfill.go:36) copies the secret; the mapping never aliases a caller buffer.
- `Backfill` (backfill.go:74) / `BackfillCount` (backfill.go:83): a FOREIGN placeholder (never minted this session) is returned byte-identical, never fabricated into a secret. Bytes that are not a mapped placeholder are never touched.
- Restore is escape/depth-aware. JSON bodies go through `protocol.Walk` + `protocol.Apply`, re-spelling the secret with `leaf.RawSpelling` at the enclosing JSON depth, exactly the spelling the client sent. A secret carrying `"`, `\`, a control byte, or a newline cannot corrupt client JSON. Object keys are never emitted by `Walk`, so leftover key placeholders get exactly one escaping level via `protocol.EscapeJSONString`. A non-JSON body falls back to `bytes.ReplaceAll`. Longer placeholders replace first, so a long token is never shadowed.
- `Substitute` (substitute.go:30): an unlocatable decoded span is skipped and NEVER minted (reverse map must not hold a placeholder never sent). Only byte-changing substitutions are returned, ascending, because `protocol.Apply` alone arbitrates overlaps and no-ops.

## SSE
- Bounded backfill window: `protocol.SSEBackfillHoldbackBytes` = 256 KiB (defined in `pkg/protocol/backfill.go:8`; invariant 8). The writer holds at most that many trailing bytes; past the bound the oldest held bytes leave literally and in order, nothing dropped or fabricated. `Held()` never exceeds the bound (sse_backfill.go:240).
- `SSEBackfiller` (sse_backfill.go:158) decodes events, gates each later event behind the one pending data segment, and releases in order. `Flush` (sse_backfill.go:222) is idempotent and emits the never-dispatched tail verbatim, so a ping- or comment-only stream is byte-identical. A nil restorer gets a fresh empty backfiller: no token expands to a secret.
- `TestInvariant8BoundDerived` (invariants_test.go:222) pins the bound against the production constant, not a test local.
- Restore spelling at depth: `spellFeed` (sse_spelling.go:21) records the leaf spelling of each complete token in the data value being fed; `replace` (sse_spelling.go:44) uses it, else one escaping level for a valid JSON document, else raw.

## FROZEN / GOTCHAS
- Placeholder grammar frozen: `__PII_<type>_<digest>__`, digest grows along a fixed ladder until unique within the engine (`placeholder.go`). Do not change the prefixes, separators, caps, or ladder.
- Decoder imports (`encoding/hex`) are allowlisted in this package only at `pkg/redact/placeholder.go` (the parent's `digest*.go` glob currently matches no file here). No normalize step: never decode before detection.
- `pkg/filter` and `pkg/redact` are siblings; neither imports the other. Adding an import outside the `pkg/protocol` edge fails layering.
