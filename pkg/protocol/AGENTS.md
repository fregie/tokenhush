# pkg/protocol: Leaf Wire-Format Substrate

## OVERVIEW
Leaf package in the import graph: JSON walk, span-exact raw rewrite, SSE decode, escape re-spelling, stream backfill. Stdlib only (`bytes`, `encoding/json`, `errors`, `io`, `sort`, `strconv`, `strings`, `unicode/utf8`); imports nothing internal. Imported by `redact`, `filter`, `proxy`.

## WHERE TO LOOK
| Task | File |
|---|---|
| Walk JSON into leaves; depth/UTF-8 errors | walk.go |
| Map decoded spans back to raw bytes; splice edits | span.go |
| Re-escape decoded bytes for a wrap depth | spelling.go |
| Incremental SSE record decode | sse.go |
| Hold back tokens split across stream deltas | backfill.go |
| Committed parser regression seeds | testdata/fuzz/FuzzWalk/, testdata/fuzz/FuzzSSE/ |

## KEY CONTRACTS
- `Walk(data []byte) ([]Leaf, error)` (walk.go:67): emits every nested JSON **string value** as a `Leaf`; numbers, booleans and null are ignored; **object keys are never emitted**, so key-position secrets are a documented non-goal. Paths are RFC 6901 pointers. A string whose content itself parses as JSON yields inner leaves with `Encoded=true`. Sentinels `ErrMalformedJSON`, `ErrTrailingData`, `ErrNonUTF8`, `ErrMaxDepth` all come with **no partial leaves**. Bounds: `MaxNestingDepth` 10000, `MaxEncodedDepth` 32. Nothing is decoded here: a base64-looking leaf returns byte-identical.
- `Leaf.RawSpan` (span.go:121) and `Apply(body, edits)` (span.go:157): map each decoded detection span back to the raw escaped bytes, so a secret with newlines or quotes leaves as a placeholder and returns intact. `Apply` drops unlocatable, no-op and overlapped edits and returns the **indices of edits actually applied** in ascending raw-start order; log and count those, not the input edit slice.
- `Leaf.RawSpelling` / `EscapeJSONString` (spelling.go:66 / :59): re-escape one level per enclosing JSON-string wrapper (`escapeJSONString`). Deliberately avoids `encoding/json`, which HTML-escapes `<>&` and rewrites invalid UTF-8.
- `Decoder` / `NewDecoder` / `Feed` / `Close` (sse.go): incremental SSE; chunks may split a record at any byte. Line ends are `\n`, `\r\n`, lone `\r`; comments fold forward; a data-less blank clears event/retry but keeps the last id. `ErrClosed` is the only error because SSE has no malformed input. `Event.DataSpans` is set only for a single canonical `data:` line.
- `BackfillWriter` / `NewBackfillWriter` (backfill.go): holds exactly the trailing bytes that could still become a token, replaces each complete token once, never emits a fragment. `SSEBackfillHoldbackBytes` (256 KiB) releases the oldest held bytes literally so a hostile stream cannot stall progress.

## FUZZING
- `FuzzWalk`, `FuzzApplyOnlyTouchesTheSpan`, `FuzzSSE` in fuzz_test.go (package has 46 test funcs).
- Corpus: `testdata/fuzz/FuzzWalk/{base64-leaf,deep-arrays,invalid-utf8,truncated-document,valid-nested-json}` and `testdata/fuzz/FuzzSSE/{comment-only-stream,invalid-bytes-stream,lone-cr-stream,multi-event-stream,split-mid-field-stream}`.
- Run: `go test ./pkg/protocol -fuzz FuzzWalk -fuzztime 30s`.
- Corpus files are regression seeds. Do not delete one; add a seed whenever you fix a parser bug.

## Gotchas
- No `net/http`, `net/textproto` or `crypto/tls` here (`internal/guards/import_guard_test.go`). Stdlib-only, no internal imports.
- Base64/hex/gzip decoding is NOT done here. Those imports are allowlisted only at `pkg/filter/primitive_jwt.go`, `pkg/redact/placeholder.go`, all `pkg/supply/`, `pkg/redact/digest*.go`, and direct children of `pkg/proxy/`; never feed decoded output to `Inspect`.
- A body `Walk` cannot parse is refused by its callers (`pkg/proxy`) with 400; protocol never silently drops or normalises a body. No `normalize*.go` exists by design.
- `Walk` errors are always leaves-free; a caller that ignores the error and uses the slice will see nil, so check the error before using the result.
