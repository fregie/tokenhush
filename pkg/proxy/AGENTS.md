# pkg/proxy KNOWLEDGE BASE

## OVERVIEW
The gateway data plane: loopback bind plus Host/Origin/token guards, path routing, the request-side redaction gate, the client-bound response handlers, and the metadata-only `GET /status` control surface.

## WHERE TO LOOK
| Task | File | Key symbols |
|---|---|---|
| Bind a loopback listener | `listen.go` | `Listen`, `ErrNonLoopbackBind`, `NoticeWriter` |
| Reject a foreign Host/origin | `guard.go` | `CheckHostOrigin`, `Allowed`, `ErrForeignHost`, `ErrCrossOrigin` |
| Map a path to an upstream | `resolve.go` | `Resolve`, `builtinRoutes`, `Upstream`, `BuiltinRoutes`, `ErrUnknownUpstream` |
| Dial upstream, forward headers, redact body | `forward.go` | `Forwarder`, `BodyTransform`, `dialFunc`, `WithDialFunc` |
| Gate the request (walk/evaluate) | `dataplane.go` | `DataPlane`, `RequestEvaluator`, `Walker`, `RequestDecision` |
| Serve `GET /status` | `controlapi.go` | `ControlAPI`, `ControlConfig` |
| Buffer/decode/evaluate a response | `response_buffered.go` | `ResponseHandler`, `Evaluator`, `Backfiller`, `Counters` |
| Stream an SSE response | `response_sse.go` | `SSEHandler`, `redact.SSEBackfiller` |
| Mint/check the control token | `token.go` | `NewToken`, `Token`, `ControlGuard`, `ErrControlUnauthorized` |
| Write/read the session files | `runstate.go` | `RunState`, `WriteSession`, `ReadSession`, `SessionPaths` |

## DATA PATH
1. Loopback guard first: `Listen` binds `127.0.0.1`, adding `[::1]` when the host has IPv6; `CheckHostOrigin` validates Host and (for browser traffic) Origin before any routing. `0.0.0.0`, `::` and LAN IPs fail `ErrNonLoopbackBind`.
2. Routing is the explicit table in `resolve.go`. A configured `upstreams` entry wins (longest path-segment match); else a built-in vendor path; `GET /v1/models` is `Local: true` and answered by the gateway. No entry is `ErrUnknownUpstream`; near-misses like `/v1/model` are never guessed.
3. Outbound: `DataPlane` reads the body; a non-identity `Content-Encoding` passes through to `Forwarder`, which refuses 415 before reading a byte or dialling. A declared-JSON body over budget is 403; unwalkable JSON is 400 (`walkClassification`); detector failure is 403 `plugin_failure`. The `Forwarder.BodyTransform` performs the span-exact substitution, then exactly one upstream dial.
4. Client-bound: SSE (`text/event-stream`) streams through `SSEHandler` with bounded backfill and a lag-by-one-event decision; everything else is read whole by `ResponseHandler`, decoded, evaluated, and buffered. An undecodable coding is 502 before any status is committed.
5. Backfill runs last on every client-bound path and only restores this session's placeholders.
6. Control surface is exactly `GET /status` behind `ControlGuard`.

## KEY CONTRACTS
- Loopback-only: `Listen` refuses any non-loopback literal (`ErrNonLoopbackBind`); `localhost` pins to `127.0.0.1` with no name lookup.
- Exactly ONE upstream dial per served request and ZERO vendor dials; `TestInvariant6NoVendorEgress` asserts this at `pkg/proxy`.
- Control token: `NewToken` mints 32 random bytes (hex), written `0600` beside `run.json`; `ControlGuard` answers 401 for a missing bearer and 403 for a wrong one; `run.json` never carries the token (`RunState` has four keys).
- `Forwarder` forwards every end-to-end header byte-for-byte (auth headers unchanged; only the request BODY is transformed) and strips `Accept-Encoding`.
- `DataPlane` owns orchestration; its `next` handler is the forwarder.

## CONVENTIONS
- Decoder imports (`encoding/hex`, `compress/gzip|flate`) are allowed only in direct children of `pkg/proxy` (e.g. `response_buffered.go`), never in a subpackage.
- Request phase actions: allow, block (redaction is applied via `BodyTransform`). Response phase actions: allow, warn, block only; there is no response redact.

## GOTCHAS
- `listen_test.go` skips `TestListenIPv6LoopbackOrSingleStackFallback` when the host has no usable IPv6 loopback; do not turn that skip into a failure.
- `Counters.Redactions()` counts real byte substitutions (`CountRedactions(n)`); `countRuleBlock` moves alongside `countContentPolicyBlock` on a request Block and on a buffered response Block (a 502 there).
- `primaryRule` names only the first rule id; a Warn writes one line per id.
