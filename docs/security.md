# tokenhush security model

**English** | [中文](security.zh-CN.md)

This document is the operator-facing security contract of the v0.5.0 rewrite.
It lists the eight invariants the core keeps and the nine residual risks it does
not hide, states what is enforced where, and names the test that pins each
invariant.

- [The direction contract](#the-direction-contract)
- [The eight invariants](#the-eight-invariants)
- [Response-phase effects](#response-phase-effects)
- [Buffered responses and SSE](#buffered-responses-and-sse)
- [What is on disk](#what-is-on-disk)
- [The nine residual risks](#the-nine-residual-risks)

## The direction contract

Content moves in two directions, and rules may take different actions in each.
This is an enforced design rule, not a residual risk: on the response path rules
may only `Block` or `Warn`, `Redact` is request-path only, and a rule whose
scope includes the response phase while its action is `redact` is rejected at
compile time and again at registration. The compiler catches the document path;
the registry catches a directly-registered Go value; the evaluation loop
re-asserts it. No arrival route can request a substitution on the response path.

| Phase | Actions that may be applied |
|---|---|
| Request content (outbound) | `Block`, `Redact`, `Warn`. `Redact` is the only place the placeholder writer runs. |
| Response content (client-bound) | `Block` and `Warn` only. `Redact` is rejected. |
| Both | A rule may *evaluate* in either phase. Only the request phase may substitute. |

## The eight invariants

All eight invariants below are enforced in code and pinned by the named tests.

| # | Invariant | Named test | Owner file |
|---|---|---|---|
| 1 | Never backfill placeholders outbound | `TestInvariant1NeverBackfillOutbound` | `pkg/redact/invariants_test.go` |
| 2 | No request/response plaintext on disk; metadata only | `TestInvariant2NoPlaintextOnDisk` | `pkg/audit/invariants_test.go` |
| 3 | No root certificate, no MITM by default | `TestAbsenceNoCertificateInstallPath` | `internal/guards/absence_guard_test.go` |
| 4 | Loopback-only bind, Host/Origin validation and the control bearer token | `TestInvariant4LoopbackOnly` | `pkg/proxy/invariants_test.go` |
| 5 | Fail-safe on detection failure, not fail-open | `TestInvariant5FailSafe` | `pkg/filter/invariants_test.go` |
| 6 | Exactly two switchable vendor-bound egress categories, command-scoped | `TestInvariant6NoVendorEgress` | `pkg/proxy/invariants_test.go` |
| 7 | Content-Encoding fail-closed | `TestInvariant7EncodingFailClosed` | `pkg/proxy/invariants_test.go` |
| 8 | SSE-aware bounded backfill (256 KiB) | `TestInvariant8BoundDerived` | `pkg/redact/invariants_test.go` |

What each one means in practice:

1. **Never backfill placeholders outbound.** The outbound writer holds only the
   forward map (secret to placeholder); it has no reverse map and no restore
   method, and its exported surface is placeholder minting alone. Re-applying a
   redaction is idempotent, and a body that already carries a known placeholder
   is forwarded verbatim.
2. **No request/response plaintext on disk; metadata only.** The audit seam is a
   single write method and writes metadata-only records; the default sink is a
   no-op that persists nothing. The redaction log is masked, stderr-only and
   never persisted. The named sink-level test `TestInvariant2NoPlaintextOnDisk`
   lives in `pkg/audit/invariants_test.go`; the run-level half,
   `TestOndiskGuardRunLevelPlaintext` in `internal/guards/ondisk_guard_test.go`,
   drives the real binary and scans everything the run could have written.
3. **No root certificate, no MITM by default.** tokenhush never terminates TLS.
   The absence guard scans production Go source for every shape a
   certificate-install or MITM path would need — TLS listeners, key pairs, cert
   pools, `tls.Config` and `http.Server` literals, embedded certificates and
   MITM-flavoured config keys — and fails if any appears.
4. **Loopback-only bind, Host/Origin validation and the control bearer token.**
   A non-loopback bind is impossible (`ErrNonLoopbackBind`), a foreign `Host` is
   rejected, a cross-origin request is rejected, and the control surface refuses
   a missing credential with 401 and a wrong one with 403. Session files are
   `0600` and `run.json` never carries the token.
5. **Fail-safe on detection failure, not fail-open.** A rule that panics, times
   out, exceeds its span budget, returns malformed findings or cannot be invoked
   at all yields a labelled refusal carrying the right reason — never a silent
   pass, never a crash — and each failure writes exactly one metadata-only audit
   record. Detection is also budget-bounded: a primitive-typed detector inspects
   at most its per-primitive byte budget of one leaf, aligned with
   `scan_budget_bytes` as a per-leaf, per-detector budget. Budget truncation is
   observable rather than silent: a request leaf past the budget writes exactly one
   metadata-only `tokenhush: detector budget exceeded leaf=<len> budget=<n>`
   stderr line and moves no counter and no status key.
6. **Exactly two switchable vendor-bound egress categories, command-scoped.**
   The product may reach the vendor only for the two disclosed purposes, and
   only until the operator sets the disclosed switch. This invariant is proven
   by two artifacts, and both are required: the named test proves the data plane
   makes exactly one upstream dial and zero vendor dials; the egress guard in
   `internal/guards/egress_guard_test.go` proves the disclosure declares exactly
   two categories, each naming its switch, with every host the frozen supply
   host, and that each switch short-circuits before any network call.
7. **Content-Encoding fail-closed.** A request carrying a non-identity
   `Content-Encoding` is refused with 415 before its body is read and before any
   upstream dial is opened. On the response side, gzip and deflate are decoded
   before any status is committed; a coding the gateway cannot decode is a 502
   that discards the upstream bytes without moving a content counter. There is
   no uninspected pass-through.
8. **SSE-aware bounded backfill (256 KiB).** An unterminated token in an SSE
   stream can never make the backfill writer hold more than
   `SSEBackfillHoldbackBytes` (256 KiB); past the bound the oldest held bytes
   leave literally and in order, so the writer always makes progress instead of
   buffering without limit. Nothing is dropped and nothing is fabricated.

## Response-phase effects

These effects are frozen because they are observable:

| Condition | Effect |
|---|---|
| A response-scoped rule decides `Block` | 502 with a body naming the rule id, before any byte is committed; the whole buffered upstream response is discarded; the session's `rule_blocks` counter increments |
| A response-scoped rule decides `Warn` | The response is forwarded unchanged; a metadata-only warning line is written to stderr; no counter change |
| A buffered response exceeds `response_buffer_bytes` | 502 before any byte is committed, with no evaluation of the discarded body |
| A buffered response outlives `response_timeout` | 504 before any byte is committed; the buffer cap wins if both trip |
| Backfill | Always runs last on the client-bound path, after any evaluation |

Backfill never runs before evaluation, and the forward-only writer is never
reachable from the response path. A known session placeholder echoed by the
model is restored on the way back to the client; a foreign placeholder — one
this session never issued — is returned unchanged and never fabricated into a
secret.

## Buffered responses and SSE

Every upstream response is buffered **whole** before any byte reaches the client:
the gateway records the status and headers, buffers and decodes the body (a
content coding it cannot decode is a 502 that discards the upstream bytes without
committing), and only then evaluates, restores and commits. That includes
`text/event-stream`. SSE is no longer streamed token-by-token: its events are
decoded, the aggregate of every event whose joined `data` is valid JSON is
evaluated, backfill runs, and the restored stream is emitted in one piece. There
is no point at which the client holds a partial response the gateway could not
take back, and there is no token-level streaming.

A response-scoped `Block` on a buffered SSE response is a 502 before any byte is
committed, exactly like a buffered JSON response: nothing has to be recalled
because nothing was sent. The buffer is bounded by `response_buffer_bytes`
(default **32 MiB**); a response past the cap is a 502 before commit. The whole
read is bounded by `response_timeout` (default **5m**); a response past the
deadline is a 504 before commit, and the cap wins if both trip. Backfill still
runs last, so a placeholder content-split across SSE `data:` events restores
exactly once before the single commit.

## What is on disk

| Path | Contents |
|---|---|
| `<DataDir>/run.json` | `pid`, `port`, `addrs`, `started_at`. Never the control token. Mode `0600`, atomic, removed on clean shutdown. |
| `<DataDir>/control.token` | The session control bearer token. Mode `0600`, atomic, removed on clean shutdown. |
| `<DataDir>/rules/…` | The verified rules cache and the anti-rollback mark: signed documents and serial numbers, no request content. |
| `<DataDir>/update/highwater.json` | The update anti-rollback mark: a serial/version integer, nothing else. |

Request and response bodies, detected secrets and the placeholder-to-secret
mapping are never written to disk. The redaction log line
`tokenhush: redacted request <type> (len=<N>) <masked>` goes to stderr only and
is never persisted; its masked form reveals nothing (`****`, `[redacted]`), a
bounded prefix and suffix of an opaque credential type, the PEM header kind of a
private-key block (a fixed allowlisted literal, never the captured header text),
or the domain of an email address with its local part hidden. The
response-side counter line `tokenhush: restored response placeholders=<N>` is
likewise stderr-only, metadata-only and never persisted.
Redaction runs once per request over the whole client-supplied conversation, so
a long session re-scans and re-redacts the same secrets on every turn: the
`redactions` counter and this stderr log grow with the number of carried
occurrences, not with the number of distinct secrets. That is metadata-only,
per-request work, never a persisted body.

## The nine residual risks

These are recorded honestly rather than left implicit. Listing them is not a
claim that they are absent; each one is a known limit of this design.

| # | Residual risk | What it means in practice | Status |
|---|---|---|---|
| R1 | Encoded secrets are not caught | A secret that is base64-, hex- or URL-encoded before it leaves is not detected: the rewrite has no normalization pass by design, and a non-identity request `Content-Encoding` is refused with 415 rather than decoded for detection. JSON string *escaping* is handled in **both directions** — every decoded detection span is mapped back to the raw, escaped bytes that spell it at substitution, and the client-bound restore is escape/depth-aware, re-spelling a restored secret at the enclosing JSON depth so the client body stays valid JSON — so the residual is content encodings (base64, hex, URL-encoded, or gzip nested inside another container), never JSON string escaping on either direction. | Recorded and accepted |
| R2 | A secret in a JSON object key is not caught | A secret placed in a JSON object key rather than a value is forwarded unchanged: key-position blocking is dropped per D10, so the leaf walk supplies no key leaves and no dead key surface exists. The `sensitive_keys` document block does not change this — it redacts the **value** of a named immediate object member key at any depth, never a secret stored in the key itself. Two sibling shapes stay unmatched and are recorded here: when the sensitive key's value is a container rather than a string member (`{"password":{"secret":"x"}}`, whose immediate key is `secret`), and the k8s/docker-env sibling shape (`{"name":"DB_PASSWORD","value":"…"}`). | Recorded and accepted |
| R3 | A signed remote pack may weaken detection through its own allowlist | A signed remote pack may suppress matches through its own global or per-rule allowlist: the non-weakening floor is allowlist-neutral per OD-3 and does not inspect allowlists, while the rule-signing key `rules-2026-09` remains the trust root. | Recorded and accepted |
| R4 | The OD-2 command-rule rejection is dormant and the v2 manifest bump is backward-incompatible | The OD-2 `command`-rule rejection stays dormant until the OD-4 gate opens, and the gate opens only when the rules manifest `schema_version` reaches 2; that bump is backward-incompatible with clients pinning `== 1`, so the backend must keep serving a v1 manifest until the legacy line is out of support. | Recorded and accepted |
| R5 | Response-path bodies are not capped by the request-side body guard | A response body is not limited by the request-side guards: `response_buffer_bytes` (default **32 MiB**) is a separate **total** cap on the whole buffered response, and a response past it is a 502 before commit. The request-side `max_body_bytes` memory guard never applies to a response, and the per-leaf, per-detector `scan_budget_bytes` is not a whole-body cap in either direction. That total cap does not close R5. A response-scoped primitive detector still scans at most the per-primitive `budget`, and a response leaf past that budget is truncated with no stderr report and no counter, so response-scoped detection can still miss content beyond the per-primitive budget inside a body the total cap admitted. The budget report remains deliberately request-path only and moves no status key. | Recorded and accepted |
| R6 | A placeholder split across SSE JSON-envelope `data:` events is only partially restored | A placeholder content-split across **complete-JSON-envelope** `data:` events is now restored exactly once, in both the `choices[].delta.content` channel and the `tool_calls[].function.arguments` channel, with each contributing event's fragment deleted from its own event's bytes and every emitted envelope still independently valid JSON; matching happens in the **decoded domain**, so an escaped spelling such as `__PII_\u0061pi_key_…__` is accepted and restored. That closure applies when the split spans **consecutive** `data:` events at the **same channel identity**. The remaining residual: when the upstream tears the JSON document itself, the token still completes across the split but only the **raw spelling** is knowable, so a secret carrying a quote, backslash or control byte would then sit raw inside an envelope fragment; and when the **origin** is a torn inner-JSON fragment (not `Encoded`, not valid JSON, opening `{` or `[`) whose secret needs JSON escaping, the placeholder is deliberately **kept** rather than corrupting the client's nested document. A further residual is an **interleaved** split: if an event of a non-matching channel arrives between the two halves, the held segments are released **byte-identically, unchanged** on that non-matching event, so the token never completes, the placeholder fragments are delivered **literally**, and that split is **not** restored. A no-match JSON event stream, including one whose value ends in a partial `__PII_` prefix, is **byte-identical**, and a split foreign placeholder is byte-identical and never fabricated into a secret. Latency contract (owner decision D13): while a token is unresolved the contributing segments of the **affected channel only** are held and not yet sent to the client, until the token resolves (typically the next 1-2 events) or the joint **256 KiB** budget trips, at which point the held segments are released literally, un-restored; the delay is confined to the affected channel and all other traffic streams unchanged, because correctness (never emit a partial placeholder) and bounded memory are preferred over zero added latency for that channel. Exactly **one** carry is active at a time; channel identity is the RFC 6901 path plus each enclosing frame's preceding non-string scalar members plus the leaf's 0-based occurrence among same-path leaves, so an event that **omits** the discriminating scalar (or emits it after the leaf) is outside the identity and will not match, and torn nesting deeper than one inner level with an escape-needing secret remains a residual. | Partially closed; residual recorded and accepted |
| R7 | The opt-in `high_entropy` detector replaces legitimate base64 payloads | `entropy` is off by default because a legitimate high-entropy payload is indistinguishable from a secret by construction: with `detectors: {entropy: true}`, a ~2.7 KB base64 image in an OpenAI `image_url` part or an Anthropic `image` content block is replaced by a single placeholder before the request reaches the upstream, so the model never sees the image — the client still receives it back through backfill, but the upstream payload is substituted. Enable it only for a workload that carries no images, data URLs or long random identifiers, or accept the substitution. Pure-hex runs stay excluded, so hex digests are unaffected. | Recorded and accepted |
| R8 | The global blocklist is not applied on every evaluation path | `Policy.Decide` and the shared `collect` do not apply the global blocklist; only `Compiled.Evaluate` runs `blocklistSpans`. A `sensitive_keys`-gated leaf and every other leaf therefore keep Block precedence on the `Compiled.Evaluate` path, but a caller that decides through `Policy.Decide` does not get the global blocklist applied. This is recorded rather than fixed: the blocklist-not-suppressed test lives on the `Compiled.Evaluate` path. | Recorded and accepted |
| R9 | The request body guard is a memory wall, and the second walk is unguarded | A body at or below `max_body_bytes` (default 64 MiB) is walked twice on the declared-JSON path, and only the **first** walk (`DataPlane.inspect`) runs inside `guardCall` under `detector_timeout` (30 s). The second walk, `redactRequest` inside the Forwarder, is **unguarded and has no timeout**: the first walk gates admission in practice but is not a bound on the second. `protocol.Walk` copies every leaf value (`[]byte(raw)`), so one walk retains roughly the body size again, and a declared-JSON request walks twice, so peak memory is a small multiple of the body, not the body alone. Raising the admitted ceiling from the old 32 MiB aggregate budget to the 64 MiB body guard widens the pre-existing scalar/path/identity amplification exposure window from 32 MiB to 64 MiB; `MaxNestingDepth` still bounds nesting, the first walk is still fail-closed on timeout, and the abandoned walk goroutine on timeout is pre-existing. A body above `max_body_bytes` is still refused 403 `body_too_large`, and because a session only grows it can reach the wall again — the difference is that the wall is now observable and actionable (one metadata-only `tokenhush: refused request body_too_large` stderr line) rather than a silent aggregate refusal. | Recorded and accepted |

Why each one stays as it is:

- **R1 — no normalization pass.** Decoding a JSON string that itself contains
  JSON (recursively-encoded strings) is in scope; decoding *encodings* is not.
  JSON string escaping is not this residual: the substitution path maps each
  decoded span back to its raw escaped bytes. A normalization pass was deleted
  because it duplicated detection and produced false confidence; the honest
  position is that an encoded secret can pass.
- **R2 — key-position blocking dropped, not demoted.** The walk supplies no key
  leaves at all, so there is no half-working key path to mislead an operator.
- **R3 — the floor stays allowlist-neutral.** Making the floor inspect
  allowlists would reject signed packs the legacy client accepted, drop the
  client to the built-ins and leave it weaker than the client it replaces. That
  would be a security regression, not hardening. The trust root is the signing
  key, and a pack that weakens detection is a pack the holder of the signing key
  chose to publish.
- **R4 — a coordinated backend change, not a switch to flip.** The client side
  of the gate is implemented and tested; the backend must keep serving a v1
  manifest until no supported client pins `== 1`. The OD-4 gate exists so that
  the client behaviour can be ready before the manifest version moves.
- **R5 — a total cap is not a per-primitive budget.** `response_buffer_bytes`
  bounds the whole buffered response and is a new response-side surface, but it
  is a total cap, not a per-leaf detection budget: it cannot tell which bytes a
  response-scoped detector failed to scan. Closing the remaining truncation
  would mean either aligning the per-primitive budget with the whole body or
  adding a response-path budget report (a new observable surface this rewrite
  refuses). Response-scoped detectors stay bounded by the same per-primitive
  budget, and the per-primitive truncation is recorded rather than hidden.
- **R6 — the envelope split is the upstream's choice; complete-envelope content
  splits are now closed.** A JSON-envelope stream whose event values are split
  mid-document already cannot be parsed event-by-event by any client, so there
  is no per-event JSON document left to preserve; the bounded reassembler still
  completes the token across the split, but only the raw spelling is knowable,
  and a secret carrying a quote, backslash or control byte would then sit raw
  inside an envelope fragment. A torn inner-JSON origin whose secret needs JSON
  escaping is the second residual: the placeholder is deliberately kept rather
  than corrupting the client's nested document. When every event is a complete
  JSON envelope, a content-split placeholder restores exactly once, in the
  `content` and the `tool_calls[].function.arguments` channels, and matching is
  done in the decoded domain so an escaped spelling is accepted; a no-match
  stream and a split foreign placeholder stay byte-identical, and a
  non-matching channel's event arriving between the halves releases the held
  segments byte-identically, unchanged, so the split is delivered literally and
  is not restored. The latency
  contract (D13) is the deliberate cost of that correctness: the affected
  channel's contributing segments are held until the token resolves or the
  joint `256 KiB` budget trips, and are then released literally, un-restored.
  Buffered bodies and unsplit JSON envelopes keep the depth-aware, valid-JSON
  restore. No residual conceals a secret from a third party: the client is
  the intended recipient.
- **R7 — entropy is opt-in for a reason.** High entropy is not evidence of a
  secret: an image, a data URL or a random identifier looks exactly like one.
  The detector is therefore off by default and the substitution it performs on a
  legitimate base64 payload is recorded here rather than hidden. A workload that
  never carries such payloads can enable it; one that does should not.
- **R8 — a pre-existing gap, made visible by the gate.** The global blocklist was
  only ever applied on the `Compiled.Evaluate` path; the `sensitive_keys` gate
  did not create the gap, so fixing it here would be an unrelated behaviour
  change. The gate keeps Block precedence wherever the blocklist does run, and
  the runtime gap is recorded instead of silently claimed fixed.
- **R9 — the wall moved out to the memory guard.** The old aggregate refusal was
  a scan policy that fired on legitimate multimodal traffic; the honest
  replacement is a memory guard at the body boundary that names its refusal
  (`body_too_large`) and logs it once. The second, unguarded walk and the
  per-leaf copies are pre-existing costs of walking twice; bounding the second
  walk would change the forwarder's contract, so they are recorded rather than
  fixed here.

## Related documents

- [architecture.md](architecture.md) — the layered graph, the single rule
  abstraction and the frozen byte surfaces.
- [plugins.md](plugins.md) — the extension point and its restrictions.
