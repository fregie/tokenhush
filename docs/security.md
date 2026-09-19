# tokenhush security model

**English** | [中文](security.zh-CN.md)

This document is the operator-facing security contract of the v0.5.0 rewrite.
It lists the eight invariants the core keeps and the seven residual risks it does
not hide, states what is enforced where, and names the test that pins each
invariant.

- [The direction contract](#the-direction-contract)
- [The eight invariants](#the-eight-invariants)
- [Response-phase effects](#response-phase-effects)
- [The SSE limitation](#the-sse-limitation)
- [What is on disk](#what-is-on-disk)
- [The seven residual risks](#the-seven-residual-risks)

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
   `scan_budget_bytes` for admitted requests. Budget truncation is observable
   rather than silent: a request leaf past the budget writes exactly one
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
| A response-scoped rule decides `Block` (buffered) | 502 with a body naming the rule id; the upstream bytes are discarded; the session's `rule_blocks` counter increments |
| A response-scoped rule decides `Warn` | The response is forwarded unchanged; a metadata-only warning line is written to stderr; no counter change |
| Backfill | Always runs last on the client-bound path, after any evaluation |

Backfill never runs before evaluation, and the forward-only writer is never
reachable from the response path. A known session placeholder echoed by the
model is restored on the way back to the client; a foreign placeholder — one
this session never issued — is returned unchanged and never fabricated into a
secret.

## The SSE limitation

A response-scoped `Block` on an SSE stream cannot recall deltas already emitted:
the decision is taken at the first whole-event evaluation, so events the client
already received stay delivered. Blocking an SSE response stops the stream from
that point on; it does not retract the prefix. An operator who needs
all-or-nothing responses should not route streaming requests through a
response-scoped blocking rule.

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
is never persisted; its masked form either reveals nothing (`****`,
`[redacted]`) or a bounded prefix and suffix of an opaque credential type. The
response-side counter line `tokenhush: restored response placeholders=<N>` is
likewise stderr-only, metadata-only and never persisted.
Redaction runs once per request over the whole client-supplied conversation, so
a long session re-scans and re-redacts the same secrets on every turn: the
`redactions` counter and this stderr log grow with the number of carried
occurrences, not with the number of distinct secrets. That is metadata-only,
per-request work, never a persisted body.

## The seven residual risks

These are recorded honestly rather than left implicit. Listing them is not a
claim that they are absent; each one is a known limit of this design.

| # | Residual risk | What it means in practice | Status |
|---|---|---|---|
| R1 | Encoded secrets are not caught | A secret that is base64-, hex- or URL-encoded before it leaves is not detected: the rewrite has no normalization pass by design, and a non-identity request `Content-Encoding` is refused with 415 rather than decoded for detection. JSON string *escaping* is handled in **both directions** — every decoded detection span is mapped back to the raw, escaped bytes that spell it at substitution, and the client-bound restore is escape/depth-aware, re-spelling a restored secret at the enclosing JSON depth so the client body stays valid JSON — so the residual is content encodings (base64, hex, URL-encoded, or gzip nested inside another container), never JSON string escaping on either direction. | Recorded and accepted |
| R2 | A secret in a JSON object key is not caught | A secret placed in a JSON object key rather than a value is forwarded unchanged: key-position blocking is dropped per D10, so the leaf walk supplies no key leaves and no dead key surface exists. | Recorded and accepted |
| R3 | A signed remote pack may weaken detection through its own allowlist | A signed remote pack may suppress matches through its own global or per-rule allowlist: the non-weakening floor is allowlist-neutral per OD-3 and does not inspect allowlists, while the rule-signing key `rules-2026-09` remains the trust root. | Recorded and accepted |
| R4 | The OD-2 command-rule rejection is dormant and the v2 manifest bump is backward-incompatible | The OD-2 `command`-rule rejection stays dormant until the OD-4 gate opens, and the gate opens only when the rules manifest `schema_version` reaches 2; that bump is backward-incompatible with clients pinning `== 1`, so the backend must keep serving a v1 manifest until the legacy line is out of support. | Recorded and accepted |
| R5 | Response-path bodies are not capped by scan_budget_bytes | A response body is not limited by the request `scan_budget_bytes` gate, while a response-scoped primitive detector still scans at most the per-primitive `budget`: a response leaf past that budget is truncated with no stderr report and no counter, so response-scoped detection can miss content beyond the budget. The budget report is deliberately request-path only and moves no status key. | Recorded and accepted |
| R6 | A placeholder split across SSE JSON-envelope `data:` events is only partially restored | A placeholder content-split across **complete-JSON-envelope** `data:` events is now restored exactly once, in both the `choices[].delta.content` channel and the `tool_calls[].function.arguments` channel, with each contributing event's fragment deleted from its own event's bytes and every emitted envelope still independently valid JSON; matching happens in the **decoded domain**, so an escaped spelling such as `__PII_\u0061pi_key_…__` is accepted and restored. That closure applies when the split spans **consecutive** `data:` events at the **same channel identity**. The remaining residual: when the upstream tears the JSON document itself, the token still completes across the split but only the **raw spelling** is knowable, so a secret carrying a quote, backslash or control byte would then sit raw inside an envelope fragment; and when the **origin** is a torn inner-JSON fragment (not `Encoded`, not valid JSON, opening `{` or `[`) whose secret needs JSON escaping, the placeholder is deliberately **kept** rather than corrupting the client's nested document. A further residual is an **interleaved** split: if an event of a non-matching channel arrives between the two halves, the held segments are released **byte-identically, unchanged** on that non-matching event, so the token never completes, the placeholder fragments are delivered **literally**, and that split is **not** restored. A no-match JSON event stream, including one whose value ends in a partial `__PII_` prefix, is **byte-identical**, and a split foreign placeholder is byte-identical and never fabricated into a secret. Latency contract (owner decision D13): while a token is unresolved the contributing segments of the **affected channel only** are held and not yet sent to the client, until the token resolves (typically the next 1-2 events) or the joint **256 KiB** budget trips, at which point the held segments are released literally, un-restored; the delay is confined to the affected channel and all other traffic streams unchanged, because correctness (never emit a partial placeholder) and bounded memory are preferred over zero added latency for that channel. Exactly **one** carry is active at a time; channel identity is the RFC 6901 path plus each enclosing frame's preceding non-string scalar members plus the leaf's 0-based occurrence among same-path leaves, so an event that **omits** the discriminating scalar (or emits it after the leaf) is outside the identity and will not match, and torn nesting deeper than one inner level with an escape-needing secret remains a residual. | Partially closed; residual recorded and accepted |
| R7 | The opt-in `high_entropy` detector replaces legitimate base64 payloads | `entropy` is off by default because a legitimate high-entropy payload is indistinguishable from a secret by construction: with `detectors: {entropy: true}`, a ~2.7 KB base64 image in an OpenAI `image_url` part or an Anthropic `image` content block is replaced by a single placeholder before the request reaches the upstream, so the model never sees the image — the client still receives it back through backfill, but the upstream payload is substituted. Enable it only for a workload that carries no images, data URLs or long random identifiers, or accept the substitution. Pure-hex runs stay excluded, so hex digests are unaffected. | Recorded and accepted |

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
- **R5 — no new response-side surface.** Closing R5 would mean either capping
  response bodies at `scan_budget_bytes` (a product change with no request-side
  equivalent) or adding a response-path budget report (a new observable surface,
  which this rewrite refuses). Response-scoped detectors are bounded by the same
  per-primitive budget, and the limit is recorded rather than hidden.
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

## Related documents

- [architecture.md](architecture.md) — the layered graph, the single rule
  abstraction and the frozen byte surfaces.
- [plugins.md](plugins.md) — the extension point and its restrictions.
- [PRO-MIGRATION.md](PRO-MIGRATION.md) — what the Pro repository must do after
  this rewrite lands.
