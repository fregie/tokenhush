# tokenhush security model

This document is the operator-facing security contract of the v0.5.0 rewrite.
It lists the eight invariants the core keeps and the four residual risks it does
not hide, states what is enforced where, and names the test that pins each
invariant.

- [The direction contract](#the-direction-contract)
- [The eight invariants](#the-eight-invariants)
- [Response-phase effects](#response-phase-effects)
- [The SSE limitation](#the-sse-limitation)
- [What is on disk](#what-is-on-disk)
- [The four residual risks](#the-four-residual-risks)

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
   record.
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
`[redacted]`) or a bounded prefix and suffix of an opaque credential type.

## The four residual risks

These are recorded honestly rather than left implicit. Listing them is not a
claim that they are absent; each one is a known limit of this design.

| # | Residual risk | What it means in practice | Status |
|---|---|---|---|
| R1 | Encoded secrets are not caught | A secret that is base64-, hex- or URL-encoded before it leaves is not detected: the rewrite has no normalization pass by design, and a non-identity request `Content-Encoding` is refused with 415 rather than decoded for detection. | Recorded and accepted |
| R2 | A secret in a JSON object key is not caught | A secret placed in a JSON object key rather than a value is forwarded unchanged: key-position blocking is dropped per D10, so the leaf walk supplies no key leaves and no dead key surface exists. | Recorded and accepted |
| R3 | A signed remote pack may weaken detection through its own allowlist | A signed remote pack may suppress matches through its own global or per-rule allowlist: the non-weakening floor is allowlist-neutral per OD-3 and does not inspect allowlists, while the rule-signing key `rules-2026-09` remains the trust root. | Recorded and accepted |
| R4 | The OD-2 command-rule rejection is dormant and the v2 manifest bump is backward-incompatible | The OD-2 `command`-rule rejection stays dormant until the OD-4 gate opens, and the gate opens only when the rules manifest `schema_version` reaches 2; that bump is backward-incompatible with clients pinning `== 1`, so the backend must keep serving a v1 manifest until the legacy line is out of support. | Recorded and accepted |

Why each one stays as it is:

- **R1 — no normalization pass.** Decoding a JSON string that itself contains
  JSON (recursively-encoded strings) is in scope; decoding *encodings* is not.
  A normalization pass was deleted because it duplicated detection and produced
  false confidence; the honest position is that an encoded secret can pass.
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

## Related documents

- [architecture.md](architecture.md) — the layered graph, the single rule
  abstraction and the frozen byte surfaces.
- [plugins.md](plugins.md) — the extension point and its restrictions.
- [PRO-MIGRATION.md](PRO-MIGRATION.md) — what the Pro repository must do after
  this rewrite lands.
