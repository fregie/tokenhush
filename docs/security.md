# Security Model

**English** | [中文](security.zh-CN.md)

> Status: V1 is implemented (2026-09). The hard invariants are locked by named tests in `pkg/*`, and are restated under Hard invariants below and in `architecture.md`.

Tokenhush is itself a security tool, so **it must be secure first**. This document defines the threat model and the invariants that cannot be broken.

## 🛡️ Threat model

| Threat | Description | Mitigation |
|---|---|---|
| **Prompt injection to exfiltration** | An attacker tricks the model into emitting a placeholder; if the gateway backfills on the outbound direction, the secret leaks | **Hard invariant: never backfill outbound** (see Hard invariants). This blocks the outbound leak path only: the inbound direction deliberately restores placeholders so a local tool receives the real value, and a prompt-injection payload that reaches a tool call is an accepted risk (private Pro repository ADR-0027) |
| **Local malicious process/web page reaches the gateway** | Any local process or browser page can `fetch` `127.0.0.1:8787` | Loopback-only bind (`127.0.0.1`, plus `[::1]` when the host has an IPv6 loopback); `Host` header validation; the control plane additionally requires a bearer token generated per `run`, stored `0600` on disk, and same-origin validation for requests carrying `Origin`; the runtime allowlist can be changed only through that authenticated control plane, and every change writes one metadata-only audit row |
| **DNS rebinding** | A malicious domain resolves to 127.0.0.1 to bypass same-origin | `Host`/`Origin` header validation |
| **Placeholder collision** | Two secrets map to the same placeholder, causing a wrong backfill | HMAC-deterministic mapping + high-entropy suffix |
| **Plaintext read from memory** | Debug or dump by another process under the same user | Sandbox/hardened runtime; no plaintext written to disk |
| **Supply-chain attack** | A dependency is poisoned (see the LiteLLM incident) | Minimal dependencies + pinned versions + signed releases + SBOM |

- **Prompt injection, concretely.** A poisoned file tells the model to print `__PII_email_3f9a2b__`. If the model echoes it and the gateway backfilled outbound, the real email would go upstream; invariant 1 blocks that one path, because a placeholder is never restored toward the upstream. The other direction is deliberately different: an inbound body (a response, or a model-emitted tool call) does have its placeholders restored, which is what lets a local tool receive the real value. A prompt-injection payload that reaches a tool call can therefore still materialise a secret locally; that residual risk is accepted, with its compensating controls and honest limits recorded in the private Pro repository's ADR-0027.
- **Local reachability, concretely.** A random npm `postinstall` script, or a web page you have open, can call `fetch("http://127.0.0.1:8787/...")`. It still fails: loopback-only bind, `Host` check, and a per-`run` bearer token.

## 🛡️ Hard invariants

1. **Never backfill placeholders outbound.** Backfill happens only on responses returned to the client.
2. **Do not store request/response plaintext by default.** The core stores no request or response content. The redaction log line printed to the console is a transient local diagnostic: only a masked form, the detector type, and the byte length, never the full value, and it is never persisted. It is on by default and can be disabled with `--log-redactions=false`.
3. **No root certificate is installed and no MITM is performed by default.** MITM is an explicit opt-in in later stages and is not implemented in the public core.
4. **The local service binds loopback only: `127.0.0.1` always, plus `[::1]` when the host has an IPv6 loopback. On a host without an IPv6 loopback it serves `127.0.0.1` only and logs a notice.**
5. **Fail-safe on detection failure, not fail-open.** When the gateway cannot tell whether content is sensitive, it prefers over-redaction, or allows with a warning, and never silently emits plaintext. The policy is configurable (see below). The one runtime affordance that can let a specific value through is the allowlist: changing it is an explicit, audited user action taken through the loopback control plane (the CLI or the Pro Web UI), never a silent file edit, and the model is not an authorized mutator.
6. **Vendor-bound egress is exactly two switchable, command-scoped categories.** The only requests that leave the machine for the vendor are update check and rule sync, both disclosed in the machine-readable [`egress.yaml`](../egress.yaml) and both switchable. Neither is performed by the gateway's data plane: a proxied request still egresses only to the configured upstream, placeholders are never backfilled outbound, and the audit seam carries metadata only.
7. **An inbound response with a non-identity `Content-Encoding` is decoded or failed closed; it is never passed through uninspected.** The pipeline classifies **every** `Content-Encoding` header line (`Header.Values` split on commas, not just the first value). A `gzip`/`deflate` body is decompressed in the buffered path **before any status code is committed**, then inspected and backfilled, and its `Content-Encoding` is removed. An unsupported coding (`br`, `zstd`, …), a decode failure, or a decodable coding on a `text/event-stream` body is answered **502 Bad Gateway** and the upstream bytes are discarded. Test-locked by `TestPipelineGzipResponseBackfilled`, `TestPipelineDecodableResponseInspected`, `TestPipelineUndecodableEncodingFailsClosed`, and `TestPipelineMultiValuedEncodingFailsClosed`.
8. **An inbound request with a non-identity `Content-Encoding` is rejected with 415 before any transform and before the upstream is dialed.** A request body the client compressed would otherwise bypass redaction, because the request path leaf-walks plain JSON and cannot decode a compressed body. The check lives in `Forwarder.ServeHTTP`, the only layer that can read the header: the body is never read, no transform runs, and no upstream connection is opened. Test-locked by `TestPipelineCompressedRequestBodyFailsClosed`.
9. **Inbound backfill is SSE-aware and its holdback is bounded.** A placeholder split across several `data:` events (each carrying a partial JSON delta) cannot be found in the raw byte stream, so the backfiller reassembles it per JSON leaf path and restores it when that path's window empties at an event boundary. The contributing events are rewritten in place, so SSE framing, event count, and every non-delta field (`event:`, `id:`, `retry:`, comments, multi-line or colon-less `data:`) are preserved byte for byte. Retained bytes are bounded by `sseBackfillMaxHoldbackBytes` (256 KiB); past the bound the oldest window is flushed as literal text. Test-locked by `TestPipelineSSEBackfillAcrossDeltas`, `TestSSEBackfillerRestoresAcrossProviderDeltaPaths`, and `TestSSEBackfillerHoldbackBoundEnforcedFromConstant`.

> [!IMPORTANT]
> Invariant 1 covers the outbound half of the prompt-injection risk: placeholders are only ever replaced on the way back to the client, never on the way to the upstream, so an echoed placeholder does not carry the real value upstream. The inbound half is deliberately the other way: restoring placeholders on the way back to the client is what lets a local tool receive the real value, and it also lets a prompt-injection payload that reaches a tool call materialise a secret locally. That residual risk is accepted, with its compensating controls and honest limits recorded in the private Pro repository's ADR-0027.

> [!NOTE]
> **Compatibility change (deliberate).** A client that compressed its request body (`Content-Encoding: gzip`) used to be forwarded as-is, which silently bypassed redaction because compressed bytes are not walkable JSON. It now receives **415 Unsupported Media Type** (invariant 8). This is a fail-safe trade-off: rejecting the request is preferred over forwarding an uninspected body. On the response side, a `br`/`zstd` response an upstream sends despite the identity request is answered **502** (invariant 7) for the same reason.

> [!NOTE]
> **Known boundary (stdlib behaviour, not a parser defect).** With the default HTTP client, a response whose `Content-Encoding` arrives as two header lines with a first value of exactly `gzip` is decompressed by Go's `net/http` transport before the pipeline ever sees it, because the transport tests `Header.Get` (the first value only) rather than all values. Observed as a 200 with an empty body when the body is not valid gzip, with no upstream bytes released to the client. This is `net/http` behaviour, not a parser defect, and it does not create an uninspected pass-through: the pipeline's own all-values classifier is unaffected and is locked by `TestClassifyContentEncodingMultiValued`, and the transport's early decode releases no bytes the pipeline would otherwise have forwarded raw.

## 🧯 Failure policy, per path

The failure policy depends on which direction a body travels, because only the outbound (request) direction can turn a parse failure into an upstream leak.

- **Request path: fail closed when JSON is declared.** A request body is leaf-walked before it is forwarded. If the walk fails and the request declares JSON (a `Content-Type` of `application/json*`, or no `Content-Type` at all with JSON symptoms, meaning the first non-whitespace byte is `{`, `[` or `"`), the gateway fails closed with **HTTP 400** and sends **zero upstream bytes**. The verdict is made at the HTTP layer (`pkg/gateway`'s data plane), because the body-transform seam cannot see headers; the underlying sentinel is `proxy.ErrUnwalkableBody`. A request that is explicitly non-JSON (`text/plain`, …) keeps the documented passthrough: the body is forwarded byte for byte and no walk runs. Test-locked by `TestPipelineMalformedInputPassthrough` (the seam returns the sentinel with a byte-identical body) and the `pkg/gateway` data-plane tests.
- **Response and SSE path: deliberately not fail-closed.** A response body the walker cannot parse is still forwarded byte for byte, and backfill still runs. Both directions here are client-bound (inbound): an unparseable response cannot exfiltrate anything to an upstream, and failing closed would break legitimate plain-text error bodies and `data: [DONE]`/ping streams. The skip is no longer silent: `Pipeline.ResponseWalkFailures()` counts it, and each skip emits one metadata-only `RedactionEvent` (`response_walk_failed` for the buffered path, `sse_walk_failed` for the SSE desync guard; direction `response`, phase `response_content`) that carries no body bytes, object keys or JSON paths.

This asymmetry is deliberate: fail closed where a failure could leak, stay transparent and observable where it cannot.

## 📌 Named routing exceptions

The gateway **refuses to guess** an upstream for an unrecognised request: an unknown route is an explicit typed error (`ErrUnknownUpstream`), never a silent misroute. There is exactly one **named exception list**, and a path gets on it only because the call carries no user data and every provider serves it identically:

| Path | Default upstream | Why it is safe |
|---|---|---|
| `GET /v1/models` | OpenAI | Model discovery. The request carries no prompt or payload, and both providers expose the same shape; assigning one cannot leak or misroute user content. |

A configured `upstreams:` override still wins over the exception (and over the built-in table). Every other path — including near-misses such as `/v1/model`, `/v1/models/foo` or `/v1/modelsX` — stays a typed error, so the never-misroute rule is unchanged. The list is closed and test-locked by `TestResolveModels` in `pkg/proxy`; adding an entry is a deliberate, documented decision, not a default.

## 🔍 Detector trade-offs

- **False positives (over-redaction)** hurt the experience: the model receives a placeholder and code or answers degrade.
- **False negatives (under-redaction)** hurt the promise: sensitive content leaves the machine.

The V1 strategy is **deterministic, high-precision-first detectors** (known key prefixes, high entropy, JWT, private-key headers, Luhn card-number checksums, and email addresses), backed by an allowlist (static in `tokenhush.yaml`, plus a runtime-mutable store that is audited and changed only through the control plane) and one-click release. The project does **not** claim "never leaks". The honest claim is **"high-confidence secret interception"**.

## 🔎 Detection scope: values and object keys

Detection runs at two independent positions in a walked JSON document:

- **String values** (the original scope). Every string leaf is inspected, and a finding is replaced with a placeholder.
- **Object keys** (added later). A JSON object's member names are inspected as an **independent key-position mechanism**: `protocol.WalkKeys`, a separate API that returns key spans and JSON Pointer paths. At key positions the participating detector set is exactly **`prefix` (api_key), `high_entropy`, `jwt`, `private_key`**. `luhn` (credit_card) and `email` are deliberately excluded there, to avoid false positives on 16-digit numeric keys and email-shaped keys. A credential-shaped key **fails the request closed** (the request is blocked with zero upstream bytes), and keys are **never rewritten**; a detector that fails closed at a key position also blocks.

Both domains share the detector rules, including `high_entropy`'s **structural exemptions**: provider-assigned opaque ids (`call_…`, `toolu_…`, `chatcmpl-…`, `msg_…`, `resp_…`), data-URI base64 payloads (`data:<mime>[;param];base64,…`), base64-alphabet payload runs of 256 bytes or more, and absolute paths carrying a hash segment of 32 or more hex characters are not treated as secrets. The exempted grammars are enumerated in `KnownStructuralIdentifierExemptions()` (mirrored in `pkg/redact/testdata/known_structural_exemptions.txt`); the residual risk is recorded under "Known limitations" below.

Object keys are **not** `Leaf`s and never enter the document model defined by `pkg/extension`. The key scan is a separate, additive API (`protocol.WalkKeys`, added without changing `Walk` or `Leaf`), so the "leaf = value" contract documented in `architecture.md` is **unchanged**.

**Decision record.** Adding a separate `WalkKeys` API, instead of extending `protocol.Walk`'s `Leaf` contract with key positions, is a deliberate decision (the O3 decision in the hardening plan). Extending `Leaf` was rejected because it would change `pkg/extension`'s V1-stable public surface and break the "leaf = value" contract (`architecture.md`). The key-position mechanism is pinned by `pkg/protocol` tests and by `pkg/proxy`'s key tests; the cross-repo assembly contract for the surrounding hardening work is frozen in the private Pro repository's ADR-0012 amendment A2.

## 🔒 Mutation-channel self-protection

The allowlist is the one runtime affordance that can stop a specific value from being redacted, so the channel that changes it (component C8 in the hardening plan) is guarded. The guard is **high-confidence interception, best-effort**: it recognises a fixed, explicitly enumerated pattern set, and an adversary who encodes, splits, wraps or indirectly invokes the channel can evade it. It is **not** a closed guarantee, and nothing in this section should be read as one. The allowlist remains changeable only by the human operator, through the authenticated loopback control plane; a model-originated tool call that reaches for that channel is refused on a best-effort basis.

**The change channel.** Three ways to change the allowlist, all of which the guard aims at:

- the `tokenhush allowlist` CLI (`tokenhush allowlist list|add|remove`);
- the loopback control plane (`/allowlist` and `/status` on the control port);
- a direct write to `<DataDir>/allowlist.json`.

**What the guard does.** Mutation-channel detection runs on the response side, over model-originated tool-call arguments. The pattern set is explicit, enumerable and auditable (`MutationChannelPatternInventory()` in `pkg/proxy`). The control-port class requires evidence of the control channel, never the bare port: a loopback host with the bound control port **plus** a control endpoint path or a control request line. A data-plane path on the same port (for example `http://127.0.0.1:8787/v1/chat/completions`) is legitimate traffic and is not refused.

- On the buffered path it inspects each tool call's `arguments` string, including its nested leaves, and on a match rewrites **only that tool call's** whole arguments value to a structured JSON refusal (`{"error":"<notice>","refused":true,"channel":"<class>"}`), so a client that parses `arguments` as JSON succeeds and the model can adapt. Other tool calls in the same response are untouched, and no response-wide `403` is returned.
- On the streaming (SSE) path it accumulates a tool call's streamed arguments **per path, bounded by `SSEGuardCap` (64 KiB)**, then applies the same per-tool-call refusal; fragments that arrive after a hit are dropped. The cap is deliberately smaller than the backfill holdback (`sseBackfillMaxHoldbackBytes`, 256 KiB) so the decision is reachable.
- The guard is gated by `self_protection.enabled` and `self_protection.modes`; `enabled: false` is an explicit opt-out.

**The exclusion set.** Two values are force-redacted on the outbound direction, **before the detectors run** (so the allowlist cannot exempt them), and are **never restored inbound**:

- the session's control-token value, installed once the token exists and refreshed on every allowlist mutation;
- the bytes of `<DataDir>/allowlist.json`.

This narrow pair is the only exception to the general backfill behaviour; every other value's backfill behaviour is byte-for-byte unchanged. The set deliberately does **not** contain allowlist entry values, so a value the operator has allowed still passes through.

**Observability.** Every refusal and every allowlist change is recorded as metadata only, with no plaintext and no entry values, and `tokenhush status` exposes the counts: `self_protection_interceptions`, `allowlist_mutations`, `stream_guard_refusals`, `stream_guard_fail_closed` and `egress_blocks`.

### Known limits and uncovered classes (aggregate)

This is the single aggregate list for the hardening work's known boundaries. None of it is closed; the register throughout is **high-confidence interception**. The machine-readable sources are `KnownUncoveredMutationChannels()` and `MutationChannelPatternInventory()` in `pkg/proxy` (mirrored in `pkg/proxy/testdata/known_uncovered_mutations.txt`), and `KnownUncoveredEncodings()` and `KnownStructuralIdentifierExemptions()` in `pkg/redact` (mirrored in `pkg/redact/testdata/known_uncovered_encodings.txt` and `pkg/redact/testdata/known_structural_exemptions.txt`). The detector-focused boundaries recorded under "Known limitations" below stay in force as well.

**Mutation-channel self-protection**

1. **Base64 and other encoded commands.** The guard matches the literal command shape. It does not decode the command before matching, so command text a shell decodes at run time (base64, hex, or any other encoding) is not covered.
2. **Indirect execution through a script file.** The guard sees the argument text, not the file's contents, so a command that lives inside a script the tool call merely names is not covered.
3. **Multi-step assembly.** A command assembled across separate tool calls has no single candidate carrying the full command shape. A command split across several leaves of one tool call is likewise not covered on the streaming path, which joins only that path's raw fragments; the buffered path additionally tries no-separator and single-space joins of a call's nested leaves, but that is a heuristic for the common split shapes, not a closure.
4. **Arguments outside the OpenAI `arguments` string field.** The guard scopes on a JSON Pointer whose last segment is exactly `arguments`. An Anthropic-shaped `input` object, which has a different field name and shape, is not scanned on either path.
5. **Interleaved streams and absent terminators.** On SSE, a tool call whose arguments path is interleaved with another path's events can be judged clean early. A stream that ends without a terminator while an arguments path is still active is refused (fail-closed).
6. **Unenumerated wrappers and write mechanisms.** The pattern set deliberately does not enumerate every shell wrapper or interpreter (for example `ssh`, `xargs` or `expect`), nor every write mechanism (for example an editor save, a custom program or an unlisted CLI). For the data directory, only the documented path spellings are covered; an indirect spelling such as a symlink or a bind mount is not.
7. **Unparseable response bodies.** If a response body cannot be walked, the guard does not run on it (see the response-path policy below).
8. **A conservative false positive.** When nested leaves of one tool call join into a command shape by coincidence, the call is refused. The direction is fail-closed, per tool call and not a response-wide block, so the cost is accepted.

**Outbound re-check (encodings)**

9. **Coverage is a fixed decoder enumeration, not a grammar.** Each covered form is one entry in the decoder set of `NormalizeCandidates`; the classes deliberately **not** covered include arbitrary multi-layer custom or non-standard encodings, nesting deeper than `NormalizeMaxRounds` (4), inputs larger than `NormalizeMaxInputBytes` (256 KiB, which are not scanned at all), `od -tu1` output produced without `-v` (where a run of sixteen identical bytes collapses to `*`), a payload that straddles a candidate window above `NormalizeMaxCandidateBytes` (8192), password-protected or encrypted containers, steganographic or lossy transforms, and splits the extractor cannot bound.
10. **Body-size bound.** The outbound re-check is skipped for a body larger than `egressRecheckMaxBodyBytes` (128 KiB). A body above that bound still egresses, without a re-check; this is a documented boundary, never a pass.
11. **Non-JSON request bodies.** A request that is explicitly non-JSON keeps the documented byte-for-byte passthrough and runs no walk, so the outbound re-check does not run for it.

**Key-position scanning**

12. **`high_entropy`'s pure-hex exclusion also applies in the key domain.** A secret that is pure hex and placed in an object key is not blocked, the same exclusion as in the value domain.

**Failure policy and accepted cost**

13. **The response and SSE path is deliberately not fail-closed.** An unparseable response body is forwarded byte for byte and backfill still runs; the skip is counted (`Pipeline.ResponseWalkFailures()`) and reported as a metadata-only event, but it is not blocked.
14. **An over-cap legal tool call is refused.** When a streamed tool call's arguments reach `SSEGuardCap` (64 KiB) without a decision, the tool call is refused fail-closed and counted (`stream_guard_fail_closed`). This is an accepted cost, never a pass.

**Detector precision exemptions**

15. **The `high_entropy` structural exemptions are skips, not verdicts.** A secret that fits one of the exempted grammars (provider ids `call_…`, `toolu_…`, `chatcmpl-…`, `msg_…`, `resp_…`; a data-URI base64 payload; a base64-alphabet run of 256 bytes or more; a hash-addressed absolute path) is not redacted. If the engine already knows the secret, the outbound re-check still refuses the request (403, zero upstream bytes; `StructuralIdentifierContains`, which covers every exemption class); an **unknown** secret in that shape is the recorded residual risk. The grammars are enumerated in `KnownStructuralIdentifierExemptions()`. `high_entropy`'s pure-hex exclusion is unchanged (item 12).

## ⚠️ Known limitations

Stated plainly, so nothing here reads as a closed guarantee. The honest register throughout is **high-confidence interception**.

- **`high_entropy`'s pure-hex exclusion also applies in the key domain.** The detector already declines to flag a run made only of hex characters (to avoid false positives on hashes and IDs). The same exclusion applies at object-key positions, so a secret that is pure hex and placed in an object key is **not** blocked. This is the same exclusion as in the value domain, not a new gap; it is pinned by `TestPipelinePureHexKeysNotBlocked`.
- **`high_entropy`'s structural exemptions are documented skips.** Well-formed provider ids (`call_…`, `toolu_…`, `chatcmpl-…`, `msg_…`, `resp_…`), data-URI base64 payloads, base64-alphabet runs of 256 bytes or more and hash-addressed absolute paths are not treated as secrets at either position. A secret the engine already knows inside such a run is still refused by the outbound re-check (`StructuralIdentifierContains`, 403, zero upstream bytes, pinned by `TestHighEntropyStructuralExemptionEgressBypassBlocked`); a secret the engine does **not** already know in that shape is the recorded residual risk. The grammars are enumerated in `KnownStructuralIdentifierExemptions()` and mirrored in `pkg/redact/testdata/known_structural_exemptions.txt`. No coverage guarantee is claimed.
- **Encoded-form coverage is a fixed decoder enumeration, not a closure.** Secrets transformed by an encoding (hex, base64, gzip, …) before they leave are a known area of residual risk. The forms that are covered, and the classes known **not** to be covered, are published as `KnownUncoveredEncodings()` in `pkg/redact` and mirrored in `pkg/redact/testdata/known_uncovered_encodings.txt`; the aggregate list under "Known limits and uncovered classes" above enumerates the classes. No coverage guarantee is claimed.
- **Response/SSE observability is metadata-only.** The response-path walk-failure counter and its events carry metadata only (direction, phase, action; no body, keys or paths) by design, and an unparseable response body is deliberately not blocked (see "Failure policy, per path").

## 🔑 Key handling

- **V1: passthrough.** Tools carry their own provider keys; the gateway only forwards and **does not store** them.
- When multi-account/routing (Pro) needs to store keys, it goes through the cross-platform keyring abstraction (macOS Keychain / Windows Credential Manager / Linux Secret Service plus a fallback chain, a design recorded in the private Pro repository), and adds a gateway token + Origin validation to prevent CSRF.
- **Honest degradation**: without an OS keyring, storage falls back to a restricted file (`0600`), reported **explicitly** through the secret store's `Backend()`, never silently.

## 📦 Release and supply chain

- **Dependency audit**: the core allows permissive licenses only (MIT/Apache/BSD); **GPL/AGPL are forbidden**.
- **Release**: signed builds + checksums + SBOM; CI scans dependencies and secrets.
- **Updates**: Homebrew / Scoop / signed `install.sh` and `install.ps1` distribution.

## 🔁 Network egress

Vendor-bound requests are limited to two switchable, command-scoped categories — **update check** and **rule sync**. Neither runs on its own and neither is performed by the gateway's data plane. Each category's status is reported truthfully: `active` only after it is really in effect.

| Category | Command | Status |
|---|---|---|
| Rule sync | `tokenhush rules sync` | **Active** — fetches the signed rule manifest and bundle from `updates.tokenhush.com` |
| Update check | `tokenhush update` (self-managed install) | **Active** — fetches the root-signed key-list and the signed update manifest over HTTPS when you run `tokenhush update` (or `--check`) |

Both disclose what the server can observe (source IP, timestamp, and Cloudflare access logs) and its retention period, and both can be switched off: set `TOKENHUSH_NO_RULE_SYNC=1` to make `rules sync` refuse without any network request, and set `TOKENHUSH_NO_UPDATE_CHECK=1` to make `tokenhush update` return before any network request. The disclosure is generated from the machine-readable [`egress.yaml`](../egress.yaml) manifest, printed by `tokenhush privacy`, and published at [generated/network-egress.md](generated/network-egress.md). The scope is locked by `TestNoTelemetry` in `pkg/proxy`, which proves the data plane never dials a vendor host even for vendor-looking paths.

## 🛡️ Vulnerability disclosure

> [!CAUTION]
> **Do not open a public issue** for a vulnerability. Follow the disclosure process in [SECURITY.md](../SECURITY.md) (supported versions, private reporting, and response times). Details are published only after a fix has been released.
