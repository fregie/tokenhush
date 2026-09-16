# Security Model

**English** | [中文](security.zh-CN.md)

> Status: V1 is implemented (2026-09). The hard invariants are locked by named tests in `pkg/*`, and are restated under Hard invariants below and in `architecture.md`.

Tokenhush is itself a security tool, so **it must be secure first**. This document defines the threat model and the invariants that cannot be broken.

## 🛡️ Threat model

| Threat | Description | Mitigation |
|---|---|---|
| **Prompt injection to exfiltration** | An attacker tricks the model into emitting a placeholder; if the gateway backfills on the outbound direction, the secret leaks | **Hard invariant: never backfill outbound** (see Hard invariants) |
| **Local malicious process/web page reaches the gateway** | Any local process or browser page can `fetch` `127.0.0.1:8787` | Loopback-only bind (`127.0.0.1`, plus `[::1]` when the host has an IPv6 loopback); `Host` header validation; the control plane additionally requires a bearer token generated per `run`, stored `0600` on disk, and same-origin validation for requests carrying `Origin`; the runtime allowlist can be changed only through that authenticated control plane, and every change writes one metadata-only audit row |
| **DNS rebinding** | A malicious domain resolves to 127.0.0.1 to bypass same-origin | `Host`/`Origin` header validation |
| **Placeholder collision** | Two secrets map to the same placeholder, causing a wrong backfill | HMAC-deterministic mapping + high-entropy suffix |
| **Plaintext read from memory** | Debug or dump by another process under the same user | Sandbox/hardened runtime; no plaintext written to disk |
| **Supply-chain attack** | A dependency is poisoned (see the LiteLLM incident) | Minimal dependencies + pinned versions + signed releases + SBOM |

- **Prompt injection, concretely.** A poisoned file tells the model to print `__PII_email_3f9a2b__`. If the model echoes it and the gateway backfilled outbound, the real email would go upstream. Invariant 1 blocks that: backfill only runs toward the client.
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
> Invariant 1 is why prompt injection cannot turn the gateway into an exfiltration path: placeholders are only ever replaced on the way back to the client.

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

Object keys are **not** `Leaf`s and never enter the document model defined by `pkg/extension`. The key scan is a separate, additive API (`protocol.WalkKeys`, added without changing `Walk` or `Leaf`), so the "leaf = value" contract documented in `architecture.md` is **unchanged**.

**Decision record.** Adding a separate `WalkKeys` API, instead of extending `protocol.Walk`'s `Leaf` contract with key positions, is a deliberate decision (the O3 decision in the hardening plan). Extending `Leaf` was rejected because it would change `pkg/extension`'s V1-stable public surface and break the "leaf = value" contract (`architecture.md`). The key-position mechanism is pinned by `pkg/protocol` tests and by `pkg/proxy`'s key tests; the cross-repo assembly contract for the surrounding hardening work is frozen in the private Pro repository's ADR-0012 amendment A2.

## ⚠️ Known limitations

Stated plainly, so nothing here reads as a closed guarantee. The honest register throughout is **high-confidence interception**.

- **`high_entropy`'s pure-hex exclusion also applies in the key domain.** The detector already declines to flag a run made only of hex characters (to avoid false positives on hashes and IDs). The same exclusion applies at object-key positions, so a secret that is pure hex and placed in an object key is **not** blocked. This is the same exclusion as in the value domain, not a new gap; it is pinned by `TestPipelinePureHexKeysNotBlocked`.
- **Encoded-form coverage is not established (placeholder).** Secrets transformed by an encoding (hex, base64, gzip, …) before they leave are a known area of residual risk, and the explicit list of encoding classes that are known **not** to be covered is not published yet.
  <!-- W1.5 placeholder: the encoder-normalization work (W2.2) supplies the known-uncovered encoding-class list here; do not state a coverage guarantee before then. -->
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
