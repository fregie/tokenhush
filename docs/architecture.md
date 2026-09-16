# Architecture

**English** | [中文](architecture.zh-CN.md)

> Status: V1 is implemented; the current release line is `v0.4.0` (2026-09). This document describes the shipped core architecture and the open-core boundary.

Tokenhush is a local base-URL gateway between your AI coding tool and the model provider. Before a request leaves the machine, it finds sensitive content and replaces it.

## 🎯 Goals and non-goals

**Goals**

- Detect and redact sensitive content (keys, `.env` values, PII) before a request leaves the machine.
- Onboard tools that accept a `*_BASE_URL` or custom endpoint with almost no setup.
- Run **cross-platform** on Windows, Linux, and macOS.
- Process requests locally: **sensitive values are redacted on the device before a request goes out**.

**Non-goals (explicitly out of scope for V1)**

- System-level MITM / root certificate installation.
- Covering Cursor agent traffic, ChatGPT/Claude desktop apps, or browser web UIs.
- Team collaboration, cloud, or SSO.
- System-level interception on all three platforms; system extensions and MITM stay macOS-first, a decision recorded in the private Pro repository.
- NER or a local small model for semantic detection.

## 🔁 Data flow

```mermaid
flowchart LR
  Tool["AI coding tool<br/>Claude Code, Codex, Aider, Cline, ..."]
  Up["Model provider<br/>Anthropic, OpenAI, ..."]

  subgraph GW["tokenhush local gateway"]
    direction TB
    S1["1. Parse JSON leaves"]
    S2["2. Detect sensitive data"]
    S3["3. Replace with placeholders outbound"]
    S4["4. Forward upstream"]
    S5["5. Stream backfill inbound"]
    S1 --> S2 --> S3 --> S4 --> S5
  end

  Tool -- "HTTP, localhost, plaintext" --> GW
  GW -- "HTTPS" --> Up
  Up -- "HTTPS response" --> GW
  GW -- "HTTP response, backfilled" --> Tool
```

**Key insight**: the sensitive direction is the **request**, and requests are **non-streaming**. The tool sends the whole JSON body in one piece, so the gateway can redact it completely before forwarding, with no streaming-rewrite problem. Responses usually carry only placeholders, so backfill is a bounded "placeholder to original" swap.

> [!NOTE]
> Outbound requests are read in full before redaction. Only the inbound response path needs incremental handling, and it only ever rewrites placeholders back to originals.

## 🏗️ Components

| Package | Responsibility |
|---|---|
| `pkg/proxy` | Local HTTP reverse proxy: listener, upstream routing, SSE passthrough, lifecycle |
| `pkg/gateway` | Shared request-path assembly (listener lifecycle, control token/`run.json`, middleware chain, data plane); see `extension-api.md` |
| `pkg/redact` | Detectors (deterministic rules) + placeholder generation/mapping + backfill |
| `pkg/protocol` | Protocol-agnostic JSON leaf walk; incremental SSE parsing; recursive handling of double-encoded JSON in tool calls |
| `pkg/config` | Configuration loading and defaults (`tokenhush.yaml`) |
| `pkg/platform` | Cross-platform abstraction: paths, keyring, service. Exported for reuse by the private Pro repository |
| `pkg/extension` | Content plugin interfaces (Inspector / Transformer / Registry) plus cross-layer extension points (see `extension-api.md`, `plugins.md`) |
| `pkg/license` | Read-only Pro license validation and display (isolated, fuzz-tested) |
| `cmd/tokenhush` | Free CLI: `run` (foreground gateway), `status`, `env` (print setup snippets), `doctor`, `version`, plus the control-plane API |

## 🏗️ Key design decisions

### Protocol-agnostic leaf walk (no API normalization)

A "leaf" is a string value buried inside the request JSON. Take this body:

```json
{"messages": [{"content": "my key is sk-abc123"}]}
```

The gateway walks the JSON tree and runs detect/replace on `"my key is sk-abc123"`. It does not translate Anthropic, OpenAI, or Responses into one internal shape, because that shape would rot as APIs change. Double-encoded JSON inside tool calls is handled recursively, and SSE is parsed incrementally at the leaf level.

**Object keys are outside this model.** A JSON object's member names are inspected by a separate, additive API (`protocol.WalkKeys`, a key-span scanner), and they are **not** `Leaf`s: they never enter the `extension.Document` model. `Walk` and `Leaf` are unchanged, so the "leaf = value" contract above still holds. See `security.md` for the key-position detector set and the failure policy.

### Placeholders and backfill

A **placeholder** is the fake string that replaces a real secret on the way out. Format: JSON-safe, tokenizer-friendly, high-entropy, for example `__PII_email_3f9a2b__`.

- **Mapping**: the same secret maps **HMAC-deterministically** to the same placeholder. HMAC is a keyed hash: same input, same output. Two secrets cannot collide onto one placeholder and "backfill the wrong secret".
- **Storage**: **in-memory and session-scoped only**. A restart forgets the mapping, so a failed backfill shows the user a placeholder. That is **safe degradation, not a leak**.
- **Hard invariant**: backfill happens only toward the **client**. Never backfill outbound.

### Streaming

- **Outbound**: the full body is read, then redacted. There is no streaming-rewrite problem on this side. A request that arrives with a non-identity `Content-Encoding` is rejected with **415** in `Forwarder.ServeHTTP` before the body is read and before the upstream is dialed, so a client-compressed body can never skip redaction (see `security.md`, invariant 8). A request body that declares JSON but that the leaf walker cannot parse is likewise rejected with **400** before the upstream is dialed (see `security.md`).
- **Inbound, non-SSE**: the body is buffered whole and backfilled as one unit. A `gzip`/`deflate` `Content-Encoding` is decompressed before any status code is committed; an encoding the core cannot decode (`br`, `zstd`, ...) or a decode failure is answered **502**, never passed through.
- **Inbound, SSE (`text/event-stream`)**: a placeholder can arrive split across several `data:` events, each a partial JSON delta. A raw sliding window over the byte stream cannot match it, because the placeholder is not contiguous (`__PII_ema` in one event, `il_3f9a2b__` in the next) and the intervening SSE/JSON framing changes the bytes. The response instead streams through an **SSE-aware backfiller** (`pkg/proxy/ssebackfill.go`):
  - Every single-line `data:` payload's terminal string leaves are fed into a **per-path window** (a `BackfillWriter` sized to the longest placeholder), so one JSON leaf path accumulates across events and across framing.
  - When a path's window empties at an event boundary the path is **decided**. If a replacement happened, the last contributing event is rewritten to the merged content and every earlier contributor to an empty string, so client-side delta concatenation yields the restored value exactly once. If nothing changed, every event keeps its original bytes.
  - The rewrite is **in place** on the record's `data:` span, so SSE framing, event count, and all non-delta fields (`event:`, `id:`, `retry:`, comments, multi-line or colon-less `data:`) are preserved byte for byte. Records are never rebuilt from parsed fields, so the cross-record `id:` (last-event-id) stays correct.
  - **Delivery stays incremental**: an event whose content is already decided is emitted within the same `Write`, and only events that contribute to a still-open path are held, so the client sees each event promptly instead of waiting for EOF (`TestPipelineSSEIncrementalDeliveryBeforeEOF`).
  - **Memory is bounded**: held bytes are capped by `sseBackfillMaxHoldbackBytes` (256 KiB). Past the cap the oldest windows are flushed as literal text and their events released, so a pathological stream cannot grow the buffer without bound (`TestSSEBackfillerHoldbackBoundEnforcedFromConstant`).

### Detector strategy (V1)

Deterministic rules with **high precision first**: known key prefixes (`sk-`, `AKIA`, `ghp_`, ...), high-entropy strings, JWT, private-key headers, Luhn card-number checksums, and email addresses. An allowlist and one-click release are provided. The wording stays honest: **"high-confidence secret interception"**, never "never leaks".

## 📄 Open-core boundary

The public core (this repository, Apache-2.0) is **fully usable for a single user**: proxy, redaction, the CLI, and the extension-point interfaces.

The private Pro repository builds paid binaries by importing this repository's Go module. It provides:

- System extension / MITM power mode (on the closed-source macOS app side)
- Multi-provider / multi-account routing
- Cost tracking
- Team export / SSO
- Dashboard / menu bar UI

> [!IMPORTANT]
> Pro code and algorithms **never enter this repository**, and this repository contains no `if license { ... }` paid implementation branches. The full distribution and open-core policy lives in the private Pro repository.

## 🎯 Capability ladder

| Stage | Capability | Channel |
|---|---|---|
| V1 | base-URL gateway: content-level redaction | Open-source core + free CLI |
| V2 | System-extension metadata mode: domain/process-level interception (**no CA**) | Pro (direct download) |
| V3 | Transparent proxy + local CA: content-level redaction covering Cursor/browser/desktop apps | Pro (explicit opt-in) |

> [!WARNING]
> V2 and V3 depend on the macOS Network Extension system extension (Developer ID signing + user approval + Apple capability approval) and are **not implemented in this repository**.
