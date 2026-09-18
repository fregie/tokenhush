# tokenhush architecture

tokenhush v0.5.0 is a from-scratch rewrite of the tokenhush core. It keeps the
security invariants and the supply-chain wire format, and it drops everything
the evidence showed to be vestigial or duplicated. This document is the
architectural map: the layered dependency graph, the single rule abstraction,
the frozen supply-chain byte surfaces, and the CLI that assembles all of it.

- [The four goals of the rewrite](#the-four-goals-of-the-rewrite)
- [The layered dependency graph](#the-layered-dependency-graph)
- [The single rule abstraction](#the-single-rule-abstraction)
- [The data path at a glance](#the-data-path-at-a-glance)
- [The two signing-input projections](#the-two-signing-input-projections)
- [Frozen byte surfaces](#frozen-byte-surfaces)
- [The seven-command CLI](#the-seven-command-cli)

## The four goals of the rewrite

1. **Much lighter.** Keep only the non-negotiable invariants and the extension
   mechanism. The legacy core was roughly 60,551 lines of Go and concentrated
   its complexity in a handful of subsystems — a change-channel self-protection
   guard, an outbound encoding re-check, a keyring/secret store with one
   consumer, two parallel SSE accumulators, two independent copies of the
   signing machinery. None of them is created here.
2. **One minimal, highly extensible filtering/replacement framework.** A single
   rule abstraction, `pkg/filter`'s `Rule`, is *the* extension point. Built-in
   detectors, signed remote packs and third-party rules all enter through the
   same public registry.
3. **The supply chain preserved.** Signed rule sync and signed self-update stay
   byte-compatible with the already-designed backend: the same endpoints, the
   same domain tags, the same embedded key ids, the same document schemas and
   the same floor behaviour.
4. **Lean, clearly layered, highly extensible.** Every package depends only
   downward, and the allowed edges are enforced by a test
   (`internal/layering`, `scripts/check-layering.sh`) rather than by
   convention.

## The layered dependency graph

Dependencies point one way only. Arrows below are "imports"; there is no
cycle, and sibling packages never reach into each other.

```
platform          -> (stdlib only)
audit             -> (stdlib only)
protocol          -> (stdlib only)

redact            -> protocol
filter            -> protocol, audit
config            -> platform

supply            -> stdlib, platform, filter

proxy             -> protocol, redact, filter, audit, config, platform

internal/cli      -> everything (the ONLY assembler)
cmd/tokenhush     -> internal/cli

internal/guards   -> (analysis only; imported by nothing)
internal/layering -> (analysis only; imported by nothing)
internal/layering/cmd -> internal/layering
```

Three properties of this graph are load-bearing:

- **`filter` and `redact` are siblings, not a stack.** `filter` produces
  findings; `redact` performs substitution; neither imports the other, and
  `proxy` orchestrates the two. That split is what makes invariant 1
  structural: the forward-only writer lives in `redact`, and the response path
  never reaches it.
- **`supply -> filter` is intentional.** The rule document schema, the strict
  decoder and the non-weakening floor live in `pkg/filter`, and `pkg/supply`
  invokes them to verify and activate a pack before a single rule runs.
- **`internal/cli` is the sole assembly point.** `pkg/proxy`, `pkg/filter`,
  `pkg/redact` and `pkg/supply` are libraries with injectable seams; only
  `internal/cli` wires them into a running product and owns the command
  surface.

## The single rule abstraction

`pkg/filter` owns the one exported extension contract:

```go
type Rule interface {
	ID() string           // stable wire id; unique across the registry
	Type() string         // regex | keyword | prefix | email | luhn | jwt | pem | entropy
	Category() string     // api_key | email | credit_card | private_key | jwt | high_entropy | custom
	Scope() Scope         // request | response | both
	Action() Action       // allow | warn | redact | block
	Priority() int        // ascending; ties break on ID
	Confidence() float64  // in (0,1]
	Inspect(leaf []byte) []Span
}
```

Every rule — a compiled-in detector, a rule from a signed remote pack, or a
value a third party registers from its own package — arrives through the same
registry and is evaluated by the same evaluator. A rule supplies spans only:
the core stamps the finding's rule id, the action and the provenance origin, so
a rule cannot spoof another rule or its own origin.

The properties a rule author can rely on, and the ones the core refuses:

- **Deterministic order.** Ascending `Priority`, ties broken by `ID`, and
  identical for the compiled-document path and the directly-registered path, so
  a rule cannot evaluate in one order as a document and another as a value.
- **Fail closed, labelled.** A rule that panics, times out, exceeds its span
  budget or returns malformed output produces a labelled refusal carrying one of
  five reasons (`panic`, `timeout`, `budget`, `malformed`, `error`) — never a
  silent pass and never a crash.
- **Registration is a gate.** The whole batch is validated before anything is
  stored, so a rejected registration leaves the registry exactly as it was.
- **No capability tiers, no gates, no phases beyond `Scope`, no failure-policy
  negotiation.** A registered rule is evaluated; there is nothing to negotiate.
- **The direction contract.** On the response path rules may only `Block` or
  `Warn`. `Redact` is request-path only, and a rule whose scope includes the
  response phase while its action is `redact` is rejected both at compile time
  (documents) and at registration (directly-registered values).
- **Budget-bounded primitives.** A primitive-typed rule (`prefix`, `email`,
  `luhn`, `jwt`, `pem`, `entropy`) inspects at most its per-primitive byte
  budget of one leaf. `internal/cli` aligns that budget with
  `scan_budget_bytes` for admitted requests, so detection cost stays O(budget)
  and the budget is never a silent blind spot: a request leaf past the budget
  is reported on stderr (metadata only) and moves no counter.

See [plugins.md](plugins.md) for the third-party example and the full
registration semantics, and [security.md](security.md) for the invariants the
registry enforces.

## The data path at a glance

At runtime the pieces line up like this:

1. **Startup is ordered and never rearranged.** `tokenhush run` performs crash
   recovery of the running binary first, then loads the config, builds the
   pipeline (which reads the rules cache, never the network), binds the
   loopback listener, writes the session files, and only then serves. Nothing
   is written before the bind succeeds.
2. **Every request passes the loopback guard first.** The `Host` header and
   `Origin` are checked before routing, so a non-loopback or cross-origin
   request is refused before it can do anything.
3. **Routing is an explicit table.** Built-in vendor paths resolve to the
   OpenAI-compatible or Anthropic-style upstream; `GET /v1/models` is the one
   route answered locally; a configured `upstreams` entry wins over the table;
   anything else is a typed `unknown_upstream` refusal — near-miss paths are
   never guessed at.
4. **Outbound requests are walked, evaluated and rewritten.** A declared-JSON
   body that cannot be walked is refused with 400; a non-identity
   `Content-Encoding` is refused with 415 before the body is read or any
   upstream dial is opened. The request-phase decision then allows, blocks or
   substitutes. Substitution is **span-exact**: each decoded detection span is
   mapped back to the raw, escaped bytes that spell it, so a multi-line or
   quote-bearing secret leaves as a placeholder and returns intact. The
   redaction log line and the `redactions` counter count only substitutions
   that really changed bytes. Primitive-typed detectors scan at most
   `scan_budget_bytes` of one leaf — the per-primitive budget is aligned with
   the configured scan budget for admitted requests — and a leaf past the
   budget is reported on stderr (metadata only) instead of failing silently.
   Redaction runs once per request over the whole client-supplied conversation,
   so a long session re-scans and re-redacts the same secrets on every turn: the
   `redactions` counter and the stderr log grow with the number of carried
   occurrences, not with the number of distinct secrets; that is metadata-only,
   per-request work, never a persisted body.
5. **Client-bound responses are decoded before any status is committed.**
   Identity-encoded `text/event-stream` bodies stream through the SSE handler
   with a bounded backfill window; everything else is buffered, decoded and
   evaluated. Undecodable content refuses with 502 and discards the upstream
   bytes rather than passing them through uninspected. Backfill runs last, and
   only a placeholder this session minted is restored. Restore is
   **escape/depth-aware**: a restored secret is re-spelled at the enclosing JSON
   depth (exactly the spelling the client sent), so a multi-line or
   quote-bearing secret cannot corrupt the client's JSON. A raw stream fragment
   or a non-JSON body keeps the raw spelling, and a foreign placeholder is
   returned byte-identical.
6. **The control surface is exactly `GET /status`.** It is metadata only, it
   requires the session bearer token, and the data plane and the control surface
   are separate mux patterns.

## The two signing-input projections

The supply chain has two document families, and each signs a **different**
projection. They are never unified: the backend and the pending offline key
ceremony are frozen against the current bytes.

| Family | Signing input |
|---|---|
| Update documents | `domain + "\n" + one key:value line per field`, with **epoch-second** timestamps |
| Rule documents | `domain + "\n" + hex(sha256(json.Marshal(payloadStruct)))` |

For the rule family, all **three** payload struct shapes are frozen — the pack,
the manifest and the revocations document each reproduce the legacy field set,
field order, JSON names, types and `omitempty` tags exactly. The projection is
computed from the raw, undefaulted decoded values, never after applying
defaults such as `scope: request` or `confidence: 0.9`, because a defaulted
field would emit a key absent from an existing document and break its
signature. New fields are `omitempty` and absent from every existing document.

## Frozen byte surfaces

Everything inside `pkg/supply` and `pkg/filter` may be restructured (that is how
the duplicated machinery was unified); the surfaces below may not change.

| Surface | Frozen value |
|---|---|
| Origin and endpoints | `https://updates.tokenhush.com` plus `/v1/update/{manifest,revocations,keylist}` and `/v1/rules/{manifest,bundle,revocations}`, always with `?channel=stable` |
| Domain tags | `tokenhush-update-manifest-v1`, `tokenhush-update-revocations-v1`, `tokenhush-update-keylist-v1`, `tokenhush-rules-manifest-v1`, `tokenhush-rules-pack-v1`, `tokenhush-rules-revocations-v1` |
| Embedded key ids | `root-2026-09` (update trust root) and `rules-2026-09` (rule trust root), public halves only. The online update key (`upd-*`) is fetched through the root-signed key list and is never embedded. |
| The two document size caps | Update documents (`manifest`, `revocations`, `keylist`): **128 KiB**. Rules documents (`manifest`, `bundle`, `revocations`): **256 KiB**. Neither is tightened or raised. |
| Artifact cap | The downloaded binary artifact: **256 MiB** (`MaxArtifactBytes`), fetched by a separate bounded fetcher that must not inherit a document cap. |
| Wire detector and category ids | Detectors `prefix`, `high_entropy`, `jwt`, `private_key`, `luhn`, `email`; categories `api_key`, `high_entropy`, `jwt`, `private_key`, `credit_card`, `email` |
| The floor's behaviour | It rejects exactly three things: a pack that disables a baseline detector, a pack that drops a required category, and a rule carrying an `allow` action. It is allowlist-neutral (OD-3). |
| Cache and anti-rollback layout | `<DataDir>/rules/{active,revoked.json,<serial>/{manifest,bundle}.json,highwater.json}` and `<DataDir>/update/highwater.json`; atomic writes, mode `0600` |
| Session files | `<DataDir>/run.json` (`pid`, `port`, `addrs`, `started_at`; never the token) and `<DataDir>/control.token`; atomic, mode `0600`, removed on clean shutdown |
| Placeholder grammar | `__PII_<type>_<digest>__` |
| Redaction log line | `tokenhush: redacted request <type> (len=<N>) <masked>`, on stderr, never persisted |
| Restore log line | `tokenhush: restored response placeholders=<N>`, on stderr, never persisted |
| Startup banner | listen address, effective upstream routing (configured plus built-in) and the tool base-URL hint, on stderr, never persisted |

## The seven-command CLI

`internal/cli` is the only place where the packages are assembled, and its
command registry holds exactly seven verbs. Adding an eighth is a deliberate
product change, not an accident of wiring.

| Command | What it does |
|---|---|
| `tokenhush run` | Starts the gateway: startup recovery, config load, pipeline build, loopback bind, session files, serve. Flags: `--config`, `--port`, `--log-level`, `--log-redactions`. |
| `tokenhush rules` | `rules sync [--check]` verifies and activates the signed rule pack; `rules rollback` returns to a previously verified serial. `--check` runs every check against a throwaway sandbox and writes no real state. |
| `tokenhush update` | Checks for and applies a signed binary update, honouring the D17 install-source routing (Homebrew and Scoop delegate; only a self-managed install self-replaces). `--check` reports without downloading, installing or writing anything. |
| `tokenhush status` | Reads the session files and asks the running gateway's control surface. `--json` emits the frozen ten-key document. A gateway that is not running prints `not running` and exits 1. |
| `tokenhush env <tool>` | Prints the onboarding snippet for one of the fourteen supported tools, pointing its base URL at the loopback gateway. |
| `tokenhush privacy` | Prints the egress disclosure rendered from `egress.yaml`: exactly two vendor-bound categories, each with its switch, host and retention. `--json` emits the same document as JSON. |
| `tokenhush version` | Prints the OD-1 version line (`v0.5.0`) plus the build target and toolchain. |

Exit codes are frozen because scripts observe them: `0` success, `1` a failed
check or operation, `2` a usage error (unknown command or tool, bad flag
value). The dispatcher's unknown-command message lists the registered commands
in sorted order, so the help can never advertise a command that does not exist.
