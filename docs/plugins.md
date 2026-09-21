# tokenhush plugins

**English** | [中文](plugins.zh-CN.md)

tokenhush has exactly one extension point: the `Rule` interface in
`pkg/filter`. A detector is not a special kind of object — the six built-in
detectors, the rules in a signed remote pack, and rules a third party compiles
in from its own package all implement the same contract and arrive through the
same public registry.

- [The contract](#the-contract)
- [Detector options](#detector-options)
- [The `sensitive_keys` block](#the-sensitive_keys-block)
- [Compiling a rule in from your own package](#compiling-a-rule-in-from-your-own-package)
- [What the core does and does not offer](#what-the-core-does-and-does-not-offer)
- [The response-phase restriction](#the-response-phase-restriction)
- [Remote packs and the floor](#remote-packs-and-the-floor)

## The contract

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

A rule inspects one leaf value — a string inside the request or response body —
and returns the byte spans it considers sensitive. That is the whole job. The
core stamps the finding's rule id, action and provenance origin; a rule cannot
spoof another rule or its own origin, and it cannot substitute anything itself.

The registry is the one entry point:

```go
reg := filter.NewRegistry()
err := reg.Register(myRule, myOtherRule)        // OriginPlugin
err = reg.RegisterBuiltin(builtinRules...)      // OriginBuiltin
err = reg.RegisterCompiled(compiledDocument)    // OriginRemotePack
```

`Register` is the third-party path. The whole batch is validated before
anything is stored, so a rejected registration leaves the registry exactly as
it was. Duplicate ids, invalid ids or metadata, and a response-capable `redact`
rule are rejected with a typed error naming the rule. Registration is expected
before evaluation starts; a constructed registry is read-only afterwards and
`Evaluate` keeps no state, so concurrent evaluations are safe.

Evaluation order is deterministic and identical for every origin: ascending
`Priority`, ties broken by `ID`. A rule that panics, times out, exceeds its span
budget (`MaxRuleSpans`) or returns malformed metadata or spans fails closed with
a labelled `*RuleFailure` carrying one of the five reasons
(`budget`, `timeout`, `error`, `panic`, `malformed`) — never a partial result
and never a crash.

Primitive-typed built-ins are additionally budget-bounded: `prefix`, `email`,
`luhn`, `jwt`, `pem` and `entropy` inspect at most a per-primitive byte budget
of one leaf. `internal/cli` aligns that per-leaf, per-detector budget with
`scan_budget_bytes`; `filter.CompileWithBudget`, `filter.BuiltinDetectorsBudget`
and the `New*RuleBudget` constructors set it explicitly, and
`Compiled.Budget()` reports the effective value. A request leaf past the budget
is reported on stderr (metadata only), never silently skipped.

## Detector options

A compiled document's rule may carry an `options` object beside its `type`. It
is a typed sub-object per parameterizable detector, never a free-form map:
strict decode rejects an unknown option key by name with a typed error, and the
same validation runs again at compile time, so a hand-built document cannot
bypass it.

The only detector option today is `email`:

| Key | Type | Meaning |
|---|---|---|
| `email.suffixes` | list of strings | Additive: each entry extends the built-in public-suffix set. Entries are canonicalized (trimmed, lowercased, one leading dot) and the list is capped at 256 entries. |
| `email.replace` | boolean | Swaps the built-in public-suffix set out for the declared `suffixes`. Permitted only for a non-remote local document; a remote pack that sets it is refused by the floor. |

Additive `email.suffixes` can only extend the built-in set, so a signed pack
may add a suffix it needs but can never remove or narrow a built-in one. The
built-in suffix table itself is compiled in and frozen.

## The `sensitive_keys` block

A compiled document may carry one document-level `sensitive_keys` block beside
its `rules`. It is a strict sub-object, not a rule type:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `keys` | list of strings | none (required) | The object member key names whose values are redacted. At least one key, at most `MaxSensitiveKeys` (256) keys, each key at most 256 bytes (`MaxLiteralBytes`); an empty key is rejected. |
| `case_sensitive` | boolean | `false` | When false (the default) ASCII case is folded; when true the member key must match byte-for-byte. |

An unknown sub-key is rejected by name as `sensitive_keys.<name>`, and the same
validation runs on the decode path and the compile path, so a hand-built
document cannot skip a bound. The block carries no `action` field: its effect is
a fixed request-phase `redact`.

Matching is by the leaf's **immediate object member key, at any object depth**,
so `{"password":"hunter2"}` and `{"credentials":{"password":"hunter2"}}` both
match `password`, while a numeric key never matches an array element. A matching
leaf is redacted whole as one finding — no inner substitution is minted, so no
orphan placeholder can exist — but a rule that would `Block` the leaf is still
evaluated and keeps Block precedence, and the global and per-rule allowlists
still suppress the finding.

Two shapes stay unmatched and are the recorded residual (see `security.md` R2):
a sensitive key whose value is a container rather than a string member
(`{"password":{"secret":"x"}}`), and the k8s/docker-env sibling shape
(`{"name":"DB_PASSWORD","value":"…"}`). A secret placed in a JSON object key
itself is still not caught.

### The signed-pack projection slot

A signed pack carries the same block as an optional field of its rules payload.
`SensitiveKeys` is declared **immediately after `blocklist` and before `rules`**;
declaration order defines the projection bytes, so the Pro signing backend must
use the same slot. The field is a pointer with `omitempty`, which is
load-bearing: `encoding/json` does not omit a zero struct value, so a
non-pointer field would add the key to every existing preimage and invalidate
every existing signature. A pack without the block marshals byte-identically to
today, and there is **no `schema_version` bump**. The operational consequence is
recorded: an older client whose strict decoder uses `DisallowUnknownFields`
rejects a pack carrying the block and falls back to the built-in detectors, so
the backend must emit the block only to clients that support it.

## Compiling a rule in from your own package

A plugin is an ordinary Go package. It imports `pkg/filter`, implements the
contract, and registers its rules at assembly time:

```go
package myrules

import (
	"bytes"

	"github.com/fregie/tokenhush/pkg/filter"
)

type TicketRule struct{}

func (TicketRule) ID() string            { return "ticket" }
func (TicketRule) Type() string          { return filter.TypePrefix }
func (TicketRule) Category() string      { return filter.CategoryCustom }
func (TicketRule) Scope() filter.Scope   { return filter.ScopeRequest }
func (TicketRule) Action() filter.Action { return filter.ActionRedact }
func (TicketRule) Priority() int         { return 10 }
func (TicketRule) Confidence() float64   { return 0.95 }

func (TicketRule) Inspect(leaf []byte) []filter.Span {
	at := bytes.Index(leaf, []byte("TICKET-"))
	if at < 0 {
		return nil
	}
	return []filter.Span{{Start: at, End: at + 7}}
}
```

Then register and evaluate it:

```go
reg := filter.NewRegistry()
if err := reg.Register(TicketRule{}); err != nil {
	return err
}
findings, err := reg.Evaluate(leaves, filter.ScopeRequest)
```

`findings` are core-stamped `AttributedFinding` values, so a caller can always
tell which rule, category and origin produced a span. The same registry
evaluates built-ins, remote-pack rules and plugin rules side by side, in one
deterministic order.

`pkg/filter` ships the acceptance test for this path:
`pkg/filter/external_plugin_test.go` defines a rule in an external test package,
registers it through the public API and evaluates it alongside a rule that
arrived as a compiled document.

## What the core does and does not offer

| Offered | Not offered |
|---|---|
| One `Rule` interface and one public registry | Capability tiers, gates or phases beyond `Scope` |
| Three origins stamped by the core (builtin, remote pack, plugin) | A capability gate on registration or a plugin permission model |
| Deterministic ordering (ascending `Priority`, ties by `ID`) | A failure-policy negotiation — every failure fails closed |
| Fail-closed labelled failures with one metadata-only audit record each | A plugin-configurable timeout or budget |
| Registration-time validation of the whole batch | Runtime plugin loading |

**There is no runtime plugin loading.** Rules are compile-time only (D12): no
WASM, no `.so` shared objects, no subprocess plugins, no scripting layer. A
plugin is Go code compiled into the binary that imports it, which is what makes
the contract auditable and the failure model simple.

## The response-phase restriction

On the response path rules may only `Block` or `Warn`. `Redact` is request-path
only, because substitution needs the session's placeholder writer, and the
response path must never reach it. The restriction is enforced on both arrival
paths:

- a compiled document whose rule has `scope` `response` or `both` with action
  `redact` is rejected at compile time;
- a directly-registered `Rule` with the same combination is rejected at
  registration with a typed error.

The restriction is applied at registration rather than being left to the
operator, so a plugin cannot widen its own authority by declaring a scope it was
never meant to have.

## Remote packs and the floor

A signed remote pack is not a different extension mechanism: its rules enter
through `RegisterCompiled` and evaluate in the same order as everything else.
Two constraints apply to remote packs specifically:

- **The non-weakening floor.** A pack may add detections and tighten
  sensitivity, but the floor rejects exactly four things: a pack that disables a
  baseline detector, a pack that drops a required category, a rule carrying an
  `allow` action, and a rule that sets the email `replace` flag (which would
  narrow the built-in suffix set). Additive `email.suffixes` extend the built-in
  set and remain allowed, and a pack's additive `sensitive_keys` block is
  likewise not rejected by the floor. The floor is allowlist-neutral (OD-3): it
  does not inspect global or per-rule allowlists, because a stricter floor would
  reject real signed packs and drop the client to the built-ins.
- **The trust root.** A pack is only compiled after signature verification
  against the embedded rule trust root (`rules-2026-09`). A local operator
  document and a signed remote pack share the same strict decoder and compiler;
  only the remote path is subject to the floor.

See [security.md](security.md) for the invariants the registry enforces and the
residual risks that come with the allowlist-neutral floor, and
[architecture.md](architecture.md) for where `pkg/filter` sits in the layered
graph.
