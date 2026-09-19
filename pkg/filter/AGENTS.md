# pkg/filter KNOWLEDGE BASE

## OVERVIEW
The one extension point: rule document schema, compiler, evaluator, registry, action policy, and the six built-in detector algorithms.

## WHERE TO LOOK
| Task | File |
|---|---|
| Add/change a built-in detector | `primitive_<name>.go`; register in `builtinTable` (`builtin.go`) and `primitiveBuilders` (`primitive_builders.go`) |
| Rule/bundle document schema, bounds, sentinels | `schema.go` |
| Typed per-rule options decode/validate | `options_schema.go`, `options.go` |
| Email suffix grammar/table | `email_suffixes.go` |
| Compile gate, per-type field rules, direction contract | `compile.go` |
| Registration, ordering, fail-closed guard, `MaxRuleSpans` | `registry.go` |
| Findings, allowlist/blocklist, span matching | `evaluate.go` |
| Action precedence, `Decision`, refusal audit | `policy.go` |
| Non-weakening floor for remote packs | `floor.go` |
| v1 wire compat, command signal | `compat_v1.go` |
| Primitive byte budget default | `primitive_prefix.go` (`PrimitiveByteBudgetBytes`) |

## KEY CONTRACTS
- **Frozen `Rule` interface, exactly 8 methods:** `ID() string`, `Type() string`, `Category() string`, `Scope() Scope`, `Action() Action`, `Priority() int`, `Confidence() float64`, `Inspect(leaf []byte) []Span`. Pinned by `internal/guards/shape_guard_test.go` and `external_plugin_test.go`; never change the set or add a second exported interface.
- **Registration paths** (`registry.go`): `Register` -> `OriginPlugin`, `RegisterBuiltin` -> `OriginBuiltin`, `RegisterCompiled` -> `OriginRemotePack`. Whole batch validated (id grammar/uniqueness, scope/action enum, confidence, direction contract) before any mutation, so a rejected batch leaves the registry untouched.
- **Deterministic order:** ascending `Priority`, ties by `ID`; identical for compiled documents and registered rules. Findings sorted by (leaf, start, end), stable so exact-span ties keep invocation order.
- **Fail closed:** a rule that panics, times out, errors, exceeds `MaxRuleSpans` (= `MaxMatches` = 4096), or returns malformed spans yields `*RuleFailure{RuleID, Origin, Reason}`; reasons `ReasonBudget`, `ReasonTimeout`, `ReasonError`, `ReasonPanic`, `ReasonMalformed`. `errors.Is(err, ErrRuleFailure)`. `DefaultRuleTimeout = 30s`. `Policy.Decide` turns a failure into `Decision{Action: ActionBlock, Refusal: ...}` plus one metadata-only audit record.
- **Budget-bounded primitives:** `PrimitiveByteBudgetBytes = 1<<20` default; `internal/cli` aligns the budget with `scan_budget_bytes` via `CompileWithBudget`/`BuiltinDetectorsBudget`/`New*RuleBudget`. `primitiveInput` truncates each leaf, so cost is O(budget).
- **Typed strict `options`:** only `email` today. `RuleOptions{Email *EmailOptions}`, `EmailOptions{Suffixes []string, Replace bool}`. Unknown keys rejected by name (`strictDecodeRuleOptions`); a sub-object on a non-matching type is `ErrInvalidValue` (`validateRuleOptions`); `MaxEmailSuffixes = 256`; suffixes canonicalized in place. Additive `suffixes` extend the built-in table; `replace` swaps it out and is refused for remote packs by the floor.
- **v1 compat:** `CommandSignal{RuleIDs, Count}` + `Present()`; `DecodeDocumentWithSignal(data)` returns `(*Document, *CommandSignal, error)`. A command rule decodes, is marked `ExcludedFromEvaluation`, is signalled, and is never dropped or treated as an error.

## DETECTORS: detector id / rule type -> category
| Detector id | `Type()` | `Category()` |
|---|---|---|
| `prefix` | `prefix` | `api_key` |
| `email` | `email` | `email` |
| `luhn` | `luhn` | `credit_card` |
| `jwt` | `jwt` | `jwt` |
| `private_key` | `pem` | `private_key` |
| `high_entropy` | `entropy` | `high_entropy` |

Frozen table order in `builtin.go`; `entropy` is off by default (`BuiltinConfig.HighEntropy` opt-in only). Detector ids differ from type ids for `private_key`/`pem` and `high_entropy`/`entropy`. `DefaultFloorBaseline` keeps all six detectors and categories regardless of the default enabled set. Action precedence: `allow < warn < redact < block`; response-phase redact is rejected at compile and registration.

## CONVENTIONS
- Frozen exported surface: `Rule`, the wire consts, sentinels, and constructor names are pinned; extend by adding a sub-object field to `RuleOptions` (schema_version bump), never a free-form map.
- No decode/normalize before `Inspect`: detectors read raw leaf bytes; spans are byte offsets only, never content.
- `pkg/filter` and `pkg/redact` are siblings; neither imports the other.
- 250-pure-LOC ceiling forces splits: `options_schema.go` and `primitive_builders.go` carry helpers relocated out of `schema.go`/`compile.go`.

## GOTCHAS
- `shape_guard_test.go` pins the 8 methods and frozen consts; `invariants_test.go` (`TestInvariant5FailSafe`) pins the 5 reasons and one-audit-record rule; `external_plugin_test.go` pins the exported plugin API. Do not relax any of them.
- A command rule never enters the compiled set, but its id stays reachable via `Compiled.Commands()`.
- The floor is allowlist-neutral by design and checks remote packs only; local `detectors:` switches are out of scope.
