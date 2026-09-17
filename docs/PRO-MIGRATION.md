# Pro migration note

This note records the relationship between this rewrite and the private Pro
repository. **The Pro migration is documented here; it is not performed by this
plan.** Pro is explicitly out of scope for the rewrite.

## Status: a hard fork

- The Pro repository keeps building against the **legacy** tree through its
  `tokenhush-pro/go.work` workspace, whose `use ../tokenhush` directive points
  at the legacy checkout. That directive must keep pointing there until Pro has
  migrated.
- This rewrite is a **hard fork**. There is no Pro contract here: no Pro-facing
  gateway assembly contract, no lifecycle hooks, no dependency-injection surface
  for Pro, and no backward-compatibility shim beyond a single deliberate
  exception (below).
- The module path is unchanged (`github.com/fregie/tokenhush`). That is exactly
  why the `use` directive matters: repointing `use ../tokenhush` at this tree
  would make Pro compile against a different API under the same import paths,
  without a single migration decision being made.
- **Pro needs a separate migration plan after this rewrite lands.** Nothing in
  this repository is designed to be adopted incrementally by pinning a version
  string; the migration is a deliberate port with its own review.

## The single compatibility exception

`pkg/filter` still decodes **schema-v1 rule documents**. The signed backend
publishes schema-v1 documents, so dropping that decoder would reject every real
rule pack the moment this client replaced a legacy one. This is the only
deliberate compatibility path in the rewrite; it is deliberate because the wire
format is frozen, not because legacy internals are supported.

Everything else is a hard break: config keys, flags, command set, package
layout, Go API surface and docs structure are all rewritten with no shims.

## What Pro can rely on unchanged

- **The supply-chain wire format.** Endpoints, paths, the channel query, the
  domain tags, the embedded trust-root ids (`root-2026-09`, `rules-2026-09`),
  the three rules payload structs, the floor's behaviour and the document size
  caps are all frozen and pinned by golden vectors. A signed backend designed
  against the legacy client keeps working against this client.
- **The version line starts at `v0.5.0`.** The rules manifest's
  `min_binary_version` gate is evaluated against the same version source, so a
  `0.3.0` floor continues to be satisfied.
- **The placeholder grammar and the redaction log format.** If Pro observes
  either, the bytes are unchanged (see the repository README's verify recipe).

## What Pro must rework when it migrates

The following surfaces changed fundamentally, and Pro code that depended on the
legacy versions must be ported rather than shimmed:

| Surface | What changed |
|---|---|
| Assembly | There is no `pkg/gateway` and no 15-field `Options` contract. `internal/cli` is the only assembler; a Pro binary that needs a custom pipeline composes the public packages itself. |
| Config | The schema is strict and closed: unknown keys are errors. Legacy keys for deleted subsystems are gone. |
| CLI | Exactly seven commands: `run`, `rules`, `update`, `status`, `env`, `version`, `privacy`. There is no `doctor` and no standalone `allowlist` command. |
| Status | `GET /status` is the whole control API, with a frozen ten-key metadata document. |
| Deleted subsystems | The change-channel guard, outbound encoding re-check, key-position blocking, capability tiers, keyring/secret store, `pkg/license`, OS-service stubs and the runtime plugin protocol do not exist. Pro features built on them need a new design or must be dropped. |
| Extension point | Rules are compile-time only, through `pkg/filter`'s `Rule` registry. There is no runtime plugin loading and no capability negotiation. |
| Response path | Rules may only block or warn; redaction is request-path only. |

## Migration checklist (for the separate Pro effort)

1. Do **not** repoint `tokenhush-pro/go.work` at this tree before the port is
   done. Keep `use ../tokenhush` on the legacy checkout.
2. Audit Pro code for imports of deleted packages and of the legacy `pkg/gateway`
   assembly contract; each one is a port decision, not a rename.
3. Move Pro config files to the strict schema and remove deleted keys.
4. Rebuild Pro against this module in a dedicated branch, keeping the supply
   backend frozen: the signing side does not change because the wire format did
   not change.
5. Re-run Pro's own test suite against the ported build, including any golden
   vectors it keeps, before switching the `use` directive.
6. Treat the switch of `use ../tokenhush` as the last step, not the first.

## Related documents

- [architecture.md](architecture.md) — the layered graph and the frozen byte
  surfaces, including the wire format Pro's backend already implements.
- [security.md](security.md) — the invariants and the four residual risks.
- [plugins.md](plugins.md) — the compile-time-only extension point.
