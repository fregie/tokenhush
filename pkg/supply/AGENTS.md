# pkg/supply

## OVERVIEW
Signed rule sync plus signed self-update supply chain: frozen wire format, Ed25519 verification, anti-rollback, crash-safe replace.

## WHERE TO LOOK
| Task | File |
|---|---|
| Frozen origin, paths, domain tags, caps, roots | `substrate.go` |
| Update document decode+verify, freshness, D17 routing | `source.go` |
| Online update key install + rollback rejection | `keylist.go` |
| Update sequence order, OD-1 downgrade gate | `update.go` |
| Two-phase replace, journal, artifact download | `replace.go` |
| Startup self-heal of an interrupted commit | `recover.go` |
| Revocation stream + rollback retention | `revocation.go` |
| Rules sync order, OD-2 gate, `RulesState` | `rules.go`, `rules_activate.go` |
| Rules cache layout, pack decode/verify, version+digest checks | `rules_cache.go` |
| Rules manifest decode, OD-4 `SchemaVersionGate` | `manifest.go` |
| Both signing-input projections + payload structs | `payload.go` |
| High-water mark, atomic 0600 persist | `highwater.go` |
| Golden vectors | `testdata/signing_vectors.json` |

## FROZEN WIRE SURFACES (never change)
- Origin `https://updates.tokenhush.com` (`BaseURL`). Every URL is `BaseURL + Path + ChannelQuery`; channel is always `stable`, nothing configurable.
- Endpoints `/v1/update/{manifest,revocations,keylist}` and `/v1/rules/{manifest,bundle,revocations}`.
- Six domain tags: `tokenhush-update-manifest-v1`, `tokenhush-update-revocations-v1`, `tokenhush-update-keylist-v1`, `tokenhush-rules-manifest-v1`, `tokenhush-rules-pack-v1`, `tokenhush-rules-revocations-v1`.
- Embedded key ids `root-2026-09` (`KeyRootUpdate`) and `rules-2026-09` (`KeyRulesRoot`), public halves only. Online `upd-*` keys arrive through the root-signed keylist and are never embedded.
- Caps: update docs `MaxUpdateDocBytes` 128 KiB, rules docs `MaxRulesDocBytes` 256 KiB, artifact `MaxArtifactBytes` 256 MiB via a separate bounded fetcher that must not inherit a doc cap.
- Cache layout `<DataDir>/rules/{active,revoked.json,<serial>/{manifest,bundle}.json,highwater.json}` and `<DataDir>/update/highwater.json`; atomic writes, mode `0600`.

## THE TWO SIGNING-INPUT PROJECTIONS (never unify)
- Update docs: `domain + "\n" + name:value lines`, frozen field order, epoch-second timestamps.
- Rules docs: `domain + "\n" + hex(sha256(json.Marshal(payloadStruct)))`.
- All three rule payload struct shapes are frozen (`RulesPackPayload`, `RulesManifestPayload`, `RulesRevocationsPayload`): field set, order, JSON names, Go types, `omitempty`.
- Projection uses raw, undefaulted decoded values. `EpochSeconds` decodes RFC 3339 doc form and epoch-number payload form, always marshals the number. Every rule projection strips `Signature` before hashing.

## THE NON-WEAKENING FLOOR (OD-3)
`filter.DefaultFloorBaseline().Check(doc)` rejects exactly four things: a pack that disables a baseline detector, a pack that drops a required category, a rule carrying `allow`, and a rule setting email `replace`. It is allowlist-neutral; additive `email.suffixes` stay allowed.
OD-2 gate refusal is `CommandGateError` / `errors.Is(err, ErrCommandGate)`, deliberately distinct from `ErrSchemaVersion`. Command packs are accepted with a warning under manifest `schema_version` 1 and refused under 2.
OD-4 gate: `SchemaVersionGate` accepts only 1 (closed) or 2 (open); any other version is `ErrSchemaVersion`.

## INSTALL-SOURCE ROUTING (D17)
`DetectSource` maps to `SourceHomebrew` (delegates `brew upgrade --cask tokenhush`), `SourceScoop` (delegates `scoop update tokenhush`), `SourceSelfManaged` (only this one self-replaces), `SourceUnknown` (guidance only, never self-replaced). `--check` downloads, installs, and writes nothing. A downgrade needs both the caller flag and `TOKENHUSH_ALLOW_DOWNGRADE`.

## GOTCHAS
- Packs load at next start, never hot. `Startup` is cache-only and makes no network request; `Sync` short-circuits on `TOKENHUSH_NO_RULE_SYNC=1`.
- Any problem falls back to the built-in defaults with a warning. A cached pack is re-verified by signature but not by freshness.
- The high-water mark advances LAST in both streams; a rejected sync or update leaves the active pack, cache, and running binary byte-identical.
- Branch on typed sentinels (`ErrReplay`, `ErrHighWaterCorrupt`, `ErrKeyListRollback`, `ErrRevocationRollback`, `ErrCacheCorrupt`, `ErrDigestMismatch`, `ErrCommandGate`, ...). Error text never echoes untrusted document content.
- Tests: 50 test funcs across `*_test.go`; the golden vectors are anchored by `golden_test.go` and `manifest_test.go`.
