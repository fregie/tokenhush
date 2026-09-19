# INTERNAL/GUARDS KNOWLEDGE BASE

## OVERVIEW
Test-only analysis package: no production `.go`. Each guard scans the repo or product tree to enforce one structural invariant. These are not unit tests; they fail when the repository stops matching its contract.

## THE GUARDS
| Guard file | Enforces | Invariant / pin |
|---|---|---|
| `absence_guard_test.go` | No certificate-install, TLS-termination or trust-store shape. Scans production Go for TLS listeners, key pairs, cert pools, `tls.Config`/`http.Server` literals, embedded certs, MITM config keys. | Invariant 3; `TestAbsenceNoCertificateInstallPath` |
| `ci_config_test.go` | `ci.yml` / `.goreleaser.yaml` wiring: exactly one `TOKENHUSH_GUARD_FULL_GRAPH=1` step; required build/vet/test/layering/cross-build/gitleaks/lint steps present. | `TestCIConfigFullGraphGate`, `TestReleaseConfigProductTree` |
| `deps_guard_test.go` | Only `goccy/go-yaml` as a direct dependency; zero indirect. Stdlib-only parser (no `x/mod`). | `TestGoModPinsOnlyTheYAMLDirectDependency` |
| `docs_guard_test.go` | Frozen `docs/` tree; documented command set equals the registered 7 commands parsed from `internal/cli` `register()` calls. | `TestDocsGuardCommandSet`, `TestDocsGuardProductTree` |
| `egress_guard_test.go` | Exactly two vendor-bound egress categories, each naming its switch and host; every switch short-circuits before any network call. Reads `egress.yaml`. | Invariant 6 disclosure half; `TestEgressGuardProductTree`, `TestEgressGuardSwitchesShortCircuit` |
| `import_guard_test.go` | Forbidden imports and rendered signatures in leaf packages: no `net/http`, `net/textproto`, `crypto/tls` in `pkg/{protocol,redact,audit,platform,filter,config}` (aliases included). | `TestImportGuardLeafPackages` |
| `license_guard_test.go` | No GPL/LGPL/AGPL in the module graph; every `go.mod` require exposes a verifiable license file in the module cache. | `TestLicenseGuardProductTree` |
| `normalization_guard_test.go` | No decode/normalize before detection: decoder imports only in allowlisted sites; no `normalize*.go`; decoders never feed `Inspect`. | Must-NOT-Have #19; `TestNormalizationGuardProductTree` |
| `ondisk_guard_test.go` | Builds the real binary, drives it end to end, scans everything a run could write. Metadata only, no request/response plaintext. Runtime-generated secret so the guard never matches its own source. | Invariant 2 run-level half; `TestOndiskGuardRunLevelPlaintext` |
| `shape_guard_test.go` | `pkg/filter.Rule` frozen at exactly 8 methods; no second exported interface in the package. | `TestShapeGuardProductTree` |
| `size_guard_test.go` | 250 strict pure LOC ceiling per production Go file (blank/comment-only excluded; lone `}` and package clause count). Tests, `testdata/`, generated, `.omo/`, `vendor/` exempt. | `TestSizeCeiling` |

Fixture: `testdata/fixturepkg/fixture.go` is a tiny parse target for the guards.

## INVARIANT TEST OWNERSHIP
The 8 security invariants in `docs/security.md` also carry named `TestInvariant*` tests in `pkg/{redact,audit,proxy,filter}`: 1 and 8 in `pkg/redact`, 2 in `pkg/audit`, 4/6/7 in `pkg/proxy`, 5 in `pkg/filter`. Invariant 3's named test *is* `absence_guard_test.go`. Invariant 6 is split: the named proxy test proves the data plane dial count, this package proves the disclosure and switch short-circuit. This package owns the structural/absence half; the behavior half lives beside the code.

## RULE
Each guard owns exactly one rule. When a guard fails, fix the code or the docs it checks. Never loosen, skip, rename or delete the guard to make CI pass. `TOKENHUSH_GUARD_FULL_GRAPH=1` upgrades a missing expected package or missing allowed import edge from a skip to a violation; it may appear in exactly one `ci.yml` step (`ci_config_test.go` fails otherwise).

## GOTCHAS
- `ondisk_guard_test.go` builds the real binary, so it is slow and needs a working toolchain.
- Fixture packages exist to prove the guards catch violations. Do not "fix" a fixture.
