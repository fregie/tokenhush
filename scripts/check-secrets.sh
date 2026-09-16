#!/usr/bin/env bash
# Working-tree secret scan gate.
#
# `gitleaks detect` in git mode only sees committed history. A credential that
# lands in an untracked or .gitignore'd file is invisible to it — the 2026-09
# Cloudflare token leak lived in exactly such files, so this gate scans the
# working tree as a plain directory: tracked, untracked and ignored files
# alike. It scans with .gitleaks.toml (default rule set + tokenhush custom
# rules) plus a runtime-only scope exclusion for the agent workspace (below).
#
# Scope note: .omo/ (agent workspace metadata, gitignored) is excluded because
# it is never part of a repository checkout and by design records security-QA
# transcripts containing synthetic credentials, which would drown real
# findings. A second exclusion exempts exactly one line — the frozen W3.1 HKDF
# derivation test vector (a public 64-hex constant that pins the derivation
# output, not a credential) — under one rule, one path and the exact literal,
# so any other secret in that file or elsewhere is still reported. Both
# exclusions are applied here, not in .gitleaks.toml, so the committed rule
# set keeps no path exemptions; they are printed, never silent.
#
# Usage: bash scripts/check-secrets.sh
# Env:   GITLEAKS_BIN  gitleaks binary to use (default: gitleaks on PATH)
# Exit:  0 = clean; 1 = findings (secrets redacted); 2 = tooling/usage error.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

gitleaks_bin="${GITLEAKS_BIN:-gitleaks}"
if [[ "${gitleaks_bin}" == */* ]]; then
  if [[ ! -x "${gitleaks_bin}" ]]; then
    echo "check-secrets: FAIL: '${gitleaks_bin}' is not executable; set GITLEAKS_BIN or install gitleaks" >&2
    exit 2
  fi
elif ! command -v "${gitleaks_bin}" >/dev/null 2>&1; then
  echo "check-secrets: FAIL: gitleaks not found; set GITLEAKS_BIN or install gitleaks" >&2
  exit 2
fi

runtime_config="$(mktemp "${TMPDIR:-/tmp}/check-secrets-XXXXXX")"
trap 'rm -f "${runtime_config}"' EXIT
{
  cat .gitleaks.toml
  printf '\n[[allowlists]]\ndescription = "Agent workspace metadata (.omo/): gitignored, absent from CI checkouts, records synthetic security-QA transcripts"\npaths = [\n  %s,\n]\n' "'''(^|/)\\.omo/'''"
  printf '\n[[allowlists]]\ndescription = "W3.1 frozen HKDF derivation vector in pkg/platform/secretstore_derivation_test.go: a public 64-hex test vector that pins the derivation output, not a credential"\ntargetRules = [\n  "generic-api-key",\n]\ncondition = "AND"\npaths = [\n  %s,\n]\nregexTarget = "line"\nregexes = [\n  %s,\n]\n' "'''(^|/)pkg/platform/secretstore_derivation_test\\.go$'''" "'''frozenKey\\s*=\\s*\"557d2338c7ca32a866e52602c2a55c9ccdcac27205b2683d657130ef798ac195\"'''"
} > "${runtime_config}"

echo "check-secrets: gitleaks $("${gitleaks_bin}" version)"
echo "check-secrets: scanning working tree (untracked + ignored files included; .omo/ agent workspace excluded)"
"${gitleaks_bin}" detect \
  --no-git \
  --source . \
  --config "${runtime_config}" \
  --redact \
  --no-color \
  --no-banner \
  --exit-code 1 \
  --verbose
echo "check-secrets: OK — no findings in the working tree"
