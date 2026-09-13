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
# findings. The exclusion is applied here, not in .gitleaks.toml, so the
# committed rule set keeps no path exemptions; it is printed, never silent.
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
