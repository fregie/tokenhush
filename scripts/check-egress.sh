#!/usr/bin/env bash
# egress 一致性守卫（核心侧）：断言核心生成物与 egress.yaml 逐字一致。
#
# 两步：
#   1. -check 不写盘比对，能捕获手工改动（不会被重新生成掩盖）；
#   2. 重新生成后 git diff --exit-code，捕获已提交产物与清单漂移。
# 任一失败即非零退出；CI 门见 .github/workflows/ci.yml 的 egress-guard job。
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

manifest="${1:-${repo_root}/egress.yaml}"
echo "egress-guard: 校验核心生成物与 ${manifest} 一致"

go run ./cmd/egress-gen -check -core-root "${repo_root}" -manifest "${manifest}"
go run ./cmd/egress-gen -core-root "${repo_root}" -manifest "${manifest}"

git diff --exit-code -- \
  internal/cli/egress_generated.go \
  docs/generated/network-egress.md

echo "egress-guard: OK"
