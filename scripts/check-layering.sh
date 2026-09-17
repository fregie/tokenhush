#!/usr/bin/env bash
# check-layering.sh runs the shared layering guard (goal 4) from the repo root.
#
# Set TOKENHUSH_GUARD_FULL_GRAPH=1 to turn missing expected packages and
# missing required edges into violations (the final gate).
set -euo pipefail

cd "$(dirname "$0")/.."

exec go run ./internal/layering/cmd
