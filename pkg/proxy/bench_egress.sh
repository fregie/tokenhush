#!/usr/bin/env bash
#
# bench_egress.sh - the W2.5 reproducible benchmark gate for the outbound
# egress re-check (pkg/proxy/egress.go).
#
# Run it with no arguments from any directory; it writes its artifacts into the
# current directory:
#
#   bash pkg/proxy/bench_egress.sh
#
# It captures the two files with the command the plan fixes:
#
#   baseline.txt - egressRecheckDisabled = true  (the zero-overhead path)
#   after.txt    - egressRecheckDisabled = false (the checked path)
#
#   go test ./pkg/proxy/ -run '^$' -bench BenchmarkEgressRecheck \
#       -benchtime 2s -count 6
#
# then runs benchstat over them and asserts the plan's bounds:
#
#   EgressRecheck/NoSecrets            delta < 5%
#   EgressRecheck/CleanBodyWithSecrets delta < 15%
#
# A violated bound exits non-zero after printing the offending benchstat row.
# The test-only switch is flipped in place and restored on exit (the trap); the
# script fails if it cannot confirm the switch state, so do not run two copies
# at once.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$(pwd)"
SRC="$REPO_ROOT/pkg/proxy/egress.go"

BENCHSTAT="/home/fregie/go/bin/benchstat"
BENCH_PATTERN="BenchmarkEgressRecheck"
BENCHTIME="2s"
COUNT="6"

SWITCH_TRUE="var egressRecheckDisabled = true"
SWITCH_FALSE="var egressRecheckDisabled = false"
BASELINE="$OUT_DIR/baseline.txt"
AFTER="$OUT_DIR/after.txt"
BENCHSTAT_OUT="$OUT_DIR/benchstat.txt"

log() { printf 'bench_egress: %s\n' "$*"; }
fail() { printf 'bench_egress: FAIL: %s\n' "$*" >&2; exit 1; }

restore_switch() {
  if grep -qx "$SWITCH_TRUE" "$SRC" 2>/dev/null; then
    sed -i "s/^${SWITCH_TRUE}\$/${SWITCH_FALSE}/" "$SRC"
  fi
}
trap restore_switch EXIT

set_switch() {
  sed -i -E "s/^var egressRecheckDisabled = (true|false)\$/var egressRecheckDisabled = $1/" "$SRC"
  grep -qx "var egressRecheckDisabled = $1" "$SRC" \
    || fail "could not set egressRecheckDisabled = $1 in $SRC"
}

capture() {
  local state="$1" dest="$2"
  set_switch "$state"
  log "capturing $dest with egressRecheckDisabled = $state"
  ( cd "$REPO_ROOT" && go test ./pkg/proxy/ -run '^$' -bench "$BENCH_PATTERN" -benchtime "$BENCHTIME" -count "$COUNT" ) > "$dest" 2>&1 \
    || { cat "$dest"; fail "benchmark capture failed (see $dest)"; }
  grep -q "^BenchmarkEgressRecheck/" "$dest" \
    || fail "no raw BenchmarkEgressRecheck lines in $dest - did a tool compress the output?"
  log "$dest: $(grep -c '^BenchmarkEgressRecheck/' "$dest") raw benchmark lines"
}

delta_of() {
  local row pct
  row="$(awk -v name="$1" 'index($0, name) == 1 { print; exit }' "$BENCHSTAT_OUT")"
  [ -n "$row" ] || fail "benchstat printed no row for $1 (see $BENCHSTAT_OUT)"
  pct="$(printf '%s\n' "$row" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[+-][0-9.]+%$/) { print $i; exit } }')"
  if [ -z "$pct" ]; then
    case "$row" in
      *"~"*) pct="+0.00%" ;;
      *) fail "cannot read a delta from the benchstat row for $1: $row" ;;
    esac
  fi
  printf '%s' "$pct"
}

check_bound() {
  local pct
  pct="$(delta_of "$1")"
  awk -v v="${pct%\%}" -v max="$2" 'BEGIN { exit ((v + 0) > (max + 0)) ? 1 : 0 }' \
    || fail "$3: delta $pct exceeds the $2% bound"
  log "$3: delta $pct within the $2% bound"
}

main() {
  [ -x "$BENCHSTAT" ] || fail "benchstat not found or not executable at $BENCHSTAT"

  capture true "$BASELINE"
  capture false "$AFTER"
  grep -qx "$SWITCH_FALSE" "$SRC" || fail "the test-only switch was not restored to false"

  log "benchstat $BASELINE $AFTER"
  "$BENCHSTAT" "$BASELINE" "$AFTER" | tee "$BENCHSTAT_OUT"

  check_bound "EgressRecheck/NoSecrets" 5 "no known secrets"
  check_bound "EgressRecheck/CleanBodyWithSecrets" 15 "known secrets + clean body"

  log "PASS: both bounds hold"
}

main "$@"
