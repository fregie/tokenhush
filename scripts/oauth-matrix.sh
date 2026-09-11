#!/usr/bin/env bash
# oauth-matrix.sh — offline request-shape matrix for subscription/OAuth AI clients.
#
# Matrix mode (default) starts a fake provider endpoint on an ephemeral loopback
# port, sends the request shapes that Claude Code / Codex CLI are expected to
# send when they honor a base-URL override, records what the endpoint actually
# received, and asserts per-mode counts + shape fingerprints. Loopback only,
# no third-party dependencies (bash + curl + the Go toolchain this repo needs).
#
# Capture mode (--capture MODE) starts the same fake endpoint and waits while a
# human points a real client at it (the documented manual live-OAuth procedure).
# The real request shape is recorded into the artifact; see docs/12 §6.
#
# Usage:
#   bash scripts/oauth-matrix.sh                          # full deterministic matrix
#   OUT_DIR=/tmp/out bash scripts/oauth-matrix.sh         # choose artifact directory
#   bash scripts/oauth-matrix.sh --capture claude-oauth   # interactive capture (manual)
#   bash scripts/oauth-matrix.sh --list                   # modes and shapes
#
# Artifacts (in OUT_DIR): requests.jsonl (per-record shape), counts.txt (per-mode counts).
# Exit codes: 0 = all modes matched; 1 = shape/count mismatch; 2 = usage/env error.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GO_BIN="${GO:-go}"
CURL_BIN="${CURL:-curl}"
READY_TIMEOUT="${READY_TIMEOUT:-15}"
FINISH_TIMEOUT="${FINISH_TIMEOUT:-15}"
CURL_MAX_TIME="${CURL_MAX_TIME:-10}"

# Obvious placeholders; never real credentials. The fake upstream classifies
# token prefixes and never writes token values to the artifact.
AUTH_OAUTH_PLACEHOLDER="oa-matrix-claude-oauth-0001"
AUTH_API_KEY_PLACEHOLDER="sk-ant-api03-matrix-placeholder"
AUTH_CHATGPT_PLACEHOLDER="codex-matrix-chatgpt-0001"
AUTH_OPENAI_PLACEHOLDER="codex-matrix-api-key-0001"

UPSTREAM_PID=""
TAIL_PID=""
BASE_URL=""
OVERALL=0
MODE_COUNT=0
SHAPE_COUNT=0

usage() {
  cat <<'EOF'
usage: bash scripts/oauth-matrix.sh [--capture MODE | --list | --help]

  (no args)        run the deterministic request-shape matrix
  --capture MODE   start the fake upstream and record a real client session
                   (manual live-OAuth procedure; Ctrl-C when done)
  --list           list modes and their expected shapes
  --help           this text

env: OUT_DIR (artifact dir; default: fresh mktemp dir), GO, CURL,
     READY_TIMEOUT, FINISH_TIMEOUT, CURL_MAX_TIME, KEEP_TMP=1
EOF
}

list_modes() {
  cat <<'EOF'
modes and expected shapes (base-URL override honored):
  claude-oauth    POST /v1/messages?beta=true, POST /v1/messages/count_tokens?beta=true
                  authorization: Bearer sk-ant-oat01-* (subscription OAuth),
                  anthropic-beta includes oauth-2025-04-20
  claude-apikey   POST /v1/messages?beta=true, POST /v1/messages/count_tokens?beta=true
                  x-api-key: sk-ant-api03-*
  codex-chatgpt   POST /responses (base URL without /v1)
                  authorization: Bearer ChatGPT access token, chatgpt-account-id,
                  originator: codex_cli_rs, openai-beta: responses_websockets=*
  codex-apikey    POST /v1/responses (base URL includes /v1)
                  authorization: Bearer sk-* platform key
EOF
}

# Expected records per mode: single-line JSON substrings. Field order is fixed
# by the upstream helper's struct (mode, seq, method, path, [query], auth, ...).
expected_lines() {
  case "$1" in
    claude-oauth)
      cat <<'EOF'
"mode":"claude-oauth","seq":1,"method":"POST","path":"/v1/messages","query":"beta=true","auth":"bearer:placeholder"
"mode":"claude-oauth","seq":2,"method":"POST","path":"/v1/messages/count_tokens","query":"beta=true","auth":"bearer:placeholder"
EOF
      ;;
    claude-apikey)
      cat <<'EOF'
"mode":"claude-apikey","seq":1,"method":"POST","path":"/v1/messages","query":"beta=true","auth":"x-api-key:api-key"
"mode":"claude-apikey","seq":2,"method":"POST","path":"/v1/messages/count_tokens","query":"beta=true","auth":"x-api-key:api-key"
EOF
      ;;
    codex-chatgpt)
      cat <<'EOF'
"mode":"codex-chatgpt","seq":1,"method":"POST","path":"/responses","auth":"bearer:placeholder"
EOF
      ;;
    codex-apikey)
      cat <<'EOF'
"mode":"codex-apikey","seq":1,"method":"POST","path":"/v1/responses","auth":"bearer:placeholder"
EOF
      ;;
    *)
      echo "unknown mode: $1" >&2
      return 2
      ;;
  esac
}

post() { # post <path> <json-body> [curl header args...]
  local path="$1" body="$2"
  shift 2
  local code
  code="$("$CURL_BIN" --silent --show-error --max-time "$CURL_MAX_TIME" \
    --request POST --output "$WORK/resp.body" --write-out '%{http_code}' \
    "$BASE_URL$path" --header 'content-type: application/json' \
    "$@" --data-binary "$body")"
  if [ "$code" != "200" ]; then
    printf 'FAIL: POST %s -> HTTP %s\n' "$path" "$code" >&2
    cat "$WORK/resp.body" >&2 2>/dev/null || true
    return 1
  fi
  printf 'sent: POST %s http=%s\n' "$path" "$code"
}

send_claude_oauth() {
  post '/v1/messages?beta=true' "$(cat <<'JSON'
{"model":"claude-sonnet-4-5","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"oauth-matrix probe"}]}
JSON
)" \
    --header "authorization: Bearer $AUTH_OAUTH_PLACEHOLDER" \
    --header 'anthropic-version: 2023-06-01' \
    --header 'anthropic-beta: oauth-2025-04-20,claude-code-20250219' \
    --header 'x-app: cli' \
    --header 'user-agent: claude-cli/2.1.9 (external, cli)' \
    --header 'accept: application/json'

  post '/v1/messages/count_tokens?beta=true' "$(cat <<'JSON'
{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"oauth-matrix probe"}]}
JSON
)" \
    --header "authorization: Bearer $AUTH_OAUTH_PLACEHOLDER" \
    --header 'anthropic-version: 2023-06-01' \
    --header 'anthropic-beta: oauth-2025-04-20,claude-code-20250219' \
    --header 'x-app: cli' \
    --header 'user-agent: claude-cli/2.1.9 (external, cli)' \
    --header 'accept: application/json'
}

send_claude_apikey() {
  post '/v1/messages?beta=true' "$(cat <<'JSON'
{"model":"claude-sonnet-4-5","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"oauth-matrix probe"}]}
JSON
)" \
    --header "x-api-key: $AUTH_API_KEY_PLACEHOLDER" \
    --header 'anthropic-version: 2023-06-01' \
    --header 'anthropic-beta: claude-code-20250219' \
    --header 'x-app: cli' \
    --header 'user-agent: claude-cli/2.1.9 (external, cli)' \
    --header 'accept: application/json'

  post '/v1/messages/count_tokens?beta=true' "$(cat <<'JSON'
{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"oauth-matrix probe"}]}
JSON
)" \
    --header "x-api-key: $AUTH_API_KEY_PLACEHOLDER" \
    --header 'anthropic-version: 2023-06-01' \
    --header 'anthropic-beta: claude-code-20250219' \
    --header 'x-app: cli' \
    --header 'user-agent: claude-cli/2.1.9 (external, cli)' \
    --header 'accept: application/json'
}

send_codex_chatgpt() {
  post /responses "$(cat <<'JSON'
{"model":"gpt-5-codex","instructions":"oauth-matrix probe","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"oauth-matrix probe"}]}],"tools":[],"tool_choice":"auto","parallel_tool_calls":false,"store":false,"stream":true,"include":[]}
JSON
)" \
    --header "authorization: Bearer $AUTH_CHATGPT_PLACEHOLDER" \
    --header 'chatgpt-account-id: 00000000-0000-0000-0000-000000000000' \
    --header 'originator: codex_cli_rs' \
    --header 'version: 0.154.0' \
    --header 'openai-beta: responses_websockets=2026-02-06' \
    --header 'user-agent: codex_cli_rs/0.154.0 (Linux x86_64)' \
    --header 'accept: text/event-stream'
}

send_codex_apikey() {
  post /v1/responses "$(cat <<'JSON'
{"model":"gpt-5-codex","instructions":"oauth-matrix probe","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"oauth-matrix probe"}]}],"tools":[],"tool_choice":"auto","parallel_tool_calls":false,"store":false,"stream":true,"include":[]}
JSON
)" \
    --header "authorization: Bearer $AUTH_OPENAI_PLACEHOLDER" \
    --header 'originator: codex_cli_rs' \
    --header 'version: 0.154.0' \
    --header 'openai-beta: responses_websockets=2026-02-06' \
    --header 'user-agent: codex_cli_rs/0.154.0 (Linux x86_64)' \
    --header 'accept: text/event-stream'
}

start_upstream() { # start_upstream <mode> <expect>
  local mode="$1" expect="$2" i=0
  rm -f "$WORK/ready" "$WORK/upstream.log"
  "$WORK/oauth-matrix-upstream" -mode "$mode" -ready "$WORK/ready" \
    -out "$REQUESTS" -expect "$expect" >"$WORK/upstream.log" 2>&1 &
  UPSTREAM_PID=$!
  while [ ! -s "$WORK/ready" ]; do
    if ! kill -0 "$UPSTREAM_PID" 2>/dev/null; then
      printf 'FAIL: upstream exited before becoming ready\n' >&2
      cat "$WORK/upstream.log" >&2 || true
      return 1
    fi
    i=$((i + 1))
    if [ "$i" -gt $((READY_TIMEOUT * 10)) ]; then
      printf 'FAIL: upstream not ready after %ss\n' "$READY_TIMEOUT" >&2
      return 1
    fi
    sleep 0.1
  done
  BASE_URL="http://$(cat "$WORK/ready")"
  printf 'upstream: %s (ephemeral port)\n' "$BASE_URL"
}

finish_upstream() {
  local i=0
  while ! grep -q '^DONE ' "$WORK/upstream.log" 2>/dev/null; do
    if ! kill -0 "$UPSTREAM_PID" 2>/dev/null; then
      break
    fi
    i=$((i + 1))
    if [ "$i" -gt $((FINISH_TIMEOUT * 10)) ]; then
      printf 'FAIL: upstream did not finish after %ss\n' "$FINISH_TIMEOUT" >&2
      cat "$WORK/upstream.log" >&2 || true
      kill_upstream
      return 1
    fi
    sleep 0.1
  done
  wait "$UPSTREAM_PID" 2>/dev/null || true
  UPSTREAM_PID=""
  cat "$WORK/upstream.log"
}

kill_upstream() {
  if [ -n "$UPSTREAM_PID" ] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
    kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
  fi
  UPSTREAM_PID=""
}

check_mode() { # check_mode <mode>
  local mode="$1" status=ok expected=0 received=0 line hits
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    expected=$((expected + 1))
    hits="$(grep -F -c -- "$line" "$REQUESTS" || true)"
    if [ "${hits:-0}" -ne 1 ]; then
      printf 'FAIL[%s]: expected exactly 1 match for %s (got %s)\n' \
        "$mode" "$line" "${hits:-0}"
      status=FAIL
    fi
  done < <(expected_lines "$mode")
  received="$(grep -c "\"mode\":\"$mode\"" "$REQUESTS" || true)"
  received="${received:-0}"
  if [ "$received" -ne "$expected" ]; then
    printf 'FAIL[%s]: expected %d record(s), found %d\n' "$mode" "$expected" "$received"
    status=FAIL
  fi
  printf 'mode=%s shapes=%d received=%d status=%s\n' \
    "$mode" "$expected" "$received" "$status" | tee -a "$COUNTS"
  MODE_COUNT=$((MODE_COUNT + 1))
  SHAPE_COUNT=$((SHAPE_COUNT + expected))
  [ "$status" = "ok" ]
}

artifact_hash() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$REQUESTS" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$REQUESTS" | awk '{print $1}'
  else
    openssl dgst -sha256 "$REQUESTS" | awk '{print $NF}'
  fi
}

build_upstream() {
  command -v "$GO_BIN" >/dev/null 2>&1 || { echo "missing Go toolchain ($GO_BIN)" >&2; exit 2; }
  command -v "$CURL_BIN" >/dev/null 2>&1 || { echo "missing curl ($CURL_BIN)" >&2; exit 2; }
  if ! "$GO_BIN" build -o "$WORK/oauth-matrix-upstream" "$SCRIPT_DIR/oauth-matrix-upstream.go"; then
    echo "failed to build scripts/oauth-matrix-upstream.go" >&2
    exit 2
  fi
}

run_matrix() {
  local modes="claude-oauth claude-apikey codex-chatgpt codex-apikey"
  local mode expected
  : >"$REQUESTS"
  : >"$COUNTS"
  printf '== oauth-matrix (simulated client request shapes) ==\n'
  printf 'artifact: %s\n' "$REQUESTS"
  for mode in $modes; do
    expected="$(expected_lines "$mode" | grep -c . || true)"
    printf '\n== mode: %s (expected %s request(s)) ==\n' "$mode" "$expected"
    start_upstream "$mode" "$expected"
    "send_${mode//-/_}"
    finish_upstream
    if check_mode "$mode"; then :; else OVERALL=1; fi
  done
  printf '\nCOUNTARTIFACT %s\n' "$COUNTS"
  printf 'RESULT: %s modes=%d shapes=%d\n' \
    "$([ "$OVERALL" -eq 0 ] && echo PASS || echo FAIL)" "$MODE_COUNT" "$SHAPE_COUNT"
  printf 'artifact: %s\n' "$REQUESTS"
  printf 'artifact_sha256: %s\n' "$(artifact_hash)"
  return "$OVERALL"
}

run_capture() {
  local mode="$1" stop=0
  case "$mode" in
    claude-oauth|claude-apikey|codex-chatgpt|codex-apikey) ;;
    *) printf 'unknown capture mode: %s\n' "$mode" >&2; usage >&2; exit 2 ;;
  esac
  : >"$REQUESTS"
  printf '== oauth-matrix --capture %s (manual) ==\n' "$mode"
  start_upstream "$mode" 0
  tail -n +1 -f "$WORK/upstream.log" &
  TAIL_PID=$!
  cat <<EOF
[capture] fake provider endpoint: $BASE_URL
[capture] artifact: $REQUESTS
[capture] point the real client at the endpoint, run one trivial prompt,
[capture] and watch the REQ lines appear. Press Ctrl-C when the request
[capture] (or the absence of one) has been observed.
EOF
  trap 'stop=1' INT TERM
  while [ "$stop" -eq 0 ]; do
    if grep -q '^DONE ' "$WORK/upstream.log" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done
  kill_upstream
  stop_tail
  printf '[capture] artifact: %s\n' "$REQUESTS"
  if [ -s "$REQUESTS" ]; then
    printf '[capture] captured %s record(s); shapes above\n' "$(grep -c . "$REQUESTS" || true)"
  else
    printf '[capture] no request arrived -> base-URL override NOT honored for this mode\n'
  fi
}

stop_tail() {
  if [ -n "$TAIL_PID" ] && kill -0 "$TAIL_PID" 2>/dev/null; then
    kill "$TAIL_PID" 2>/dev/null || true
    wait "$TAIL_PID" 2>/dev/null || true
  fi
  TAIL_PID=""
}

cleanup() {
  kill_upstream
  stop_tail
  if [ "${KEEP_TMP:-0}" != "1" ] && [ -n "${WORK:-}" ]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

main() {
  local arg="${1:-}"
  case "$arg" in
    --help|-h) usage; exit 0 ;;
    --list) list_modes; exit 0 ;;
    --capture)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      ;;
    "") ;;
    *) usage >&2; exit 2 ;;
  esac

  OUT_DIR="${OUT_DIR:-}"
  if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tokenhush-oauth-matrix.XXXXXX")"
  fi
  mkdir -p "$OUT_DIR"
  REQUESTS="$OUT_DIR/requests.jsonl"
  COUNTS="$OUT_DIR/counts.txt"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/tokenhush-oauth-matrix-work.XXXXXX")"

  build_upstream
  local go_ver curl_ver
  go_ver="$("$GO_BIN" version | awk '{print $3}')"
  curl_ver="$("$CURL_BIN" --version | head -n 1)"
  printf 'tools: go=%s curl=%s\n' "$go_ver" "$curl_ver"

  if [ "$arg" = "--capture" ]; then
    run_capture "$2"
  else
    run_matrix
  fi
}

main "$@"
