#!/usr/bin/env bash
#
# check-docs.sh — assert the public docs stay in sync with the shipped CLI and config.
#
# Checks:
#   1. every command listed inside a `check-docs:commands` block is recognized by
#      the built `./cmd/tokenhush` binary (`--help` prints that command's usage,
#      or exits 0 for commands without a flag parser);
#   2. every key inside a `check-docs:config` block is accepted by the real
#      `pkg/config` loader (an unknown documented key makes `config.LoadFile`
#      fail with "unknown field").
#
# Usage:
#   scripts/check-docs.sh [DOC ...]
#
# Extra DOC arguments are scanned in addition to the defaults. That is how the
# negative proof injects a documented-but-missing command or config key.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

default_docs=(
	"$repo_root/README.md"
	"$repo_root/README.zh-CN.md"
	"$repo_root/AGENTS.md"
	"$repo_root/CONTRIBUTING.md"
	"$repo_root/CONTRIBUTING.zh-CN.md"
	"$repo_root/docs/README.md"
	"$repo_root/docs/README.zh-CN.md"
	"$repo_root/docs/architecture.md"
	"$repo_root/docs/architecture.zh-CN.md"
	"$repo_root/docs/configuration.md"
	"$repo_root/docs/configuration.zh-CN.md"
	"$repo_root/docs/deployment.md"
	"$repo_root/docs/deployment.zh-CN.md"
	"$repo_root/docs/extension-api.md"
	"$repo_root/docs/extension-api.zh-CN.md"
	"$repo_root/docs/plugins.md"
	"$repo_root/docs/plugins.zh-CN.md"
	"$repo_root/docs/security.md"
	"$repo_root/docs/security.zh-CN.md"
	"$repo_root/docs/verify.md"
	"$repo_root/docs/verify.zh-CN.md"
)
docs=("${default_docs[@]}" "$@")

tmp="$(mktemp -d "${TMPDIR:-/tmp}/tokenhush-check-docs.XXXXXX")"
helper_dir=""
cleanup() {
	rm -rf "$tmp"
	if [ -n "$helper_dir" ]; then
		rm -rf "$helper_dir"
	fi
}
trap cleanup EXIT INT TERM

failures=0
info() { printf '%s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; failures=$((failures + 1)); }

# block <file> <marker>: print the lines strictly between the matching
# `check-docs:<marker>:start` and `:end` HTML comments, if the file exists.
block() {
	[ -f "$1" ] || return 0
	awk -v m="$2" '
		index($0, "check-docs:" m ":start") { inblock = 1; next }
		index($0, "check-docs:" m ":end")   { inblock = 0; next }
		inblock { print }
	' "$1"
}

# --- 1. documented CLI commands -------------------------------------------------

info "== documented CLI commands =="
bin="$tmp/tokenhush"
if ! (cd "$repo_root" && go build -o "$bin" ./cmd/tokenhush); then
	echo "FAIL: cannot build ./cmd/tokenhush" >&2
	exit 1
fi

commands="$tmp/commands.txt"
: > "$commands"
for f in "${docs[@]}"; do
	block "$f" commands \
		| grep -oE 'tokenhush[[:space:]]+[a-z][a-z0-9-]*' \
		| awk '{ print $2 }' >> "$commands" || true
done
sort -u -o "$commands" "$commands"

if [ ! -s "$commands" ]; then
	fail "no documented commands found (missing a check-docs:commands block?)"
fi

while IFS= read -r cmd; do
	[ -n "$cmd" ] || continue
	set +e
	out="$("$bin" "$cmd" --help 2>&1)"
	rc=$?
	set -e
	if [ "$rc" -eq 0 ]; then
		info "ok: tokenhush $cmd --help (exit 0)"
	elif printf '%s' "$out" | grep -q "Usage of $cmd:"; then
		# Commands backed by a stdlib flag set exit 2 on --help while printing
		# their own usage. That usage is the "command is recognized" signal.
		info "ok: tokenhush $cmd --help (recognized; usage exit $rc)"
	else
		fail "documented command 'tokenhush $cmd' is not recognized (exit $rc): $(printf '%s' "$out" | head -n1)"
	fi
done < "$commands"

# --- 2. documented config keys --------------------------------------------------

info
info "== documented config keys =="

# Build a throwaway helper INSIDE the module so it uses the repo's go.mod/go.sum
# and the real config.LoadFile. A dot-prefixed dir is ignored by `./...` and is
# removed by the cleanup trap.
helper_dir="$(mktemp -d "$repo_root/.checkdocs.XXXXXX")"
cat > "$helper_dir/main.go" <<'GO'
package main

import (
	"fmt"
	"os"

	"github.com/fregie/tokenhush/pkg/config"
)

// main validates one documented YAML sample with the real loader. An unknown
// field (a documented key pkg/config does not define) or an invalid value makes
// LoadFile fail, which is exactly the drift this checker exists to catch.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: checkdocs <config.yaml>")
		os.Exit(2)
	}
	if _, err := config.LoadFile(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("config sample OK")
}
GO

samples=0
for f in "${docs[@]}"; do
	block "$f" config | grep -vE '^[[:space:]]*```[a-zA-Z]*[[:space:]]*$' > "$tmp/sample.yaml" || true
	if [ ! -s "$tmp/sample.yaml" ]; then
		continue
	fi
	samples=$((samples + 1))
	set +e
	out="$(cd "$repo_root" && go run "./$(basename "$helper_dir")" "$tmp/sample.yaml" 2>&1)"
	rc=$?
	set -e
	if [ "$rc" -eq 0 ]; then
		info "ok: config sample in ${f#"$repo_root"/} accepted by pkg/config"
	else
		reason="$(printf '%s\n' "$out" | grep -m1 -E 'unknown field|must be|invalid' || printf '%s' "$out" | head -n1)"
		fail "config sample in ${f#"$repo_root"/} rejected by pkg/config: $reason"
	fi
done

if [ "$samples" -eq 0 ]; then
	fail "no documented config sample found (missing a check-docs:config block?)"
fi

# --- verdict --------------------------------------------------------------------

echo
if [ "$failures" -gt 0 ]; then
	echo "check-docs: FAILED ($failures problem(s))"
	exit 1
fi
echo "check-docs: OK"
