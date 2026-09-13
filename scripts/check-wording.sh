#!/usr/bin/env bash
#
# check-wording.sh — forbid absolute no-egress / no-telemetry claims.
#
# A single, authoritative "forbidden family / allowed form" definition, shared
# with the A5 wording sweep (same semantics, same family). It fails on a *claim*
# of absolute privacy — "数据不出设备", "绝不泄露", "no telemetry", "data never
# leaves", … — while deliberately accepting:
#
#   * the qualified form  无遥测（除更新检查与规则同步两个可关外发…）
#     (a `除` clause right after the phrase), which is the approved wording;
#   * quoted mentions  "…"  '…'  「…」  『…』  `…`  “…”  ‘…’ — mentioning a
#     phrase to reject it is not claiming it;
#   * ❌ denylist entries (a bullet that marks the phrase as forbidden);
#   * negation / discipline immediately before the phrase (不宣称/不写/不做/
#     不吹/不说/不称/不承诺, 否认, 禁止, 勿 …).
#
# Exempt: docs/archive/** (historical snapshot) and docs/decisions/** (ADR
# bodies are historical records; the approved qualified form is what new ADRs
# use). The marketing site (web/**) is owned by its own copy/claim guard
# (`cd web && npm run verify`), not by this repository-docs gate.
#
# Rationale for the family: an absolute privacy claim is a factual promise the
# product cannot keep once update-check / rule-sync egress exists (ADR-0022).
#
# Usage:
#   scripts/check-wording.sh              # scan this repository's Markdown
#   scripts/check-wording.sh PATH ...     # scan only these files/directories
# Exit: 0 = clean; 1 = a forbidden claim found; 2 = usage/tooling error.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "check-wording: FAIL: python3 is required but was not found on PATH" >&2
  exit 2
fi

python3 - "${repo_root}" "$@" <<'PY'
"""Fail on an absolute no-egress / no-telemetry claim in Markdown.

The forbidden family and the allowed forms are defined once, here. A match is
accepted as a *mention* (not a claim) when it is quoted, is a ❌ denylist entry,
carries a `除…` qualifier, or is immediately preceded by a negation/discipline
word. Everything else is a violation and makes the gate exit non-zero.
"""
import os
import re
import sys

# --- the single forbidden family (absolute negation + egress/telemetry) -------
FAMILY = (
    r"数据不出|绝不泄露|不发送任何数据|零外发|零非 ?loopback|无遥测|"
    r"no data leaves|data never leaves|no outbound|no network|no telemetry"
)
FAMILY_RE = re.compile(FAMILY, re.I)

SKIP_DIRS = {".git", ".omo", "node_modules", ".astro", "web"}
SKIP_REL_PREFIXES = ("docs/archive", "docs/decisions")

# Quoted spans: mentioning a phrase to reject it is not claiming it.
QUOTE_PAIRS = [
    ('"', '"'),
    ("'", "'"),
    ("「", "」"),
    ("『", "』"),
    ("`", "`"),
    ("“", "”"),
    ("‘", "’"),
]
QUOTE_RES = [
    re.compile(re.escape(o) + r".*?" + re.escape(c)) for o, c in QUOTE_PAIRS
]

# `无遥测（除更新检查与规则同步两个可关外发…）` — the approved qualified form.
QUALIFIED = re.compile(r"^[（(]?\s*除")

# Negation / discipline immediately before the phrase.
DISCIPLINE_TAIL = re.compile(
    r"(?:不宣称|不声称|不承诺|不写|不做|不吹|不说|不称|否认|禁止|勿|不)$"
)
STRIP_TAIL = re.compile(r"[\s\"'`「」『』“”‘’()（）\[\]【】]+$")

REPO_ROOT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else "."


def classify(line, match):
    """Return an allow-reason, or None if this match is a forbidden claim."""
    start, end = match.start(), match.end()
    for quoted in QUOTE_RES:
        for qm in quoted.finditer(line):
            if qm.start() <= start and end <= qm.end():
                return "quoted mention"
    if "❌" in line[:start]:
        return "denylist (❌) entry"
    if QUALIFIED.match(line[end:].lstrip()):
        return "qualified (除…)"
    before = STRIP_TAIL.sub("", line[:start])
    if DISCIPLINE_TAIL.search(before):
        return "negated / discipline"
    return None


def markdown_files(paths):
    """Yield (abs_path, repo-relative-or-given-path) for Markdown under paths."""
    seen = set()
    for base in paths:
        base_abs = os.path.abspath(base)
        if os.path.isfile(base_abs):
            if base_abs.endswith(".md") and base_abs not in seen:
                seen.add(base_abs)
                yield base_abs, os.path.relpath(base_abs, REPO_ROOT)
            continue
        for root, dirs, files in os.walk(base_abs):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            relroot = os.path.relpath(root, REPO_ROOT)
            if relroot == ".":
                relroot = ""
            if any(
                relroot == p or relroot.startswith(p + os.sep)
                for p in SKIP_REL_PREFIXES
            ):
                dirs[:] = []
                continue
            for name in sorted(files):
                if not name.endswith(".md"):
                    continue
                abs_path = os.path.join(root, name)
                if abs_path in seen:
                    continue
                rel = os.path.normpath(os.path.join(relroot, name))
                if any(
                    rel == p or rel.startswith(p + os.sep)
                    for p in SKIP_REL_PREFIXES
                ):
                    continue
                seen.add(abs_path)
                yield abs_path, rel


def main():
    repo_root = os.path.abspath(sys.argv[1])
    extra = sys.argv[2:]
    paths = (
        [
            os.path.join(repo_root, p) if not os.path.isabs(p) else p
            for p in extra
        ]
        if extra
        else [repo_root]
    )

    files = list(markdown_files(paths))
    violations = []

    for path, rel in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            print("check-wording: FAIL: cannot read {}: {}".format(rel, exc))
            return 1
        for lineno, line in enumerate(lines, 1):
            for match in FAMILY_RE.finditer(line):
                if classify(line, match) is None:
                    violations.append(
                        ("{}:{}".format(rel, lineno), match.group(0), line.strip())
                    )

    if violations:
        print(
            "check-wording: FAILED ({} forbidden claim(s))".format(
                len(violations)
            )
        )
        print("check-wording: family: {}".format(FAMILY))
        for loc, hit, line in violations:
            print("  {}: '{}'".format(loc, hit))
            print("      {}".format(line[:160]))
        return 1
    print(
        "check-wording: OK ({} file(s) scanned, 0 forbidden claims)".format(
            len(files)
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
