#!/usr/bin/env bash
#
# check-links.sh — verify every Markdown link target resolves, including the
# heading anchor of a `file.md#fragment` link.
#
# Deterministic, fully offline, zero third-party dependencies: bash + python3
# only (both present on every GitHub runner and standard developer machine).
#
# Scope: every *.md file in the repository, excluding
#   .omo/  node_modules/  .astro/  docs/archive/
# External targets (http(s), mailto:, tel:, data:, javascript:, ftp:, //) are
# skipped — this gate checks internal consistency, not the live web.
#
# Usage:
#   scripts/check-links.sh [REPO_DIR]
#     REPO_DIR defaults to the repository that contains this script; the
#     argument exists so the negative QA can point the checker at a fixture.
# Exit:
#   0 = every link resolves; 1 = at least one broken link; 2 = usage/tooling.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="${1:-$(cd -- "${script_dir}/.." && pwd)}"

if [[ ! -d "${repo_root}" ]]; then
  echo "check-links: FAIL: '${repo_root}' is not a directory" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "check-links: FAIL: python3 is required but was not found on PATH" >&2
  exit 2
fi

python3 - "${repo_root}" <<'PY'
"""Resolve every internal Markdown link (and its anchor) in a repository.

The anchor slug mirrors GitHub's heading slugger: lowercase, drop everything
that is not a letter/digit (Unicode-aware, so CJK survives), a hyphen or an
underscore, collapse whitespace to a single hyphen, and suffix duplicates with
-1, -2, ... Explicit <a id="..."> anchors are honoured too.

Reference-style links ([text][ref] + `[ref]: target`) are resolved as well, so
a definition is checked exactly like an inline target. Fenced code blocks,
inline code spans and HTML comments are stripped first, so an example link in
prose-style documentation is not mistaken for a real one.
"""
import os
import re
import sys
import urllib.parse

repo = os.path.abspath(sys.argv[1])

SKIP_DIRS = {".git", ".omo", "node_modules", ".astro"}
SKIP_REL_PREFIXES = ("docs/archive",)

EXTERNAL = re.compile(r"^(https?:|mailto:|tel:|data:|javascript:|ftp:|//)", re.I)
FENCE = re.compile(r"^\s{0,3}(```|~~~)")
INLINE_CODE = re.compile(r"`[^`]*`")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
LINK = re.compile(
    r"!?\[([^\]]*)\]\(\s*(<[^>]+>|[^()\s]+)(?:\s+[\"'][^\"']*[\"'])?\s*\)"
)
REF_DEF = re.compile(
    r"^\s{0,3}\[([^\]]+)\]:\s*(\S+)(?:\s+[\"'][^\"']*[\"'])?\s*$"
)
REF_USE = re.compile(r"!?\[([^\]]*)\]\[([^\]]*)\]")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")


def is_skipped(rel):
    parts = rel.split(os.sep)
    if any(p in SKIP_DIRS for p in parts):
        return True
    return any(rel == p or rel.startswith(p + os.sep) for p in SKIP_REL_PREFIXES)


def md_files():
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        relroot = os.path.relpath(root, repo)
        if relroot == ".":
            relroot = ""
        if relroot == "docs/archive" or relroot.startswith("docs/archive" + os.sep):
            dirs[:] = []
            continue
        for name in sorted(files):
            if name.endswith(".md"):
                rel = os.path.normpath(os.path.join(relroot, name))
                if not is_skipped(rel):
                    yield os.path.join(root, name), rel


def strip_noise(text):
    """Drop fenced code blocks, HTML comments and inline code spans."""
    kept = []
    fence = None
    for line in text.splitlines():
        if fence is None:
            if FENCE.match(line):
                fence = FENCE.match(line).group(1)
                continue
            kept.append(line)
        elif line.strip().startswith(fence):
            fence = None
    text = "\n".join(kept)
    text = HTML_COMMENT.sub("", text)
    text = INLINE_CODE.sub(" ", text)
    return text


def slugify(heading):
    s = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"`([^`]*)`", r"\1", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = s.replace("**", "").replace("__", "").replace("*", "")
    chars = []
    for ch in s.lower():
        if ch.isalnum() or ch in "-_":
            chars.append(ch)
        elif ch.isspace():
            chars.append(" ")
    return re.sub(r"\s+", "-", "".join(chars).strip())


_anchor_cache = {}


def anchors_for(path):
    if path not in _anchor_cache:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = strip_noise(fh.read())
        except OSError:
            _anchor_cache[path] = set()
            return _anchor_cache[path]
        anchors = set()
        counts = {}
        for line in text.splitlines():
            m = HEADING.match(line)
            if not m:
                continue
            slug = slugify(m.group(1))
            if not slug:
                continue
            if slug in counts:
                counts[slug] += 1
                anchors.add("{}-{}".format(slug, counts[slug]))
            else:
                counts[slug] = 0
                anchors.add(slug)
        for m in re.finditer(r"""<a\b[^>]*\bid=["']([^"']+)["']""", text):
            anchors.add(m.group(1))
        _anchor_cache[path] = anchors
    return _anchor_cache[path]


def resolve_target(source_path, target):
    target = target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    if not target or EXTERNAL.match(target):
        return None
    path_part, _, frag = target.partition("#")
    path_part = urllib.parse.unquote(path_part)
    frag = urllib.parse.unquote(frag)
    if path_part:
        if path_part.startswith("/"):
            resolved = os.path.normpath(os.path.join(repo, path_part.lstrip("/")))
        else:
            resolved = os.path.normpath(
                os.path.join(os.path.dirname(source_path), path_part)
            )
    else:
        resolved = source_path
    return target, resolved, frag


def main():
    files = list(md_files())
    broken = []
    internal_links = 0
    for path, rel in files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = strip_noise(fh.read())
        refdefs = {}
        for line in text.splitlines():
            m = REF_DEF.match(line)
            if m:
                refdefs[m.group(1).lower()] = m.group(2)
        targets = [m.group(2) for m in LINK.finditer(text)]
        for m in REF_USE.finditer(text):
            key = (m.group(2) or m.group(1)).lower()
            if key in refdefs:
                targets.append(refdefs[key])
        for target in targets:
            parsed = resolve_target(path, target)
            if parsed is None:
                continue
            target, resolved, frag = parsed
            internal_links += 1
            if not os.path.exists(resolved):
                broken.append("{}: missing target: {}".format(rel, target))
                continue
            if frag and (resolved == path or resolved.endswith(".md")):
                if frag not in anchors_for(resolved):
                    broken.append(
                        "{}: missing anchor '{}' -> {}".format(rel, frag, target)
                    )

    if broken:
        print("check-links: FAILED ({} broken link(s))".format(len(broken)))
        for line in broken:
            print("  " + line)
        return 1
    print(
        "check-links: OK ({} file(s), {} internal link(s) resolved)".format(
            len(files), internal_links
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
