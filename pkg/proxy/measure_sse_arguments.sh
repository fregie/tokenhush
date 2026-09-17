#!/usr/bin/env bash
#
# measure_sse_arguments.sh — report the size distribution of streamed
# tool-call `arguments` payloads seen in an SSE (text/event-stream) capture, so
# the `SSEGuardCap` (192 KiB, see sseguard.go) can later be revisited with data
# instead of guesswork.
#
# This is a measurement only: it changes no cap, no configuration and no code.
#
# Usage:
#   pkg/proxy/measure_sse_arguments.sh FILE [CAP_BYTES]
#   cat capture.sse | pkg/proxy/measure_sse_arguments.sh -
#
# FILE is an SSE capture as written to the wire (one or more `data: <json>`
# lines). CAP_BYTES defaults to 196608 (192 KiB), the current SSEGuardCap.
#
# It accumulates, per (stream, tool-call) identity:
#   - OpenAI  : choices[i].delta.tool_calls[j].function.arguments
#   - Anthropic: content_block_delta with delta.type == input_json_delta
#               (delta.partial_json)
# and prints the count, min/p50/p90/p99/max accumulated sizes, and how many tool
# calls would exceed CAP_BYTES. A capture is the instrument; a real decision
# needs captures from real streams.
set -euo pipefail

file="${1:--}"
cap="${2:-196608}"
if [ "$file" = "-" ]; then
	file="/dev/stdin"
fi
if [ ! -r "$file" ]; then
	echo "measure_sse_arguments: cannot read $file" >&2
	exit 2
fi

python3 - "$file" "$cap" <<'PY'
import json
import math
import sys

path, cap = sys.argv[1], int(sys.argv[2])


def sizes(capture):
    """Return accumulated argument bytes per tool-call identity."""
    acc = {}
    for raw in capture.splitlines():
        line = raw.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue
        for choice in event.get("choices") or []:
            delta = choice.get("delta") or {}
            idx = choice.get("index", 0)
            for call in delta.get("tool_calls") or []:
                fn = call.get("function") or {}
                text = fn.get("arguments")
                if isinstance(text, str):
                    key = ("openai", idx, call.get("index", 0), call.get("id", ""))
                    acc[key] = acc.get(key, 0) + len(text.encode("utf-8"))
        delta = event.get("delta") or {}
        if delta.get("type") == "input_json_delta" and isinstance(delta.get("partial_json"), str):
            key = ("anthropic", event.get("index", 0))
            acc[key] = acc.get(key, 0) + len(delta["partial_json"].encode("utf-8"))
    return sorted(acc.values())


with open(path, "r", encoding="utf-8", errors="replace") as fh:
    capture = fh.read()

values = sizes(capture)
if not values:
    print("measure_sse_arguments: no tool-call arguments found in %s" % path)
    sys.exit(0)


def pct(q):
    # Nearest-rank percentile; deterministic and needs no numpy.
    i = max(0, min(len(values) - 1, math.ceil(q * len(values)) - 1))
    return values[i]


over = sum(1 for v in values if v > cap)
print("SSE tool-call arguments size distribution (%d call(s), cap=%d bytes)" % (len(values), cap))
print("  min=%d  p50=%d  p90=%d  p99=%d  max=%d" % (values[0], pct(0.50), pct(0.90), pct(0.99), values[-1]))
print("  over_cap=%d (%.1f%%)" % (over, 100.0 * over / len(values)))
PY
