# Verify redaction yourself

**English** | [中文](verify.zh-CN.md)

> Status: V1 (2026-09). Everything on this page runs on loopback; no real secret and no external service is involved.

Tokenhush's claim is narrow enough to check: before a request leaves your machine, detected secrets are already replaced with placeholders. This page proves it end to end with a **local echo upstream** (a small Python process that prints the body it receives). The echo process stands in for the cloud provider, so you can read exactly what a remote endpoint would have seen.

When it works you will see:

- the echo upstream prints a placeholder such as `__PII_api_key_...__`, never the raw key;
- the client response still contains the original value, because backfill runs only on the way back to your tool.

## 🎯 Prerequisites

- Go 1.25+ to build from source (or any installed `tokenhush` binary).
- `python3` (standard library only) and `curl`.
- A scratch directory. Every file lives there, and the commands point `TOKENHUSH_HOME` at it, so your real config and data are untouched. The built binary must live **outside** that home: `TOKENHUSH_HOME` refuses a path inside the executable's directory.

```bash
# From the repository root.
WORK="$(mktemp -d)"
mkdir -p "$WORK/bin" "$WORK/home"
go build -o "$WORK/bin/tokenhush" ./cmd/tokenhush
```

## ⌨️ Commands used on this page

```text
<!-- check-docs:commands:start -->
    tokenhush version      # confirm the binary runs
    tokenhush run          # start the gateway in the foreground
    tokenhush status       # confirm the gateway is running
<!-- check-docs:commands:end -->
```

## 🚀 1. Start the echo upstream

The block below writes the echo script to the scratch directory and starts it in the background. It prints each request body it receives and echoes the body back as JSON.

```bash
cat > "$WORK/echo_upstream.py" <<'PY'
"""Local echo upstream: print each request body and echo it back as JSON."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Echo(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        print("UPSTREAM-SAW " + body, flush=True)
        payload = json.dumps({"echo": body}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Echo).serve_forever()
PY

python3 "$WORK/echo_upstream.py" 9101 > "$WORK/upstream.log" 2>&1 &
UPSTREAM_PID=$!
```

## ⚙️ 2. Point a route at the echo upstream and start the gateway

`upstreams:` maps a host or path prefix to an upstream base URL. An explicit override wins over the built-in provider table, so the configuration below routes the ordinary `/v1/messages` path to the loopback echo instead of Anthropic:

<!-- check-docs:config:start -->
```yaml
listen:
  host: 127.0.0.1
  port: 8799
upstreams:
  /v1/messages: http://127.0.0.1:9101
```
<!-- check-docs:config:end -->

Write the same values to the scratch config, then start the gateway:

```bash
cat > "$WORK/home/tokenhush.yaml" <<'YAML'
listen:
  host: 127.0.0.1
  port: 8799
upstreams:
  /v1/messages: http://127.0.0.1:9101
YAML

export TOKENHUSH_HOME="$WORK/home"
"$WORK/bin/tokenhush" run --config "$TOKENHUSH_HOME/tokenhush.yaml" > "$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
```

`tokenhush run` prints the effective upstream route table and the listening address. Wait for it, then confirm the gateway answers:

```bash
for _ in $(seq 1 100); do
  grep -q "gateway listening" "$WORK/gateway.log" && break
  sleep 0.1
done
cat "$WORK/gateway.log"
"$WORK/bin/tokenhush" status
```

```text
tokenhush: upstream routes (a request path selects its upstream; config `upstreams:` overrides win):
tokenhush:   /v1/chat/completions       -> openai     https://api.openai.com
tokenhush:   ... (the effective route table; config `upstreams:` overrides win)
tokenhush: point a tool at the gateway, then run it:
tokenhush:   tokenhush env claude   # ANTHROPIC_BASE_URL=http://127.0.0.1:8799
tokenhush:   tokenhush env codex    # base_url=http://127.0.0.1:8799/v1
tokenhush:   tokenhush env <tool>   # claude, codex, aider, cline, roo, opencode, qwen, crush, zed, continue, openwebui, goose, openhands, kilo
tokenhush: gateway listening on http://127.0.0.1:8799
tokenhush: control token file: /tmp/.../home/control.token
tokenhush: gateway running
  pid: ...
  address: 127.0.0.1:8799, [::1]:8799
```

## ⌨️ 3. Send a request with a synthetic secret

The key below is invented for this page. Send it through the gateway:

```bash
curl -sS -H 'Content-Type: application/json' \
  -d '{"model":"demo","max_tokens":16,"messages":[{"role":"user","content":"Deploy with sk-proj-abc123def456ghi789"}]}' \
  http://127.0.0.1:8799/v1/messages
```

The client response still carries the original key: the echo returned the placeholder, and core backfill restored it on the way back to the client.

```json
{"echo": "{\"model\":\"demo\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"Deploy with sk-proj-abc123def456ghi789\"}]}"}
```

## 🔍 4. Read what the upstream received

```bash
cat "$WORK/upstream.log"
grep -c 'sk-proj-abc123def456ghi789' "$WORK/upstream.log"; echo "grep exit=$?"
```

The log line shows the placeholder; the grep prints `0` and exits `1`, meaning the raw key never reached the upstream:

```text
UPSTREAM-SAW {"model":"demo","max_tokens":16,"messages":[{"role":"user","content":"Deploy with __PII_api_key_b557d7e77dad__"}]}
0
grep exit=1
```

The suffix (`b557d7e77dad` above) is session-specific: it is derived per gateway run. What the upstream sees is a `__PII_...__` placeholder in place of the value.

## 🧹 5. Clean up

```bash
kill "$GATEWAY_PID" "$UPSTREAM_PID"
rm -rf "$WORK"
```

The demo touches nothing outside `$WORK`: the gateway's control token and config both lived in `$WORK/home`.

## 📌 What this does and does not prove

Proves: detected secrets are replaced before the body is forwarded; backfill runs only on the client-bound response; an `upstreams:` override can redirect a route and redaction still runs first.

Does not prove: perfect recall. Detection is deterministic and high-precision-first ([security.md](security.md)); a value that no detector recognises is forwarded unchanged. Nor does it prove that every encoded form of a known secret is caught: the outbound re-check that runs after redaction is a fixed decoder enumeration, and its known uncovered classes are published under [known limitations](security.md#known-limitations). The hard invariant this demo shows is one-way: **placeholders are never backfilled outbound** ([security.md](security.md#hard-invariants)).

## 📚 Related

- [tool-setup.md](tool-setup.md): `upstreams:` and the full `tokenhush.yaml` reference
- [security.md](security.md): threat model and hard invariants
- [architecture.md](architecture.md): request path and modules
