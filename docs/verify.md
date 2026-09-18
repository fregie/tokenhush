# Verify redaction with a local echo upstream

This check proves the whole round trip without sending anything to a real
provider. You run a fake vendor that echoes request bodies, point a throwaway
gateway at it, send one request that carries a fake secret, and watch where the
secret does and does not appear.

You need Go 1.25+, plus `python3` and `curl`.

## 1. Run a fake vendor on 127.0.0.1:9999

In a first terminal, start the echo upstream:

```sh
python3 - <<'PY'
import http.server, sys
class Echo(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        sys.stderr.write("upstream received: " + body.decode() + "\n"); sys.stderr.flush()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
http.server.HTTPServer(("127.0.0.1", 9999), Echo).serve_forever()
PY
```

It prints every request body it receives to stderr. Leave it running.

## 2. Point a throwaway gateway at it

In a second terminal, create a throwaway `TOKENHUSH_HOME`, write a minimal
`tokenhush.yaml` that routes `/v1/chat/completions` to the echo upstream, and
start the gateway:

```sh
export TOKENHUSH_HOME="$(mktemp -d)"
mkdir -p "$TOKENHUSH_HOME/config"
cat > "$TOKENHUSH_HOME/config/tokenhush.yaml" <<'YAML'
listen:
  host: 127.0.0.1
  port: 8787
upstreams:
  - match: /v1/chat/completions
    target: http://127.0.0.1:9999
YAML
tokenhush run
```

Leave it running too. It prints one masked stderr line per redaction.

## 3. Send one request

In a third terminal, send a request whose body carries a fake secret:

```sh
curl -sS http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"echo","messages":[{"role":"user","content":"my email is me@example.com"}]}'
```

## What you should see

Before any request the gateway prints a startup banner: the loopback endpoint,
the effective upstream routing (configured entries plus the built-in fallbacks)
and the two base-URL forms to point a tool at. Nothing in it is secret. Then the
three observations below together prove the round trip.

**1. The upstream terminal printed the body with the secret replaced.** The
value left the gateway as a placeholder, so this is what the fake vendor
received:

```text
upstream received: {"model":"echo","messages":[{"role":"user","content":"my email is __PII_email_<digest>__"}]}
```

The `<digest>` is a per-session hash, so the exact value differs between runs.
The point is that the upstream never saw `me@example.com`.

**2. The gateway terminal printed two metadata-only lines.** The value it
changed is reported by type, length, and a masked form, never in full; the
return path reports only how many placeholders it restored:

```text
tokenhush: redacted request email (len=17) ****
tokenhush: restored response placeholders=1
```

**3. The `curl` output contains the original value again.** The response path
restored the session placeholder before the client saw the body:

```json
{"model":"echo","messages":[{"role":"user","content":"my email is me@example.com"}]}
```

The upstream never saw the secret; the client never saw the placeholder.

## Read the gateway like a script

With the gateway still running, query its metadata:

```sh
tokenhush status --json
```

The JSON document carries the ten frozen keys (`state`, `addrs`, `port`,
`uptime_ms`, `requests`, `redactions`, `content_policy_blocks`, `rule_blocks`,
`walk_skips`, `pack_serial`). After the single request above, `redactions` is
`1`:

```json
"redactions": 1
```

## The redaction log

The format is:

```text
tokenhush: redacted request <type> (len=<N>) <masked>
```

It goes to stderr only and is never persisted. `<masked>` is `****` for most
types. For the opaque credential types (`api_key`, `high_entropy`) it is a
bounded prefix and suffix instead, for example `sk-p…j0`. The masked form can
never equal the secret: a literal `****` renders as `[redacted]`.

The log is on by default. Silence it with `tokenhush run --log-redactions=false`.

## The restore log

Every client-bound response that restores at least one session placeholder emits
one count line:

```text
tokenhush: restored response placeholders=<N>
```

A buffered response emits one line with the total; a streaming (SSE) response
emits one line per restored placeholder. The line carries only a count, goes to
stderr only, and is never persisted. `tokenhush run --log-redactions=false`
silences it together with the redaction log.

## Why this proves it

The upstream is the stand-in for the model. It received only
`__PII_email_<digest>__`, so the secret never left the machine in a provider-bound
request. The client received `me@example.com` back, so the placeholder was
restored on the return path. And the outbound direction never backfills: the
gateway has the forward map (secret to placeholder) and no reverse map, so a
prompt-injection trick that asks the model to echo a secret cannot make the
gateway re-fill a placeholder on the way out. That is the round trip you just
watched: secret out of the body, placeholder upstream, original back to the
client.

## See also

- [tool-setup.md](tool-setup.md) for pointing a real tool at the gateway.
- [security.md](security.md) for the invariants this check exercises.
