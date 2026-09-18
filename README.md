# tokenhush

tokenhush is a local, loopback-only gateway that sits between your AI coding
tools and the vendor APIs they call. It replaces secrets it can detect in
outbound request bodies with session-scoped placeholders, and it restores the
original values in the responses on the way back. This repository is the
from-scratch **v0.5.0** rewrite of the tokenhush core.

- **No MITM, no root certificate.** tokenhush never terminates TLS and never
  installs a trust root. It is an HTTP forward proxy bound to `127.0.0.1`.
- **Metadata only on disk.** Request and response bodies, detected secrets and
  the placeholder-to-secret mapping are never persisted.
- **One extension point.** Every detector — the six built-ins, a signed remote
  rule pack, and a compile-time third-party rule set — is a `Rule` registered
  in `pkg/filter`.
- **The supply chain is preserved.** Signed rule sync and signed self-update
  keep the existing backend's byte format.

- [Quickstart](#quickstart)
- [The verify recipe (frozen)](#the-verify-recipe-frozen)
- [The seven commands](#the-seven-commands)
- [The four goals of the v0.5.0 rewrite](#the-four-goals-of-the-v050-rewrite)
- [What this does NOT do](#what-this-does-not-do)
- [Documentation](#documentation)

## Quickstart

Requires Go 1.25 or newer. The verify recipe below also uses `python3` for a
loopback echo upstream and `curl` as the client.

### 1. Build

```sh
go build -o tokenhush ./cmd/tokenhush
./tokenhush version
```

Install it on your `PATH` if you want the examples below to work verbatim:

```sh
go install ./cmd/tokenhush
```

### 2. Start a loopback echo upstream

This is the fake vendor: it logs the exact body it receives and echoes that body
straight back. Run it in a terminal of its own.

```sh
python3 - <<'PY'
import http.server, sys

class Echo(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        sys.stderr.write("upstream received: " + body.decode() + "\n")
        sys.stderr.flush()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

http.server.HTTPServer(("127.0.0.1", 9999), Echo).serve_forever()
PY
```

### 3. Run the gateway

The gateway reads `tokenhush.yaml` from the platform config directory
(`$XDG_CONFIG_HOME/tokenhush/tokenhush.yaml` on Linux) unless `--config` names a
file. Setting `TOKENHUSH_HOME` puts the config and the data directory under one
throwaway root, which keeps this walkthrough self-contained:

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

`tokenhush run` performs crash recovery, loads the config, builds the pipeline,
binds the loopback listener, writes the session files and then serves. A busy
port fails before anything is written.

### 4. Onboard a tool

`tokenhush env <tool>` prints the snippet that points a client at the gateway.
It supports fourteen tools; `claude`, `codex`, `aider`, `cline`, `roo`,
`opencode`, `qwen`, `crush`, `zed`, `continue`, `openwebui`, `goose`,
`openhands` and `kilo`.

```sh
tokenhush env claude     # export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"
tokenhush env codex      # a model_providers.tokenhush block for config.toml
tokenhush env opencode   # a provider block for opencode.json
```

Anthropic-style clients get the bare origin; OpenAI-compatible clients get the
`/v1` prefix. The snippet is plain text and can be pasted directly.

## The verify recipe (frozen)

Three details of this recipe are protected contracts: scripts and operators
observe them, so they do not change.

### The placeholder grammar

Every redacted value leaves as a placeholder:

```
__PII_<type>_<digest>__
```

`<type>` is a sanitized, length-capped category such as `email`, `jwt` or
`api_key`; `<digest>` is an opaque per-session hex digest that grows until it is
unique inside the session. The same secret always maps to the same placeholder
within a session, and a placeholder only ever restores to the secret it was
minted for. A placeholder the session never issued is returned unchanged and
never fabricated into a secret.

### The redaction log line

Every substitution prints one masked line to **stderr**:

```
tokenhush: redacted request <type> (len=<N>) <masked>
```

- it is never persisted — stderr only, and nothing about the request or the
  secret is written to disk;
- `<masked>` is `****` for most types and a bounded prefix/suffix for opaque
  credential types (`api_key`, `high_entropy`);
- the masked form can never equal the secret: the literal value `****` is
  rendered as `[redacted]`, so the fallback is a distinct string.

### The loopback echo-verify (runnable)

With the echo upstream from step 2 and the gateway from step 3 both running,
send a request whose content contains an email address:

```sh
curl -sS http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"echo","messages":[{"role":"user","content":"my email is alice@example.com"}]}'
```

Three observations prove the round trip. **The secret leaves as a placeholder** —
the echo upstream's terminal prints:

```
upstream received: {"model":"echo","messages":[{"role":"user","content":"my email is __PII_email_<digest>__"}]}
```

**The log line is masked and stderr-only** — the gateway's terminal prints:

```
tokenhush: redacted request email (len=17) ****
```

**The original returns to the client** — the `curl` output contains
`my email is alice@example.com` again, because the response path restored the
placeholder this session minted. The value returns with the correct content in
a valid JSON body: the restore re-spells the secret at the enclosing JSON depth
rather than splicing raw bytes. The upstream never saw the secret, and the
client never saw the placeholder.

Inspect the running gateway the same way a script would:

```sh
tokenhush status --json
```

The frozen ten-key document reports the session's metadata, including
`"redactions":1` for the request above.

## The seven commands

The CLI has exactly seven commands. Exit codes are frozen: `0` success, `1` a
failed check or operation, `2` a usage error.

| Command | What it does |
|---|---|
| `tokenhush run` | Starts the gateway. `--config PATH`, `--port N`, `--log-level LEVEL`, `--log-redactions` (default on). |
| `tokenhush rules` | `rules sync [--check]` verifies and activates the signed rule pack; `rules rollback` returns to a previously verified serial. `--check` writes no real state. |
| `tokenhush update` | Checks for and applies a signed binary update, honouring package-manager installs. `--check` reports without downloading, installing or writing anything. |
| `tokenhush status` | Reports the running gateway's metadata. `--json` prints the frozen document; a gateway that is not running prints `not running` and exits 1. |
| `tokenhush env <tool>` | Prints the onboarding snippet for one of fourteen tools, pointing it at the loopback gateway. |
| `tokenhush privacy` | Prints the egress disclosure: exactly two switchable vendor-bound categories with their switches, hosts and retention. `--json` for machines. |
| `tokenhush version` | Prints the version line (`v0.5.0`) and the build target. |

Switches that stop vendor-bound traffic before any request is made:

```sh
TOKENHUSH_NO_UPDATE_CHECK=1 tokenhush update   # prints "no request was sent"
TOKENHUSH_NO_RULE_SYNC=1 tokenhush rules sync  # prints "no request was sent"
```

## The four goals of the v0.5.0 rewrite

1. **Much lighter.** Keep only the non-negotiable invariants and the extension
   mechanism. The deleted subsystems — the change-channel guard, the outbound
   encoding re-check, key-position blocking, capability tiers, the keyring
   secret store, the license package, service stubs and the `doctor` check — are
   never re-created here.
2. **Filtering and replacement in one minimal, highly extensible framework.**
   `pkg/filter`'s `Rule` is the single extension point for built-ins, signed
   remote packs and third-party rules alike.
3. **The supply chain preserved.** Signed rule sync and signed self-update stay
   byte-compatible with the already-designed backend: same endpoints, domain
   tags, embedded key ids (`root-2026-09`, `rules-2026-09`), document schemas
   and floor behaviour.
4. **Lean, clearly layered, highly extensible.** Dependencies point one way
   only, and the allowed edges are enforced by a test, not by convention.

## What this does NOT do

- **No Pro contract.** This rewrite is a hard fork of the open core. The Pro
  repository keeps building against the legacy tree until it migrates
  separately; see [docs/PRO-MIGRATION.md](docs/PRO-MIGRATION.md).
- **No backward compatibility for config keys or flags.** The schema is strict
  and closed: an unknown key is an error, not a warning. The single deliberate
  compatibility path is that `pkg/filter` still decodes schema-v1 rule
  documents, because the backend signs them.
- **No TLS termination, no root certificate, no MITM.** The listener is
  loopback-only and refuses a non-loopback bind by construction.
- **No `doctor` command, no standalone `allowlist` command, no runtime plugin
  loading, no capability tiers.** The control surface is exactly `GET /status`.
- **No encoding normalization.** A secret that is base64-, hex- or URL-encoded
  before it leaves is not detected; a non-identity request `Content-Encoding` is
  refused with 415 rather than decoded for detection.
- **No object-key inspection.** A secret placed in a JSON object key rather
  than a value is forwarded unchanged.
- **No response-path redaction.** On the response path rules may only block or
  warn. A response-scoped block on an SSE stream cannot recall deltas already
  emitted.
- **No release, key ceremony or infrastructure change.** This tree builds and
  tests the client; it does not publish, re-sign or touch the backend.

## Documentation

- [docs/architecture.md](docs/architecture.md) — the layered dependency graph,
  the single rule abstraction, the two signing-input projections and the frozen
  byte surfaces.
- [docs/security.md](docs/security.md) — all eight invariants with their named
  tests, the direction contract, and the four residual risks recorded honestly.
- [docs/plugins.md](docs/plugins.md) — the extension point, a working
  third-party example, and what the core deliberately does not offer.
- [docs/PRO-MIGRATION.md](docs/PRO-MIGRATION.md) — the Pro repository's
  required, separate migration.
- [README.zh-CN.md](README.zh-CN.md) — the Simplified-Chinese mirror of this
  file.
