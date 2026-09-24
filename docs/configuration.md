# Configuration

**English** | [中文](configuration.zh-CN.md)

Tokenhush reads exactly one configuration file, `tokenhush.yaml`. The schema is
strict and closed: a missing file means the built-in defaults, and an unknown
key is an error rather than a warning. A typo in a security-relevant setting (a
detector switch, the listen address) fails loudly instead of silently falling
back to a permissive default.

Most users never touch the file. You only need it to do two things: route
requests to a provider that is not OpenAI or Anthropic (a relay, a self-hosted
endpoint, a gateway), and tune a detector switch or a size limit. Routing is the
part worth reading carefully; jump to
[Routing requests to upstreams](#routing-requests-to-upstreams).

## Where the file lives

Tokenhush separates its configuration directory from its data directory:

| Platform | Config dir | Data dir |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/config/` | `~/Library/Application Support/tokenhush/Data/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LocalAppData%\tokenhush\` |

Put `tokenhush.yaml` in the config directory. `TOKENHUSH_HOME` moves both
directories under one root: config at `<TOKENHUSH_HOME>/config` and data at
`<TOKENHUSH_HOME>/data` (an empty value counts as unset).

To read a specific file instead, pass `--config PATH` to `tokenhush run` or
`tokenhush env`. The file is optional: when it is absent, the defaults below
apply.

## The whole surface

Every key the schema defines, shown at its default:

```yaml
listen:            {host: 127.0.0.1, port: 8787}
log:               {level: info}
detectors:         {prefix: true, email: true, luhn: true, jwt: true, pem: true, entropy: false}
allowlist:         ["literal"]
upstreams:         [{match: "/v1/chat/completions", target: "https://api.openai.com"}]
scan_budget_bytes: 33554432
detector_timeout:  30s
max_body_bytes:    67108864
response_buffer_bytes: 33554432
response_timeout:  5m
```

That is the complete surface. Any other top-level key is a schema error, not a
warning.

## Configuration reference

| Key | Type | Default | What it does |
|---|---|---|---|
| `listen.host` | string | `127.0.0.1` | Only `127.0.0.1`, `::1`, or `localhost`. `0.0.0.0` is rejected. |
| `listen.port` | integer | `8787` | 1..65535. |
| `log.level` | string | `info` | One of `debug`, `info`, `warn`, `error`. |
| `detectors.prefix` | boolean | `true` | Known key shapes: `sk-`, `AKIA`, `ghp_`, `glpat-`, `xox*`, `AIza`, `npm_`. |
| `detectors.email` | boolean | `true` | Email addresses; a match requires a domain that ends at a label boundary with a known public suffix. |
| `detectors.luhn` | boolean | `true` | Card numbers, Luhn-checked. |
| `detectors.jwt` | boolean | `true` | JSON Web Tokens. |
| `detectors.pem` | boolean | `true` | PEM private-key headers. |
| `detectors.entropy` | boolean | `false` | High-entropy strings. Off by default and opt-in: false positives on real agent traffic (long tool names, session ids) broke function calling. |
| `allowlist` | list of strings | empty | Literals that are never redacted. |
| `upstreams` | list of `{match, target}` | empty | Path-prefix routes to your own origins. See [Routing requests to upstreams](#routing-requests-to-upstreams). |
| `scan_budget_bytes` | integer | `33554432` (32 MiB) | Per-leaf, per-detector scan budget: a primitive detector inspects at most this many bytes of one leaf. |
| `detector_timeout` | duration | `30s` | Detection backstop. |
| `max_body_bytes` | integer | `67108864` (64 MiB) | Memory guard on the total request body. A body over it is refused with 403 `body_too_large` at the shared read seam before any walk, and is never truncated or partially forwarded. |
| `response_buffer_bytes` | integer | `33554432` (32 MiB) | Total cap on one buffered response. An over-cap response is a 502 before any byte is committed. |
| `response_timeout` | duration | `5m` | Overall bound on reading one response. A response past the deadline is a 504 before any byte is committed. If the cap and the deadline trip together, the cap wins. |

The detector keys are exactly `prefix`, `email`, `luhn`, `jwt`, `pem`, and
`entropy`. They are not `prefixes`, not `high_entropy`, and not `private_keys`:
an unknown detector name is a schema error. Every numeric key
(`scan_budget_bytes`, `detector_timeout`, `max_body_bytes`,
`response_buffer_bytes`, `response_timeout`) must be positive.

The `email` detector matches precisely: an address is a match only when its
domain ends at a label boundary with a known public suffix (`.com`, `.co.uk`),
so subdomains count and a look-alike such as `evilcorp.com` is rejected when the
configured suffix is the narrower `.corp.com` in `replace` mode (an additive
`.corp.com` still carries the built-in `.com`, so `evilcorp.com` would match).
The built-in suffix table is compiled in, frozen, and always on.

## Routing requests to upstreams

This is the section to read if you use a relay, a self-hosted endpoint, or any
provider other than OpenAI or Anthropic. Without it, the gateway forwards by its
built-in table, which knows only the two vendors.

### How routing works

Routing is by **request path**, not by provider name or by model. For every
request the gateway reads the inbound path, picks the matching upstream, joins
the request path onto that upstream's base, and dials it exactly once.

Because the path — not the model — chooses the upstream, one upstream can serve
many models: the model is selected by the request body, and a relay that fronts
many models behind `/v1` needs a single entry.

### Declaring an upstream

`upstreams` is a **list** of `{match, target}` entries, not a map. Each entry has
exactly two keys:

- `match` — the inbound request-path prefix this entry routes.
- `target` — the upstream base the request is forwarded to.

Both keys must be set; a blank `match` or `target` fails configuration load. A
`target` must be an absolute `http` or `https` URL with a host and **no**
userinfo, query, or fragment; a malformed `target` is refused before it can
become a live route.

The smallest useful entry, routing every OpenAI-style path to a relay:

```yaml
upstreams:
  - match: /v1
    target: https://your-relay.example.com
```

### How the request path is joined

The gateway appends the inbound request path (and its query string) to `target`,
joining the two with exactly one slash:

- `match: /v1` + `target: https://relay.example.com` + request
  `/v1/chat/completions` → `https://relay.example.com/v1/chat/completions`.
- A path prefix on `target` is kept: `target: https://host/openai` + request
  `/v1/chat/completions` → `https://host/openai/v1/chat/completions`.

This is why `target` is the provider **origin plus any prefix that comes before
`/v1`**, with **no `/v1`** and no trailing slash. Your tool already sends
`/v1/...`; the gateway appends it. If the real endpoint is
`https://host/openai/v1/chat/completions`, set `target: https://host/openai`.

### Match rules and precedence

A configured `match` routes a request when:

- the path is exactly the match, or
- the path is below the match on a **path-segment boundary** — `/v1/chat`
  matches `/v1/chat/completions` but not `/v1/chatX`, or
- the match is `/`, the explicit catch-all.

Among all configured entries that match, the **longest `match` wins**; if two
entries have matches of the same length, the lexicographically smaller one wins,
so the choice is deterministic. A configured entry always wins over the built-in
table.

Paths are matched case-sensitively, and nothing else is normalised: case, `.`
and `..`, and percent-escapes are never folded. A near-miss such as `/v1/model`,
`/v1/models/foo`, or `/v1/chat/completionsX` is a typed `no upstream for request
path` error, never a silent misroute to a neighbouring provider.

### The built-in routing table

When no configured entry matches, the built-ins apply. Built-in entries are
**exact paths**; a configured `match` is a prefix. The full table:

| Request path | Upstream |
|---|---|
| `/v1/audio/speech` | OpenAI |
| `/v1/audio/transcriptions` | OpenAI |
| `/v1/audio/translations` | OpenAI |
| `/v1/chat/completions` | OpenAI |
| `/v1/completions` | OpenAI |
| `/v1/embeddings` | OpenAI |
| `/v1/images/edits` | OpenAI |
| `/v1/images/generations` | OpenAI |
| `/v1/moderations` | OpenAI |
| `/v1/responses` | OpenAI |
| `/v1/messages` | Anthropic |
| `/v1/messages/batches` | Anthropic |
| `/v1/messages/count_tokens` | Anthropic |
| `GET /v1/models` | answered by the gateway itself |
| any other path | explicit error |

OpenAI is `https://api.openai.com` and Anthropic is `https://api.anthropic.com`.

`GET /v1/models` is the one named exception: both vendors serve it with the same
meaning, so the gateway answers model discovery itself and dials no upstream.
Every other unknown path is an explicit error, never a silent misroute.

### Worked examples

**Direct to OpenAI or Anthropic.** No `upstreams` needed; the built-in table
applies.

**A relay that fronts everything under `/v1`.**

```yaml
upstreams:
  - match: /v1
    target: https://relay.example.com
```

**A self-hosted OpenAI-compatible endpoint for chat only**, leaving the
Anthropic built-ins untouched:

```yaml
upstreams:
  - match: /v1/chat/completions
    target: http://127.0.0.1:8000
```

**Split routing.** Send one path family to a local server and everything else
under `/v1` to a relay. The longest match wins, so the specific entry takes its
path and `/v1` catches the rest:

```yaml
upstreams:
  - match: /v1/chat/completions
    target: http://127.0.0.1:8000
  - match: /v1
    target: https://relay.example.com
```

**An endpoint whose base sits under a path prefix.** For
`https://host/openai/v1/chat/completions`, set the target to the part before
`/v1`:

```yaml
upstreams:
  - match: /v1
    target: https://host/openai
```

### Troubleshooting routing

- **Requests reach the wrong provider.** With no `upstreams`, unmatched paths
  use the built-ins. Set `upstreams` before pointing a relay at the gateway.
- **A doubled `/v1` (`/v1/v1/...`).** `target` must not include `/v1`; the tool
  already sends it.
- **`upstreams` looks ignored.** It must be a list, not a YAML mapping; a
  mapping fails the closed schema.
- **A blank `match` or `target`.** Rejected at load.
- **`no upstream for request path`.** The path matched neither a configured
  entry nor the built-in table. Add an entry, or check for a typo or an extra
  segment (built-in paths are exact, not prefixes).
- **Port mismatch.** If you moved the gateway with `--port` or `listen.port`,
  point the tool at the same port.

### Authentication headers

The gateway forwards auth headers byte-for-byte and never parses them; only the
request **body** is transformed. Keep your provider's API key in the tool's own
config.

## Request and response limits

Every upstream response is buffered **whole** before any byte reaches the
client, including `text/event-stream`: there is no token-level streaming. A
response-scoped `Block` on the buffered response, SSE included, is a 502 before
any byte is committed, and backfill restores a content-split placeholder exactly
once before that single commit. `response_buffer_bytes` and `response_timeout`
bound the buffered body and the whole read; over the cap is a 502, past the
deadline is a 504, and both are decided before commit.

On the request side, `max_body_bytes` guards the total body before any walk or
upstream dial, and `scan_budget_bytes` and `detector_timeout` bound each
detector pass.

## See also

- [tool-setup.md](tool-setup.md) for pointing each of the 14 tools at the
  gateway.
- [verify.md](verify.md) for the local echo-upstream round-trip check.
- [security.md](security.md) for the security model behind the loopback bind.
