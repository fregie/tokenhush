# 用本地 echo 上游验证脱敏

**中文** | [English](verify.md)

这项检查无需向真实厂商发送任何内容，就能验证整个往返。你运行一个回显请求 body 的
假厂商，把一个一次性网关指向它，发送一个携带假密钥的请求，然后观察密钥在哪里出现、
在哪里不出现。

需要 Go 1.25+，以及 `python3` 和 `curl`。

## 1. 在 127.0.0.1:9999 上运行假厂商

在第一个终端里启动 echo 上游：

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

它把收到的每个请求 body 都打印到 stderr。让它保持运行。

## 2. 把一个一次性网关指向它

在第二个终端里创建一个一次性的 `TOKENHUSH_HOME`，写一个最小的 `tokenhush.yaml`，
把 `/v1/chat/completions` 路由到 echo 上游，然后启动网关：

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

同样让它保持运行。它每次脱敏都会打印一行掩码的 stderr 日志。

## 3. 发送一个请求

在第三个终端里发送一个请求，body 里带一个假密钥：

```sh
curl -sS http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"echo","messages":[{"role":"user","content":"my email is me@example.com"}]}'
```

## 你应该看到什么

任何请求之前，网关会打印一段启动横幅：回环端点、实际生效的上游路由（配置项加上
内置回退），以及把工具指过来所需的两种 base URL 形式。横幅里没有任何密钥。接下来
下面三项观察合在一起，就验证了整个往返。

**1. 上游终端打印出的 body 里，密钥已被替换。** 该值以占位符形式离开网关，所以这是
假厂商收到的东西：

```text
upstream received: {"model":"echo","messages":[{"role":"user","content":"my email is __PII_email_<digest>__"}]}
```

`<digest>` 是每次会话的哈希，所以具体值每次运行都不同。关键在于上游从未见到
`me@example.com`。

**2. 网关终端打印了两行只含元数据的日志。** 它改动的值按类型、长度和掩码形式报告，
绝不给出完整值；回程只报告还原了多少个占位符：

```text
tokenhush: redacted request email (len=17) ****
tokenhush: restored response placeholders=1
```

**3. `curl` 的输出里又是原始值。** 响应路径在客户端看到 body 之前还原了会话占位符：

```json
{"model":"echo","messages":[{"role":"user","content":"my email is me@example.com"}]}
```

上游从未见到密钥，客户端从未见到占位符。

## 像脚本一样读取网关

网关仍在运行时，查询它的元数据：

```sh
tokenhush status --json
```

这份 JSON 文档包含十个冻结的键（`state`、`addrs`、`port`、`uptime_ms`、`requests`、
`redactions`、`content_policy_blocks`、`rule_blocks`、`walk_skips`、`pack_serial`）。
发送上面那一个请求之后，`redactions` 是 `1`：

```json
"redactions": 1
```

## 脱敏日志

格式是：

```text
tokenhush: redacted request <type> (len=<N>) <masked>
```

它只写 stderr，永不落盘。多数类型的 `<masked>` 是 `****`。对于不透明凭据类型
（`api_key`、`high_entropy`），它是经过截断的前缀与后缀，例如 `sk-p…j0`。掩码形式
永远不会等于密钥：字面量 `****` 会渲染成 `[redacted]`。

该日志默认开启。用 `tokenhush run --log-redactions=false` 可以静默它。

## 还原日志

每一个还原了至少一个会话占位符、发回客户端的响应，都会输出一行计数日志：

```text
tokenhush: restored response placeholders=<N>
```

缓冲响应输出一行给出总数；流式（SSE）响应每还原一个占位符输出一行。该行只包含
计数，只写 stderr，永不落盘。`tokenhush run --log-redactions=false` 会把它和脱敏
日志一起静默。

## 为什么这能证明

上游是模型的替身。它只收到 `__PII_email_<digest>__`，所以密钥在发往厂商的请求里
从未离开本机。客户端又拿回了 `me@example.com`，说明占位符在回程上被还原。而且
出站方向永不回填：网关持有正向映射（密钥到占位符），没有反向映射，所以提示注入
试图让模型回显密钥时，无法让网关在出站路上重新填入占位符。这就是你刚刚看到的
往返：密钥离开 body、上游看到占位符、原值回到客户端。

## 另见

- [tool-setup.zh-CN.md](tool-setup.zh-CN.md)：把真实工具指向网关。
- [security.zh-CN.md](security.zh-CN.md)：这项检查所演练的不变量。
