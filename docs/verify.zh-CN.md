# 自己验证脱敏

[English](verify.md) | **中文**

> 状态：V1（2026-09）。本页所有命令都只在环回地址上运行；不需要任何真实密钥，也不访问外部服务。

Tokenhush 的说法很窄，因此可以自己检查：请求离开你的机器之前，检测到的密钥已经替换为占位符。本页用一个**本机回显上游**（一个很小的 Python 进程，会打印收到的请求体）端到端证明这一点。这个回显进程充当云侧服务，你可以直接读到远端本会看到的内容。

成功时你会看到：

- 回显上游打印的是 `__PII_api_key_...__` 这样的占位符，而不是密钥原文；
- 客户端响应里仍带着原值，因为回填只在返回工具的入站方向发生。

## 前置条件

- Go 1.25+（从源码构建），或任意已安装的 `tokenhush` 二进制。
- `python3`（仅标准库）和 `curl`。
- 一个临时目录。所有文件都放在那里，命令把 `TOKENHUSH_HOME` 指向它，因此不会碰你的真实配置与数据。**注意**：构建出的二进制不能放在该目录内，因为 `TOKENHUSH_HOME` 会拒绝可执行文件目录内部的路径。

```bash
# 在仓库根目录执行。
WORK="$(mktemp -d)"
mkdir -p "$WORK/bin" "$WORK/home"
go build -o "$WORK/bin/tokenhush" ./cmd/tokenhush
```

## 本页用到的命令

```text
<!-- check-docs:commands:start -->
    tokenhush version      # 确认二进制可运行
    tokenhush run          # 在前台启动网关
    tokenhush status       # 确认网关正在运行
<!-- check-docs:commands:end -->
```

## 1. 启动回显上游

下面的代码块把回显脚本写入临时目录并在后台启动它。它会把收到的每个请求体打印出来，并把请求体以 JSON 形式回显。

```bash
cat > "$WORK/echo_upstream.py" <<'PY'
"""本机回显上游：打印每个请求体，并把请求体以 JSON 回显。"""
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

## 2. 把一条路由指向回显上游并启动网关

`upstreams:` 把主机名或路径前缀映射到上游 base URL。显式覆盖优先于内置服务商路由表，因此下面的配置会把常规的 `/v1/messages` 路径改派到本机回显，而不是 Anthropic：

<!-- check-docs:config:start -->
```yaml
listen:
  host: 127.0.0.1
  port: 8799
upstreams:
  /v1/messages: http://127.0.0.1:9101
```
<!-- check-docs:config:end -->

把同样的内容写入临时配置，然后启动网关：

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

`tokenhush run` 会打印监听地址。等它就绪，再确认网关可以应答：

```bash
for _ in $(seq 1 100); do
  grep -q "gateway listening" "$WORK/gateway.log" && break
  sleep 0.1
done
cat "$WORK/gateway.log"
"$WORK/bin/tokenhush" status
```

```text
tokenhush: gateway listening on http://127.0.0.1:8799
tokenhush: control token file: /tmp/.../home/control.token
tokenhush: gateway running
  pid: ...
  address: 127.0.0.1:8799, [::1]:8799
```

## 3. 发送一个带合成密钥的请求

下面的密钥是为本页虚构的。把它经网关发出：

```bash
curl -sS -H 'Content-Type: application/json' \
  -d '{"model":"demo","max_tokens":16,"messages":[{"role":"user","content":"Deploy with sk-proj-abc123def456ghi789"}]}' \
  http://127.0.0.1:8799/v1/messages
```

客户端响应里仍然带着原密钥：回显返回的是占位符，核心在返回客户端的入站方向把它还原了。

```json
{"echo": "{\"model\":\"demo\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"Deploy with sk-proj-abc123def456ghi789\"}]}"}
```

## 4. 查看上游实际收到了什么

```bash
cat "$WORK/upstream.log"
grep -c 'sk-proj-abc123def456ghi789' "$WORK/upstream.log"; echo "grep exit=$?"
```

日志行里是占位符；grep 打印 `0` 并以退出码 `1` 结束，说明原文从未到达上游：

```text
UPSTREAM-SAW {"model":"demo","max_tokens":16,"messages":[{"role":"user","content":"Deploy with __PII_api_key_b557d7e77dad__"}]}
0
grep exit=1
```

后缀（上例中的 `b557d7e77dad`）随会话变化：它按每次网关运行派生。上游看到的是替代原值的 `__PII_...__` 占位符。

## 5. 清理

```bash
kill "$GATEWAY_PID" "$UPSTREAM_PID"
rm -rf "$WORK"
```

该演示不会触碰 `$WORK` 之外的任何东西：网关的控制 token 与配置都在 `$WORK/home` 里。

## 这证明了什么、没证明什么

证明了：检测到的密钥在请求体转发之前就被替换；回填只发生在返回客户端的入站响应上；`upstreams:` 覆盖可以改派路由，且脱敏仍然先执行。

没有证明：完美的召回率。检测器是确定性的、高精度优先（见 [security.zh-CN.md](security.zh-CN.md)）；任何检测器都不认识的取值会原样转发。本演示展示的硬性不变量是单向的：**占位符绝不向出站方向回填**（[security.zh-CN.md](security.zh-CN.md#硬不变量)）。

## 相关文档

- [configuration.zh-CN.md](configuration.zh-CN.md)：`upstreams:` 与完整 `tokenhush.yaml` 参考
- [security.zh-CN.md](security.zh-CN.md)：威胁模型与硬性不变量
- [architecture.zh-CN.md](architecture.zh-CN.md)：请求路径与模块
