# Tokenhush 开源版自测指南（OSS self-test guide）

> 适用：公开核心 `tokenhush`（Apache-2.0）。本页每条命令都在你自己的机器上运行，只连回环地址；
> 除 [`tokenhush privacy`](#4-验收清单五条) 列出的两个可关外发类别外，核心不连外网。
> 措辞约定：Tokenhush 提供的是**高置信拦截**，不是"绝不泄露"；没有检测器命中的内容会原样转发。

## 📌 TL;DR (English)

Build with `CGO_ENABLED=0 go build -o bin/tokenhush ./cmd/tokenhush`, run `tokenhush run`,
point any supported tool's base URL at `http://127.0.0.1:8787`, then run the five acceptance
checks in [§4](#4-验收清单五条). [§3](#3-端到端脱敏冒烟本地假上游) shows a loopback echo
upstream so you can read byte-for-byte what leaves and what comes back. The core stores no
request or response content, and placeholders are never backfilled on the way out.

## 📦 1. 从源码构建 / 安装

需要 Go 1.25 或更高版本。

```bash
CGO_ENABLED=0 go build -o bin/tokenhush ./cmd/tokenhush
./bin/tokenhush version
```

或者不落地直接安装：

```bash
go install github.com/fregie/tokenhush/cmd/tokenhush@latest
```

安装渠道（brew / scoop / install.sh / install.ps1）见 [README.md](../README.md#quick-start-5-minutes)。

推荐用一个临时目录当数据根，既不污染真实配置，也让下面的清理一步到位。注意二进制要放在
`TOKENHUSH_HOME` **之外**（`TOKENHUSH_HOME` 会拒绝位于可执行文件目录内的路径）：

```bash
WORK="$(mktemp -d)"
mkdir -p "$WORK/bin" "$WORK/home"
CGO_ENABLED=0 go build -o "$WORK/bin/tokenhush" ./cmd/tokenhush
export TOKENHUSH_HOME="$WORK/home"        # 配置与数据都落在这里
BIN="$WORK/bin/tokenhush"
```

## 🧩 2. 把 tokenhush 接到一个真实 AI 工具（最短步骤）

1. 在一个终端里前台启动网关，并确认它在跑：

```text
<!-- check-docs:commands:start -->
    tokenhush run          # 前台启动，默认监听 127.0.0.1:8787
    tokenhush status       # 确认网关正在运行
    tokenhush env claude   # 打印可直接粘贴的接入片段
<!-- check-docs:commands:end -->
```

2. 在另一个终端里把工具指向网关。以 Claude Code 为例：

```bash
eval "$(tokenhush env claude)"    # 设置 ANTHROPIC_BASE_URL
claude
```

`tokenhush env <tool>` 覆盖 14 个工具：`claude`、`codex`、`aider`、`cline`、`roo`、`opencode`、
`qwen`、`crush`、`zed`、`continue`、`openwebui`、`goose`、`openhands`、`kilo`。约定：
**Anthropic 客户端用裸 origin**（`http://127.0.0.1:8787`），**OpenAI 兼容客户端用 `/v1`**
（`http://127.0.0.1:8787/v1`）。逐工具说明见 [tool-setup.md](tool-setup.md)。

3. 跑自检：

```text
<!-- check-docs:commands:start -->
    tokenhush doctor       # 配置/目录/密钥后端/回环/端口 检查
    tokenhush privacy      # 查看仅有的两类外发
    tokenhush version
<!-- check-docs:commands:end -->
```

如果你要把某条路由指到自己的上游（例如一个本地 OpenAI 兼容服务），在 `tokenhush.yaml` 里覆盖它：

<!-- check-docs:config:start -->
```yaml
listen:
  host: 127.0.0.1
  port: 8787
upstreams:
  /v1/chat/completions: https://api.openai.com
```
<!-- check-docs:config:end -->

未匹配的路由回退内置规则（`/v1/messages` → Anthropic，`/v1/chat/completions`、`/v1/responses`
→ OpenAI）；唯一的**具名例外**是 `GET /v1/models`，其余未知路径明确报错，绝不静默错路由。

## 🔍 3. 端到端脱敏冒烟（本地假上游）

用一个本地回显上游（`python3` 标准库）冒充云端，读它到底收到了什么。以下命令全部只连回环。

```bash
# 3.1 回显上游：把收到的请求体打进日志，并原样作为 JSON 回显
cat > "$WORK/echo_upstream.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class Echo(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
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

# 3.2 把 /v1/messages 指到回显上游，前台网关后台化
cat > "$TOKENHUSH_HOME/tokenhush.yaml" <<'YAML'
listen:
  host: 127.0.0.1
  port: 8799
upstreams:
  /v1/messages: http://127.0.0.1:9101
YAML
"$BIN" run --config "$TOKENHUSH_HOME/tokenhush.yaml" > "$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
for _ in $(seq 1 100); do grep -q "gateway listening" "$WORK/gateway.log" && break; sleep 0.1; done
cat "$WORK/gateway.log"

# 3.3 发一个含伪造密钥的请求
SECRET="sk-proj-abc123def456ghi789"
REQ1="{\"model\":\"demo\",\"messages\":[{\"role\":\"user\",\"content\":\"Deploy with $SECRET\"}]}"
curl -sS -H 'Content-Type: application/json' -d "$REQ1" http://127.0.0.1:8799/v1/messages
echo

# 3.4 读上游日志，并做断言
cat "$WORK/upstream.log"
grep -c "$SECRET" "$WORK/upstream.log";  echo "raw-key grep exit=$?   # 1 = 上游从未见到原始密钥（期望）"
PLACEHOLDER=$(grep -oE '__PII_[a-z_]+_[0-9a-f]+__' "$WORK/upstream.log" | head -1)
echo "placeholder=$PLACEHOLDER"

# 3.5 出站绝不回填：把占位符当内容再发一次，上游应收到占位符字面量而非原文
REQ2="{\"model\":\"demo\",\"messages\":[{\"role\":\"user\",\"content\":\"Replay $PLACEHOLDER\"}]}"
curl -sS -H 'Content-Type: application/json' -d "$REQ2" http://127.0.0.1:8799/v1/messages
echo
grep -c "$SECRET" "$WORK/upstream.log"; echo "raw-key grep exit=$?   # 仍为 1：出站从未回填（期望）"

# 3.6 收尾
kill "$GATEWAY_PID" "$UPSTREAM_PID"
```

一次实测输出（占位符后缀随会话不同）：

```text
tokenhush: upstream routes (a request path selects its upstream; config `upstreams:` overrides win):
tokenhush:   /v1/chat/completions       -> openai     https://api.openai.com
tokenhush:   ... (the effective route table; config `upstreams:` overrides win)
tokenhush: point a tool at the gateway, then run it:
tokenhush:   tokenhush env claude   # ANTHROPIC_BASE_URL=http://127.0.0.1:8799
tokenhush:   tokenhush env codex    # base_url=http://127.0.0.1:8799/v1
tokenhush:   tokenhush env <tool>   # claude, codex, aider, cline, roo, opencode, qwen, crush, zed, continue, openwebui, goose, openhands, kilo
tokenhush: gateway listening on http://127.0.0.1:8799
tokenhush: control token file: .../home/control.token
{"echo": "{\"model\":\"demo\",\"messages\":[{\"role\":\"user\",\"content\":\"Deploy with sk-proj-abc123def456ghi789\"}]}\n"}
UPSTREAM-SAW {"model":"demo","messages":[{"role":"user","content":"Deploy with __PII_api_key_096a96e592f0__"}]}
0
raw-key grep exit=1
placeholder=__PII_api_key_096a96e592f0__
{"echo": "{\"model\":\"demo\",\"messages\":[{\"role\":\"user\",\"content\":\"Replay literal sk-proj-abc123def456ghi789 please\"}]}\n"}
0
raw-key grep exit=1
```

结论：**上游只见到占位符**；**客户端拿回原文**（回填只发生在回客户端的响应方向）；
**把本会话占位符当内容再发出时，上游仍收到占位符字面量** —— 出站方向绝不回填，
提示注入无法把它变成外泄通道。

## ✅ 4. 验收清单（五条）

| # | 验收项 | 怎么验 | 通过标准 |
|---|---|---|---|
| 1 | **脱敏生效** | §3.4：对 `$WORK/upstream.log` 跑 `grep -c "$SECRET"` | 输出 `0`（退出码 `1`），且日志里出现 `__PII_...__` 占位符 |
| 2 | **回填正确 + 出站不回填** | §3.3 客户端响应含原始密钥；§3.5 重放占位符后上游仍只含占位符 | 客户端拿到原文；上游始终无原始密钥 |
| 3 | **审计接缝（仅元数据）** | §3 跑完后 `grep -rn "$SECRET" "$TOKENHUSH_HOME"` 与 `grep -rn '__PII_' "$TOKENHUSH_HOME"` | 都无命中；数据根只含会话元数据（运行中：`run.json`、`control.token`；干净退出后删除）。核心 `pkg/audit` 是 no-op 接缝，只定义**仅元数据**的记录契约，不落任何正文 |
| 4 | **`privacy` 两项外发，均 active** | `"$BIN" privacy --json` | 正好两项：`update-check`、`rule-sync`，`status` 均为 `active`，且与 [`egress.yaml`](../egress.yaml) 和 [generated/network-egress.md](generated/network-egress.md) 逐字段一致；各带关闭开关（`TOKENHUSH_NO_UPDATE_CHECK=1` / `TOKENHUSH_NO_RULE_SYNC=1`） |
| 5 | **`doctor` 通过** | 用一个空闲端口跑 `"$BIN" doctor --config <config>` | 退出码 `0`（无 failure）。工具未接入带来的 `warn` 不阻塞；`secret-store` 落到 `file-plaintext` 才算 failure |

补充（可选，用于验证"命令零外发"）：`TOKENHUSH_NO_UPDATE_CHECK=1 strace -f -e trace=network "$BIN" update --check`
应显示 **0 个网络系统调用**；不设开关时才会连 `updates.tokenhush.com:443`。`rules sync --check`
同理受 `TOKENHUSH_NO_RULE_SYNC=1` 控制。

## 🛠️ 5. 常见问题与排查

- **`doctor` 报 `port ... already in use`（fail）**：默认 8787 被别的进程占了。用 `--port` 换一个空闲端口，
  或在 `tokenhush.yaml` 改 `listen.port`，再 `tokenhush doctor --config <file>`。
- **`doctor` 报 `secret-store ... plaintext`（fail）**：说明回退到了明文文件后端，核心会显式失败而不是静默降级。
  启用系统钥匙串（macOS Keychain / Windows Credential Manager / gnome-keyring 或 KWallet）后重试。
  非明文回退（如 `file-encrypted`）是 `ok`，会在消息里标注"degraded fallback"。
- **工具装了但没走网关**：`doctor` 会对检测到的工具给出 `warn` 与 fix 行，照它给的 `tokenhush env <tool>` 配置即可。
- **输出里偶尔看到 `__PII_...__`**：映射只在内存、随会话生命周期存在；重启网关后旧占位符无法还原，这是**安全降级**，不是泄露。
- **本地代理拦截了回环请求**：若设置了 `HTTP(S)_PROXY`，把 `127.0.0.1,localhost,::1` 加进 `NO_PROXY`（`doctor` 的 `proxy-env` 会提示）。
- **`tokenhush update --check` 报 `got 404`**：在线更新内容（manifest）由发布流程产出；未发布时读取面返回 404，
  命令会**干净报错**（非 self-managed 的 brew/scoop/unknown 安装则根本不联网，只打印升级指引或交给包管理器）。
- **`tokenhush rules sync --check` 报错或回退**：未发布或校验失败时回退内置默认并告警，`--check` **不写盘**；
  用 `TOKENHUSH_NO_RULE_SYNC=1` 可完全关闭该命令的联网。
- **macOS 首次启动被 Gatekeeper 拦下**：右键打开一次，或 `xattr -dr com.apple.quarantine "$(command -v tokenhush)"`。
- **`tokenhush run` 是前台进程**：用系统自带方式常驻（macOS launchd / Linux systemd user unit / Windows 任务计划程序）。

## 📌 6. 局限与诚实边界

- 覆盖的是 **base-URL 代理**：把工具指向网关即可生效。**未覆盖** Cursor 代理流量、ChatGPT/Claude 桌面应用、
  浏览器 Web UI —— 它们需要系统级 MITM，公开核心不实现，也不安装任何根证书。
- 检测是**确定性、高精度优先**的（已知前缀、高熵、JWT、PEM 私钥头、Luhn 卡号、邮箱）；没有命中的值会原样转发。
- 同机同用户的其它进程仍可能读写内存；核心不把明文写入磁盘，但不宣称对进程隔离之外的场景提供保护。

## 📚 相关

- [verify.md](verify.md)：同样用回环回显上游验证脱敏（本页 §3 的可复现版本）
- [security.md](security.md)：威胁模型与硬性不变量
- [tool-setup.md](tool-setup.md)：`tokenhush.yaml` 参考与逐工具接入
- [deployment.md](deployment.md)：安装、服务化与发行产物
