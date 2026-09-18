# tokenhush

tokenhush 是一个本地、仅回环的网关，位于你的 AI 编程工具与它们调用的厂商 API
之间。它把出站请求 body 中能检测到的 secret 替换为会话级占位符，并在响应回程时把
原始值还原。本仓库是 tokenhush 内核的从零 **v0.5.0** 重写。

- **无 MITM、无根证书。** tokenhush 从不终止 TLS，也从不安装信任根。它是绑定在
  `127.0.0.1` 上的 HTTP 正向代理。
- **磁盘上只有元数据。** 请求与响应 body、检测到的 secret、以及占位符到 secret
  的映射，永不持久化。
- **一个扩展点。** 每个检测器——六个内置检测器、签名远程规则包、编译期第三方规则集
  ——都是注册在 `pkg/filter` 中的 `Rule`。
- **供应链保留。** 签名规则同步与签名自更新保持既有后端的字节格式。

- [快速开始](#快速开始)
- [验证配方（冻结）](#验证配方冻结)
- [七个命令](#七个命令)
- [v0.5.0 重写的四个目标](#v050-重写的四个目标)
- [本产品不做什么](#本产品不做什么)
- [文档](#文档)

## 快速开始

需要 Go 1.25 或更新版本。下面的验证配方还会用到 `python3`（回环 echo 上游）与
`curl`（客户端）。

### 1. 构建

```sh
go build -o tokenhush ./cmd/tokenhush
./tokenhush version
```

如果希望下面的示例逐字可用，请把它装到 `PATH` 上：

```sh
go install ./cmd/tokenhush
```

### 2. 启动回环 echo 上游

这是假的厂商：它记录收到的确切 body，并原样回显。请在单独的终端运行。

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

### 3. 运行网关

除非用 `--config` 指定文件，网关会读取平台配置目录中的 `tokenhush.yaml`
（Linux 上是 `$XDG_CONFIG_HOME/tokenhush/tokenhush.yaml`）。设置 `TOKENHUSH_HOME`
会把配置目录与数据目录放到同一个临时根下，使本演练自成一体：

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

`tokenhush run` 依次执行崩溃恢复、加载配置、构建管线、绑定回环监听、写会话文件，
然后开始服务。端口被占用会在写入任何东西之前失败。

### 4. 接入工具

`tokenhush env <tool>` 打印把客户端指向网关的接入片段。它支持十四种工具；
`claude`、`codex`、`aider`、`cline`、`roo`、`opencode`、`qwen`、`crush`、
`zed`、`continue`、`openwebui`、`goose`、`openhands` 与 `kilo`。

```sh
tokenhush env claude     # export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"
tokenhush env codex      # config.toml 中的 model_providers.tokenhush 块
tokenhush env opencode   # opencode.json 中的 provider 块
```

Anthropic 风格客户端拿到裸源站；OpenAI 兼容客户端拿到 `/v1` 前缀。片段是纯文本，
可直接粘贴。

## 验证配方（冻结）

本配方中的三处细节是受保护的契约：脚本与运维者会观察它们，因此不会改变。

### 占位符语法

每个被脱敏的值都以占位符形式离开：

```
__PII_<type>_<digest>__
```

`<type>` 是经过清洗、长度受限的类别，例如 `email`、`jwt` 或 `api_key`；
`<digest>` 是不透明的每会话十六进制摘要，按固定阶梯增长直到会话内唯一。同一
secret 在会话内总是映射到同一占位符，占位符也只会还原本会话为它铸造的那个 secret。
本会话从未发放过的占位符按原样返回，绝不会被伪造成 secret。

### 脱敏日志行

每次替换都会向 **stderr** 打印一行掩码日志：

```
tokenhush: redacted request <type> (len=<N>) <masked>
```

- 它永不持久化——只写 stderr，请求与 secret 的任何内容都不落盘；
- `<masked>` 对多数类型是 `****`，对不透明凭据类型（`api_key`、`high_entropy`）
  是有界的前缀/后缀；
- 掩码形式永远不会等于 secret：字面值 `****` 会渲染为 `[redacted]`，因此兜底
  形式是一个不同的字符串。

### 回环 echo 验证（可运行）

在第 2 步的 echo 上游与第 3 步的网关都在运行时，发送一个内容含邮箱地址的请求：

```sh
curl -sS http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"echo","messages":[{"role":"user","content":"my email is alice@example.com"}]}'
```

三个观察结果证明整个往返。**secret 以占位符离开**——echo 上游的终端打印：

```
upstream received: {"model":"echo","messages":[{"role":"user","content":"my email is __PII_email_<digest>__"}]}
```

**日志行经过掩码且只写 stderr**——网关终端打印：

```
tokenhush: redacted request email (len=17) ****
```

**原始值回到客户端**——`curl` 输出再次包含 `my email is alice@example.com`，
因为响应路径还原本会话铸造的占位符。值以内容正确、合法 JSON 的 body 返回：还原按
外层 JSON 深度重新拼写 secret，而不是拼接原始字节。上游从未见到 secret，客户端
从未见到占位符。

像脚本一样读取运行中的网关：

```sh
tokenhush status --json
```

冻结的十键文档报告会话元数据，上面的请求对应 `"redactions":1`。

## 七个命令

CLI 恰好有七个命令。退出码冻结：`0` 成功、`1` 检查或操作失败、`2` 用法错误。

| 命令 | 作用 |
|---|---|
| `tokenhush run` | 启动网关。`--config PATH`、`--port N`、`--log-level LEVEL`、`--log-redactions`（默认开启）。 |
| `tokenhush rules` | `rules sync [--check]` 校验并激活签名规则包；`rules rollback` 回到此前验证过的 serial。`--check` 不写任何真实状态。 |
| `tokenhush update` | 检查并应用签名二进制更新，遵循包管理器安装来源。`--check` 只报告，不下载、不安装、不写入。 |
| `tokenhush status` | 报告运行中网关的元数据。`--json` 输出冻结文档；网关未运行时输出 `not running` 并以 1 退出。 |
| `tokenhush env <tool>` | 为十四种工具之一打印接入片段，指向回环网关。 |
| `tokenhush privacy` | 打印出口披露：恰好两个可开关的厂商绑定类别及其开关、主机与保留期。`--json` 面向机器。 |
| `tokenhush version` | 打印版本行（`v0.5.0`）与构建目标。 |

在任何请求发出之前就切断厂商绑定额度的开关：

```sh
TOKENHUSH_NO_UPDATE_CHECK=1 tokenhush update   # 输出 "no request was sent"
TOKENHUSH_NO_RULE_SYNC=1 tokenhush rules sync  # 输出 "no request was sent"
```

## v0.5.0 重写的四个目标

1. **更轻。** 只保留不可妥协的不变量与扩展机制。被删除的子系统——变更通道守卫、
   出站编码复检、键位置阻断、能力分级、keyring secret store、license 包、服务桩与
   `doctor` 检查——绝不在这里重建。
2. **过滤与替换集中在一个最小且高度可扩展的框架。** `pkg/filter` 的 `Rule` 是内置
   规则、签名远程包与第三方规则共同的唯一扩展点。
3. **供应链保留。** 签名规则同步与签名自更新与既有后端保持字节兼容：相同的端点、
   域标签、内嵌密钥 ID（`root-2026-09`、`rules-2026-09`）、文档 schema 与 floor
   行为。
4. **精简、清晰分层、高度可扩展。** 依赖只朝一个方向，允许的边由测试强制，而不是
   靠约定。

## 本产品不做什么

- **没有 Pro 契约。** 本次重写是开放内核的硬分叉。Pro 仓库继续对旧树构建，直到它
  单独完成迁移；见 [docs/PRO-MIGRATION.md](docs/PRO-MIGRATION.md)。
- **配置键与标志不向后兼容。** schema 严格且封闭：未知键是错误而非警告。唯一有意
  保留的兼容路径是 `pkg/filter` 仍解码 schema v1 规则文档，因为后端按 v1 签名。
- **不终止 TLS、无根证书、无 MITM。** 监听器仅限回环，非回环绑定从构造上被拒绝。
- **没有 `doctor` 命令、没有独立的 `allowlist` 命令、没有运行时插件加载、没有能力
  分级。** 控制表面恰好是 `GET /status`。
- **不做编码规范化。** 先经 base64、hex 或 URL 编码再离开的 secret 不会被检测；
  非 identity 的请求 `Content-Encoding` 以 415 拒绝，而不是为检测而解码。
- **不检查对象键。** 放在 JSON 对象键而不是值里的 secret 会原样转发。
- **响应路径不脱敏。** 响应路径上规则只能 block 或 warn。SSE 流上响应作用域的
  block 无法撤回已经发出的增量。
- **不发布、不做密钥仪式、不改基础设施。** 本树构建并测试客户端；它不发布、不重新
  签名、也不触碰后端。

## 文档

- [docs/architecture.zh-CN.md](docs/architecture.zh-CN.md)——分层依赖图、单一规则
  抽象、两个签名输入投影与冻结的字节表面。
- [docs/security.zh-CN.md](docs/security.zh-CN.md)——八条不变量及其具名测试、方向
  契约，以及被诚实记录的四项残余风险。
- [docs/plugins.zh-CN.md](docs/plugins.zh-CN.md)——扩展点、可运行的第三方示例，以及
  内核有意不提供的东西。
- [docs/PRO-MIGRATION.md](docs/PRO-MIGRATION.md)——Pro 仓库必须单独完成的迁移。
- [README.md](README.md)——本文件的英文原版。
