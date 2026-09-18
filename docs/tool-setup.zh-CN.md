# 工具接入与请求路由

**中文** | [English](tool-setup.md)

任何允许覆盖其 OpenAI 兼容或 Anthropic base URL 的工具，都能放在 Tokenhush 之后。把那个 URL 指向回环网关，工具就照常工作；网关在出站方向脱敏请求 body，在回程还原它。

网关默认监听 `http://127.0.0.1:8787`。

## 唯一的规则

两条客户端风格，两种 URL 形态。你只需要匹配自己工具的那一种：

- **Anthropic 风格客户端用裸源站：** `http://127.0.0.1:8787`。
- **OpenAI 兼容客户端用 `/v1`：** `http://127.0.0.1:8787/v1`。

`tokenhush env <tool>` 会按你的 shell 方言，为你指定的工具打印对应的那一种。下面的小节展示同样的片段。如果你用 `--port` 或 `listen.port` 改了端口，把 `8787` 换成你的端口。

## 工具

顺序就是 `tokenhush env` 列出它们的顺序。

### claude

```sh
export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"
```

### codex

加入 `~/.codex/config.toml`：

```toml
model_providers.tokenhush = { name = "Tokenhush", base_url = "http://127.0.0.1:8787/v1" }
```

只有 API key 模式能经过网关。ChatGPT 订阅登录不行。

### aider

```sh
export OPENAI_API_BASE="http://127.0.0.1:8787/v1"
export ANTHROPIC_API_BASE="http://127.0.0.1:8787"
```

### cline

在 VS Code 中：Settings，然后是 API Provider，再是 "OpenAI Compatible"，然后把 Base URL 设为：

```text
http://127.0.0.1:8787/v1
```

### roo

Roo Code 使用与 Cline 相同的 VS Code 设置路径：Settings，然后是 API Provider，再是 "OpenAI Compatible"，最后是 Base URL：

```text
http://127.0.0.1:8787/v1
```

### opencode

在 `opencode.json` 中加入一个名为 `tokenhush` 的 provider：

```json
{
  "provider": {
    "tokenhush": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Tokenhush",
      "options": {
        "baseURL": "http://127.0.0.1:8787/v1"
      }
    }
  }
}
```

### qwen

```sh
export OPENAI_BASE_URL="http://127.0.0.1:8787/v1"
export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"
```

### crush

在 `crush.json` 中加入一个名为 `tokenhush` 的 provider：

```json
{
  "providers": {
    "tokenhush": {
      "type": "openai",
      "base_url": "http://127.0.0.1:8787/v1"
    }
  }
}
```

### zed

在 `settings.json` 中：

```json
{
  "language_models": {
    "openai_compatible": {
      "tokenhush": {
        "api_url": "http://127.0.0.1:8787/v1"
      }
    }
  }
}
```

### continue

在 `~/.continue/config.yaml` 中加入一个名为 `tokenhush` 的模型：

```yaml
models:
  - name: tokenhush
    provider: openai
    apiBase: "http://127.0.0.1:8787/v1"
```

### openwebui

启动服务前导出 base URL：

```sh
export OPENAI_API_BASE_URL="http://127.0.0.1:8787/v1"
```

### goose

```sh
export OPENAI_HOST="http://127.0.0.1:8787"
export OPENAI_BASE_PATH="v1"
```

注意 Goose 把源站（`OPENAI_HOST`）与路径前缀（`OPENAI_BASE_PATH`）分开，所以它的 host 值不带 `/v1`。

### openhands

```sh
export LLM_BASE_URL="http://127.0.0.1:8787/v1"
```

同一个值也可以放到 `[llm].base_url` 设置里。

### kilo

Kilo Code 使用与 Cline 相同的 VS Code 设置路径：Settings，然后是 API Provider，再是 "OpenAI Compatible"，最后是 Base URL：

```text
http://127.0.0.1:8787/v1
```

## 其它工具

如果你的工具不在列表里，不需要片段。设置下面两个值之一：

- 把它的 OpenAI 兼容 base URL 设为 `http://127.0.0.1:8787/v1`，或
- 把它的 Anthropic base URL 设为 `http://127.0.0.1:8787`。

然后用 [verify.zh-CN.md](verify.zh-CN.md) 里的本地检查确认整个往返。

## 配置请求路由（`upstreams`）

路由按**请求路径**，不是按厂商名。网关读取路径、选一个上游、把请求接在后面再发出。一个路径对应一个上游。

在 `upstreams:` 下声明你自己的上游。它是 `{match, target}` 条目的**列表**，不是映射：

- `match` 是路径前缀。
- `target` 是不带结尾斜杠且**不带 `/v1`** 的源站。

用厂商源站。你的工具已经会发送完整路径，网关把它接在后面。这正是中转站无需特殊处理就能工作的原因。

```yaml
upstreams:
  - match: /v1/chat/completions
    target: https://your-provider.example.com
```

配置的 `upstreams` 条目优先于内置表。没有条目匹配时，应用内置表：

| 请求路径 | 内置上游 |
|---|---|
| `/v1/messages` | Anthropic |
| `/v1/chat/completions` | OpenAI |
| `/v1/responses` | OpenAI |
| `GET /v1/models` | OpenAI（唯一指名的例外） |
| 其它未知路径 | 显式错误 |

`GET /v1/models` 是唯一指名的例外：它默认去 OpenAI，而不是被当作未知路径。其它未知路径是显式错误，绝不静默错发。近似路径永不猜测。

因为路由由路径而非模型决定，中转站在 `/v1` 后面服务多个模型没问题：模型由请求 body 选择。

厂商的 API key 留在工具自己的配置里。网关原样转发认证头，只脱敏请求 body。

## 配置参考

Tokenhush 读取 `tokenhush.yaml`。它使用严格且封闭的 schema：文件缺失表示使用默认值，未知键是错误而不是警告。全部表面如下：

```yaml
listen:            {host: 127.0.0.1, port: 8787}
log:               {level: info}
detectors:         {prefix: true, email: true, luhn: true, jwt: true, pem: true, entropy: false}
allowlist:         ["literal"]
upstreams:         [{match: "/v1/chat/completions", target: "https://api.openai.com"}]
scan_budget_bytes: 33554432
detector_timeout:  30s
```

| 键 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `listen.host` | 字符串 | `127.0.0.1` | 只能是 `127.0.0.1`、`::1` 或 `localhost`。`0.0.0.0` 会被拒绝。 |
| `listen.port` | 整数 | `8787` | 1..65535。 |
| `log.level` | 字符串 | `info` | `debug`、`info`、`warn`、`error` 之一。 |
| `detectors.prefix` | 布尔值 | `true` | 已知 key 形态：`sk-`、`AKIA`、`ghp_`、`glpat-`、`xox*`、`AIza`、`npm_`。 |
| `detectors.email` | 布尔值 | `true` | 邮箱地址；匹配要求域名在标签边界处结束于已知公共后缀。 |
| `detectors.luhn` | 布尔值 | `true` | 卡号，经 Luhn 校验。 |
| `detectors.jwt` | 布尔值 | `true` | JSON Web Token。 |
| `detectors.pem` | 布尔值 | `true` | PEM 私钥头。 |
| `detectors.entropy` | 布尔值 | `false` | 高熵字符串。默认关闭，需显式开启：它在真实 agent 流量上的误报（长工具名、会话 id）曾破坏 function calling。 |
| `allowlist` | 字符串列表 | 空 | 永不脱敏的字面量。 |
| `upstreams` | `{match, target}` 列表 | 空 | 指向你自己源站的路径前缀路由。 |
| `scan_budget_bytes` | 整数 | `33554432`（32 MiB） | 确定性扫描预算。 |
| `detector_timeout` | 时长 | `30s` | 检测兜底。 |

检测器键名恰好是 `prefix`、`email`、`luhn`、`jwt`、`pem` 和 `entropy`。它们不是 `prefixes`，不是 `high_entropy`，也不是 `private_keys`。

`email` 检测器精确匹配：只有当地址域名在标签边界上以已知公共后缀（`.com`、
`.co.uk`）结尾时才算命中，因此子域名同样计入，而 `evilcorp.com` 这类形似地址
在配置了更窄的 `.corp.com` 后缀时会被拒绝。内置后缀表编译进程序、已冻结、始终生效。

## 配置目录与数据目录

| 平台 | 配置目录 | 数据目录 |
|---|---|---|
| macOS | `~/Library/Application Support/tokenhush/config/` | `~/Library/Application Support/tokenhush/Data/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/tokenhush/` | `${XDG_DATA_HOME:-~/.local/share}/tokenhush/` |
| Windows | `%AppData%\tokenhush\` | `%LocalAppData%\tokenhush\` |

`TOKENHUSH_HOME` 会把两者移到一个根：配置在 `<TOKENHUSH_HOME>/config`，数据在 `<TOKENHUSH_HOME>/data`。空值视为未设置。

给 `tokenhush run` 或 `tokenhush env` 传 `--config PATH`，可以读取指定的 `tokenhush.yaml`，而不是默认位置。

## 另见

- [deployment.zh-CN.md](deployment.zh-CN.md)：安装路径与服务包装。
- [verify.zh-CN.md](verify.zh-CN.md)：本地 echo 上游检查。
- [security.zh-CN.md](security.zh-CN.md)：回环绑定背后的安全模型。
