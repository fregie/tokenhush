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

## 配置

Tokenhush 读取 `tokenhush.yaml`。完整参考 —— 每个键及其默认值、文件位置，以及如何把请求路由到你自己的厂商 —— 见 [configuration.zh-CN.md](configuration.zh-CN.md)。

使用中转站前唯一必须设置的是 `upstreams` 条目。它是 `{match, target}` 条目的**列表**：`match` 是请求路径前缀，`target` 是厂商源站（加上 `/v1` 之前的任何前缀），不带结尾斜杠且**不带 `/v1`**。

```yaml
upstreams:
  - match: /v1/chat/completions
    target: https://your-provider.example.com
```

没有 `upstreams` 时，应用内置表：`/v1/messages` 去 Anthropic，`/v1/chat/completions` 与 `/v1/responses` 去 OpenAI。完整表、匹配规则与优先级、示例与排错见 [configuration.zh-CN.md](configuration.zh-CN.md)。

## 另见

- [deployment.zh-CN.md](deployment.zh-CN.md)：安装路径与服务包装。
- [verify.zh-CN.md](verify.zh-CN.md)：本地 echo 上游检查。
- [security.zh-CN.md](security.zh-CN.md)：回环绑定背后的安全模型。
