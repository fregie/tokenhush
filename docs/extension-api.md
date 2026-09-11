# Extension API — tokenhush (public core)

> 状态：设计稿（2026-09）。接口签名可能调整。

## 目的

公开核心只提供"单账户直连"的默认实现。Pro 构建（闭源）与第三方通过**扩展点接口**挂载额外能力。接口公开 ≠ 实现公开。

## 接口（`pkg/extension`）

```go
package extension

// Router 决定一个请求走哪个上游（多 provider / 多账号）。
type Router interface {
    Name() string
    // Pick 返回目标上游；返回 nil 表示"不处理，交给默认实现"。
    Pick(req *Request) (Upstream, error)
}

// CostSink 记录 token 用量与成本（Pro：成本追踪）。
type CostSink interface {
    Name() string
    Record(req *Request, resp *Response)
}

// AuditExporter 导出审计记录（Pro：团队审计 / 合规报告）。
type AuditExporter interface {
    Name() string
    Export(ctx context.Context, q Query) ([]Record, error)
}
```

配套类型（示意）：`Request`（方法/路径/头/已解析 JSON）、`Response`、`Upstream`（base URL + 凭据来源）、`Query`、`Record`。

## 挂载方式

### 公开核心（默认）
只注册内置的"直连 + 无路由 + 无成本"空实现，作为默认路径。

### Pro 构建（闭源）
Pro 仓库是**独立的 `main` 包**，导入本核心的公开包并注册私有实现：

```go
// 私有仓库 tokenhush-pro/cmd/tokenhush-pro/main.go（不存在于本仓库）
import (
    "github.com/<org>/tokenhush/pkg/extension"
    "github.com/<org>/tokenhush/pkg/proxy"
    pro "github.com/<org>/tokenhush-pro/internal/..."
)

func main() {
    proxy.Run(proxy.Config{
        Extensions: []extension.Extension{
            pro.NewMultiAccountRouter(),
            pro.NewCostTracker(),
            pro.NewTeamAuditExporter(),
        },
    })
}
```

**要点**：Pro 的能力来自**私有源码**，不是本仓库里的开关。破解公开核心无法解锁 Pro（因为公开二进制里根本没有 Pro 实现）。

## 稳定性策略

| 接口 | 稳定性 | 说明 |
|---|---|---|
| `extension.Router` | 计划稳定（v1 起） | 第三方路由插件依赖 |
| `extension.CostSink` | 计划稳定 | |
| `extension.AuditExporter` | 计划稳定 | |
| `Request` / `Response` 结构 | **可能变动** | 随协议演进调整，遵循语义化版本 |

- 公开接口以**语义化版本**管理；破坏性变更升级 major。
- 第三方扩展在 v1.0 前不建议依赖未冻结的字段。

## 第三方扩展（未来）

计划支持通过 WASM 或子进程协议加载社区扩展（**不**用于保护 IP，因为 WASM 可反编译——仅用于生态）。V1 不做。
