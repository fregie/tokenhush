# Extension API (public core)

**English** | [中文](extension-api.zh-CN.md)

> Status: V1 implemented (2026-09). These interfaces match the real wiring in `pkg/extension` and `pkg/proxy`. Plugin-author walkthrough: [plugins.md](plugins.md).

## Purpose

The public core ships one implementation: single-account direct. Private builds (closed source) and third parties mount extra capabilities through extension-point interfaces. A public interface does not mean a public implementation.

## Interfaces (`pkg/extension`)

### Cross-layer extension points

Three hooks: pick an upstream, record cost, read audit records.

```go
package extension

// Router decides which upstream a request takes (multi-provider / multi-account).
type Router interface {
    Name() string
    // Pick returns the target upstream. A zero-value Upstream with a nil error
    // means "no opinion, fall back to the default implementation".
    Pick(req *Request) (Upstream, error)
}

// CostSink records token usage and cost.
type CostSink interface {
    Name() string
    Record(req *Request, resp *Response)
}

// AuditExporter exports audit records (team audit / compliance reports).
type AuditExporter interface {
    Name() string
    Export(ctx context.Context, q Query) ([]Record, error)
}
```

### Content plugins (compiled-in, least-privilege)

A plugin inspects or rewrites request and response content, but only through gates the core opens. The design decision lives in the private Pro repository. Built-in detectors are `Inspector` implementations; private builds and third parties mount more through the same interface. Same boundary as above: plaintext generation, outbound writes, and the placeholder mapping stay core-only.

```go
type Phase string  // RequestContent | ResponseContent | Header | Metadata
type Action string // Allow | Warn | Redact | Block

type Plugin interface {
    ID() string
    Capabilities() Capabilities
}

type Capabilities struct {
    Phases       []Phase
    ReadContent  bool
    CanTransform bool
    CanBlock     bool
    CanNetwork   bool // denied at registration for the compiled-in third-party tier
    Priority     int  // ascending; ties break on plugin id
}

type Finding struct {
    LeafIndex  int
    Start      int
    End        int
    Type       string
    Confidence float64
    Action     Action
    PluginID   string
    Meta       map[string]any
}

type Leaf struct {
    Path    string
    Content []byte
    Len     int
}
type Document struct {
    Phase  Phase
    Tool   string
    Leaves []Leaf
}

type Inspector interface {
    Plugin
    Inspect(*Document) ([]Finding, error)
}

type Transformer interface {
    Plugin
    Transform(*Document) (*Document, error)
}

// Registry (NewRegistry) holds the compiled-in plugins; Register is the
// security gate.
type Registry struct{ /* ... */ }

func NewRegistry() *Registry
func (r *Registry) Register(p Plugin) error
func (r *Registry) Inspectors(phase Phase) []Inspector
func (r *Registry) Transformers(phase Phase) []Transformer

// Gate returns the view a plugin is allowed to see: without ReadContent,
// Content is cleared; the Header phase always clears Content (leaving only
// Path/Len).
func Gate(doc *Document, caps Capabilities) (*Document, error)
```

**Safety constraints (registration and runtime)**

> [!IMPORTANT]
> A plugin only proposes; the core decides and acts. The placeholder-to-plaintext mapping is unreachable from `pkg/extension`.

- `Register` rejects with typed errors: non-plugin or typed-nil (`ErrNotAPlugin`); empty or duplicate id (`ErrMissingID` / `ErrDuplicateID`); `CanNetwork` (`ErrNetworkDenied`); negative priority (`ErrInvalidPriority`); empty or unknown phase (`ErrNoPhases` / `ErrInvalidPhase`); and a `Transformer` declaring `RequestContent` or `Header` (`ErrTransformerPhase`). It stores nothing unless every check passes.
- An `Inspector` without `ReadContent` sees only `Leaf.Len`; `Leaf.Content` is `nil`.
- A `Transformer` may declare only `ResponseContent` or `Metadata`; `RequestContent` or `Header` is rejected at registration.
- Plaintext generation and every outbound write are core-only. A `ResponseContent` rewrite runs before backfill, so its output cannot hold an original secret.
- The `Header` phase always clears `Content`, even with `ReadContent` granted. Only the header name and length survive, so `Authorization` and all credential values stay out of plugins.
- The placeholder-to-plaintext mapping is unreachable to plugins (`pkg/extension` exposes no mapping API).
- Policy lives in the core: precedence is `Allow < Warn < Redact < Block` (`Block` most severe). The per-plugin failure policy is `FailOpenWarn` (advisory, default) or `FailClosed` (critical). Panics and timeouts are never silent.

`Gate` also rejects a nil document (`ErrNilDocument`) and a document whose phase the plugin did not declare (`ErrPhaseNotDeclared`).

Supporting types (illustrative): `Request` (method/path/headers/parsed JSON), `Response`, `Upstream` (base URL, no credentials; V1 passes them through). `Query`/`Record` alias `pkg/audit` types; its `AuditSink`/`AuditQuerier` seams own audit reads and writes. Core default is a no-op sink; Pro injects the store.

## How implementations are mounted

### Public core (default)

The default path registers only no-op implementations: direct connection, no routing, no cost tracking.

### Private build (closed source)

A private repository is a separate `main` package: it imports this core's public packages and registers its own implementations:

```go
package main

import (
    "github.com/fregie/tokenhush/pkg/extension"
)

func main() {
    reg := extension.NewRegistry()

    // Content plugins go through Registry. An Inspector for detection...
    if err := reg.Register(myInspector{}); err != nil {
        return
    }
    // ...and a Transformer for response/metadata rewrites only.
    if err := reg.Register(myTransformer{}); err != nil {
        return
    }

    // Router, CostSink, and AuditExporter are independent injection points.
    // Wire them with the primitives exported by pkg/proxy and pkg/audit.
    // See plugins.md ("Registering plugins").
    _ = reg
}
```

> [!NOTE]
> This shows only the shape of injection. Real wiring uses `pkg/proxy` primitives; the `run` implementation in `internal/cli` is the reference (`internal/` is not importable by external modules).

**Key point**: Pro capability comes from private source, not a switch here. Cracking the public core cannot unlock Pro: the public binary contains no Pro implementation.

## Stability policy

| Interface | Stability | Notes |
|---|---|---|
| `extension.Router` | Stable since V1 | Third-party routing plugins depend on it |
| `extension.Inspector` / `Transformer` | Stable since V1 | Content-plugin contract; capability tiers above |
| `extension.Capabilities` / `Phase` / `Action` / `Finding` / `Document` / `Leaf` | Stable since V1 | Core plugin-contract types |
| `extension.CostSink` | Stable since V1 | |
| `extension.AuditExporter` | Stable since V1 | |
| `extension.Registry` | May change | Depends on the wiring; frozen once the wiring settles |
| `Request` / `Response` structs | May change | Adjusts as protocols evolve, following semantic versioning |

- Public interfaces follow semantic versioning; breaking changes bump the major version.
- Third-party extensions should not depend on unfrozen fields before v1.0.

## Third-party extensions

V1 supports **compile-time** plugins only (see [plugins.md](plugins.md)); no runtime loading of WASM, subprocesses, or dynamic libraries. A WASM sandbox (for ecosystem use, not IP protection) is out of scope for V1.
