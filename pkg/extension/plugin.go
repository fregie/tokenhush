package extension

import (
	"errors"
	"fmt"
	"slices"
)

// Phase identifies the part of the request/response lifecycle a plugin
// inspects or transforms. The zero value is deliberately invalid: a capability
// that forgot to declare a phase is rejected at registration instead of
// silently defaulting to the most sensitive phase.
type Phase string

// The four lifecycle phases (docs/13 §5). RequestContent covers outbound
// request body leaves; ResponseContent covers inbound response body leaves;
// Header covers request/response headers as metadata only; Metadata covers
// non-content metadata (tool, model, byte counts).
const (
	RequestContent  Phase = "request_content"
	ResponseContent Phase = "response_content"
	Header          Phase = "header"
	Metadata        Phase = "metadata"
)

// Valid reports whether p is one of the four defined phases.
func (p Phase) Valid() bool {
	switch p {
	case RequestContent, ResponseContent, Header, Metadata:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer. The zero value prints as an empty string.
func (p Phase) String() string { return string(p) }

// Action is the outcome an Inspector asks the core to take for a Finding. The
// core policy engine (W4.2) aggregates actions and applies them; a plugin never
// applies an action itself.
type Action string

// Action values. Allow leaves content untouched, Warn records a finding
// without changing content, Redact replaces the matched range, and Block
// rejects the request.
const (
	Allow  Action = "allow"
	Warn   Action = "warn"
	Redact Action = "redact"
	Block  Action = "block"
)

// Precedence ranks actions by severity, Allow < Warn < Redact < Block, and
// returns -1 for the zero value or any unrecognised string so the policy engine
// can reject an unknown action instead of treating it as Allow.
func (a Action) Precedence() int {
	switch a {
	case Allow:
		return 0
	case Warn:
		return 1
	case Redact:
		return 2
	case Block:
		return 3
	default:
		return -1
	}
}

// String implements fmt.Stringer.
func (a Action) String() string { return string(a) }

// Capabilities declares what a plugin is allowed to do. It is the core's
// least-privilege contract: registration rejects any capability the compiled-in
// third-party tier may not hold, and Gate withholds content the plugin did not
// ask to read.
type Capabilities struct {
	// Phases lists the lifecycle phases the plugin handles. It must be
	// non-empty and contain only defined phases.
	Phases []Phase
	// ReadContent grants access to Leaf.Content. Without it a plugin sees only
	// leaf paths and byte lengths.
	ReadContent bool
	// CanTransform declares that the plugin may return a rewritten document.
	// Only a Transformer can act on it.
	CanTransform bool
	// CanBlock declares that the plugin may request a block.
	CanBlock bool
	// CanNetwork would request egress. The compiled-in third-party tier is
	// denied it at registration (least privilege).
	CanNetwork bool
	// Priority orders plugins ascending; ties break on plugin id. Non-negative.
	Priority int
}

// AllowsPhase reports whether phase is among the declared phases.
func (c Capabilities) AllowsPhase(phase Phase) bool {
	return slices.Contains(c.Phases, phase)
}

// normalizePhases returns c with duplicate phases removed, preserving
// first-seen order, so a plugin that repeats a phase is not returned twice by
// Inspectors or Transformers.
func (c Capabilities) normalizePhases() Capabilities {
	seen := make(map[Phase]struct{}, len(c.Phases))
	deduped := make([]Phase, 0, len(c.Phases))
	for _, p := range c.Phases {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		deduped = append(deduped, p)
	}
	c.Phases = deduped
	return c
}

// Finding is one detection reported by an Inspector. LeafIndex selects a Leaf
// in the inspected Document; Start and End are byte offsets into that leaf's
// Content, End exclusive. When the inspector was not granted ReadContent,
// Content is nil and offsets are meaningless, so a plugin that needs offsets
// must declare ReadContent. Confidence is in [0,1].
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

// Document is the phase-scoped view of a request or response handed to a
// plugin. Leaf.Content is populated by the core only for plugins that hold the
// ReadContent capability and never for the Header phase; see Gate.
type Document struct {
	Phase  Phase
	Tool   string
	Leaves []Leaf
}

// Leaf is one content unit. For request/response bodies Path is the location
// produced by pkg/protocol (a JSON Pointer, with a '#' boundary inside a
// double-encoded string); for the Header phase Path is the header name. Len is
// the original byte length of the value and is set by the core even when
// Content is withheld.
type Leaf struct {
	Path    string
	Content []byte
	Len     int
}

// Plugin is the identity every content plugin shares.
type Plugin interface {
	ID() string
	Capabilities() Capabilities
}

// Inspector detects content in a Document and reports Findings. The core, not
// the plugin, applies the resulting action.
type Inspector interface {
	Plugin
	Inspect(*Document) ([]Finding, error)
}

// Transformer rewrites a Document and returns the replacement. For security it
// may only declare the ResponseContent or Metadata phases (registration rejects
// RequestContent and Header): request content and credentials are never handed
// to a Transformer, so it can never emit rewritten plaintext upstream (the
// core-only outbound invariant).
type Transformer interface {
	Plugin
	Transform(*Document) (*Document, error)
}

// Typed registration and gate errors. Every one is returned wrapped, so callers
// classify with errors.Is.
var (
	// ErrNotAPlugin means the value passed to Register is nil, is a typed-nil,
	// or implements neither Inspector nor Transformer.
	ErrNotAPlugin = errors.New("extension: plugin must implement Inspector or Transformer")
	// ErrNilRegistry means Register was called on a nil *Registry.
	ErrNilRegistry = errors.New("extension: nil registry")
	// ErrMissingID means the plugin id is empty or whitespace only.
	ErrMissingID = errors.New("extension: plugin id is empty")
	// ErrDuplicateID means the plugin id is already registered.
	ErrDuplicateID = errors.New("extension: duplicate plugin id")
	// ErrNoPhases means the capability declared no phases.
	ErrNoPhases = errors.New("extension: plugin declares no phases")
	// ErrInvalidPhase means the capability declared a phase that is not
	// RequestContent, ResponseContent, Header or Metadata.
	ErrInvalidPhase = errors.New("extension: plugin declares an unknown phase")
	// ErrTransformerPhase means a Transformer declared RequestContent or
	// Header, which it may never receive.
	ErrTransformerPhase = errors.New("extension: transformer may only declare response_content or metadata")
	// ErrNetworkDenied means the plugin requested network access, which the
	// compiled-in third-party tier is denied.
	ErrNetworkDenied = errors.New("extension: network access is denied for compiled-in plugins")
	// ErrInvalidPriority means the capability declared a negative priority.
	ErrInvalidPriority = errors.New("extension: priority must be non-negative")
	// ErrNilDocument means Gate was called with a nil document.
	ErrNilDocument = errors.New("extension: nil document")
	// ErrPhaseNotDeclared means a plugin was handed a document whose phase it
	// did not declare.
	ErrPhaseNotDeclared = errors.New("extension: plugin did not declare the document phase")
)

// Gate returns the view of doc that a plugin holding caps is allowed to see, or
// a typed error when the plugin may not handle doc at all. It never mutates
// doc.
//
// Rules, in order:
//
//  1. a nil doc is rejected with ErrNilDocument;
//  2. a plugin that did not declare doc.Phase is rejected with
//     ErrPhaseNotDeclared, so a plugin is never invoked out of phase;
//  3. without ReadContent, every Leaf.Content is withheld (set to nil);
//  4. the Header phase is metadata-only: Leaf.Content is withheld even when
//     ReadContent is granted, so Authorization, Cookie, API keys and every
//     other header value can never reach a plugin (only Leaf.Path and Leaf.Len
//     survive).
//
// Leaf.Len is always preserved, and when a producer left it zero Gate derives
// it from Content before withholding, so a plugin can size its work without
// seeing the value.
func Gate(doc *Document, caps Capabilities) (*Document, error) {
	if doc == nil {
		return nil, ErrNilDocument
	}
	if !caps.AllowsPhase(doc.Phase) {
		return nil, fmt.Errorf("%w: %q", ErrPhaseNotDeclared, doc.Phase)
	}
	withhold := !caps.ReadContent || doc.Phase == Header
	view := &Document{
		Phase:  doc.Phase,
		Tool:   doc.Tool,
		Leaves: make([]Leaf, len(doc.Leaves)),
	}
	for i, leaf := range doc.Leaves {
		length := leaf.Len
		if length == 0 && leaf.Content != nil {
			length = len(leaf.Content)
		}
		if withhold {
			view.Leaves[i] = Leaf{Path: leaf.Path, Len: length}
			continue
		}
		view.Leaves[i] = Leaf{Path: leaf.Path, Content: leaf.Content, Len: length}
	}
	return view, nil
}
