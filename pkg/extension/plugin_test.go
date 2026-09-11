package extension

import (
	"errors"
	"testing"
)

// gatingInspector is a fake Inspector that records the leaves it was shown, so
// a test can assert the capability gate stripped content before Inspect ran.
type gatingInspector struct {
	id   string
	caps Capabilities
	seen []Leaf
}

func (g *gatingInspector) ID() string                 { return g.id }
func (g *gatingInspector) Capabilities() Capabilities { return g.caps }

func (g *gatingInspector) Inspect(doc *Document) ([]Finding, error) {
	if doc != nil {
		g.seen = append([]Leaf(nil), doc.Leaves...)
	}
	return nil, nil
}

// rewritingTransformer is a fake Transformer that prefixes every non-nil leaf
// with mark, so a test can assert the transform actually ran.
type rewritingTransformer struct {
	id   string
	caps Capabilities
	mark string
}

func (t *rewritingTransformer) ID() string                 { return t.id }
func (t *rewritingTransformer) Capabilities() Capabilities { return t.caps }

func (t *rewritingTransformer) Transform(doc *Document) (*Document, error) {
	if doc == nil {
		return nil, errors.New("rewritingTransformer: nil document")
	}
	out := &Document{Phase: doc.Phase, Tool: doc.Tool, Leaves: make([]Leaf, len(doc.Leaves))}
	for i, leaf := range doc.Leaves {
		out.Leaves[i] = leaf
		if leaf.Content != nil {
			out.Leaves[i].Content = append([]byte(t.mark), leaf.Content...)
		}
	}
	return out, nil
}

// TestCapabilityGating locks the security-critical gate between the core and a
// plugin: content is populated only when ReadContent was granted, the Header
// phase never carries auth values, and the phase/Transformer restrictions are
// enforced before a plugin can run.
func TestCapabilityGating(t *testing.T) {
	t.Run("unprivileged_inspector_sees_content_nil_with_len", func(t *testing.T) {
		const secret = "sk-live-SECRET"
		doc := &Document{
			Phase:  RequestContent,
			Tool:   "claude-code",
			Leaves: []Leaf{{Path: "/messages/0/content", Content: []byte(secret), Len: len(secret)}},
		}
		insp := &gatingInspector{id: "no-read", caps: Capabilities{Phases: []Phase{RequestContent}}}

		view, err := Gate(doc, insp.Capabilities())
		if err != nil {
			t.Fatalf("Gate() error = %v, want nil", err)
		}
		if _, err := insp.Inspect(view); err != nil {
			t.Fatalf("Inspect() error = %v, want nil", err)
		}
		if len(insp.seen) != 1 {
			t.Fatalf("Inspect() saw %d leaves, want 1", len(insp.seen))
		}
		if insp.seen[0].Content != nil {
			t.Fatalf("Inspect() saw Content = %q, want nil when ReadContent is not granted", insp.seen[0].Content)
		}
		if insp.seen[0].Len != len(secret) {
			t.Fatalf("Inspect() saw Len = %d, want %d", insp.seen[0].Len, len(secret))
		}
		if doc.Leaves[0].Content == nil {
			t.Fatal("Gate() mutated the caller's document; want original Content preserved")
		}
		t.Logf("gated view: ReadContent=%v Len=%d Content=%#v", insp.Capabilities().ReadContent, insp.seen[0].Len, insp.seen[0].Content)
	})

	t.Run("privileged_inspector_sees_content", func(t *testing.T) {
		const secret = "sk-live-SECRET"
		doc := &Document{
			Phase:  RequestContent,
			Leaves: []Leaf{{Path: "/messages/0/content", Content: []byte(secret), Len: len(secret)}},
		}
		insp := &gatingInspector{id: "reader", caps: Capabilities{Phases: []Phase{RequestContent}, ReadContent: true}}

		view, err := Gate(doc, insp.Capabilities())
		if err != nil {
			t.Fatalf("Gate() error = %v, want nil", err)
		}
		if _, err := insp.Inspect(view); err != nil {
			t.Fatalf("Inspect() error = %v, want nil", err)
		}
		if string(insp.seen[0].Content) != secret {
			t.Fatalf("Inspect() saw Content = %q, want %q", insp.seen[0].Content, secret)
		}
	})

	t.Run("header_phase_never_exposes_auth_values", func(t *testing.T) {
		doc := &Document{
			Phase: Header,
			Leaves: []Leaf{
				{Path: "Authorization", Content: []byte("Bearer sk-live-SECRET"), Len: len("Bearer sk-live-SECRET")},
				{Path: "X-Api-Key", Content: []byte("sk-live-SECRET"), Len: len("sk-live-SECRET")},
				{Path: "Content-Type", Content: []byte("application/json"), Len: len("application/json")},
			},
		}
		// ReadContent is granted on purpose: the Header phase must strip values
		// regardless, so auth material can never reach a plugin.
		caps := Capabilities{Phases: []Phase{Header}, ReadContent: true}

		view, err := Gate(doc, caps)
		if err != nil {
			t.Fatalf("Gate() error = %v, want nil", err)
		}
		if len(view.Leaves) != len(doc.Leaves) {
			t.Fatalf("Gate() returned %d leaves, want %d", len(view.Leaves), len(doc.Leaves))
		}
		for i, leaf := range view.Leaves {
			if leaf.Content != nil {
				t.Errorf("Header leaf %q Content = %q, want nil (metadata-only phase)", leaf.Path, leaf.Content)
			}
			if leaf.Len != doc.Leaves[i].Len {
				t.Errorf("Header leaf %q Len = %d, want %d", leaf.Path, leaf.Len, doc.Leaves[i].Len)
			}
			t.Logf("header leaf %q -> Content=%#v Len=%d", leaf.Path, leaf.Content, leaf.Len)
		}
	})

	t.Run("request_content_transformer_rejected_at_registration", func(t *testing.T) {
		reg := NewRegistry()
		tr := &rewritingTransformer{
			id:   "req-transformer",
			caps: Capabilities{Phases: []Phase{RequestContent}, CanTransform: true, ReadContent: true},
		}
		err := reg.Register(tr)
		if !errors.Is(err, ErrTransformerPhase) {
			t.Fatalf("Register() error = %v, want ErrTransformerPhase", err)
		}
		if n := len(reg.Transformers(RequestContent)); n != 0 {
			t.Fatalf("Transformers(RequestContent) = %d, want 0 after rejection", n)
		}
		if n := len(reg.Inspectors(RequestContent)); n != 0 {
			t.Fatalf("Inspectors(RequestContent) = %d, want 0 after rejection", n)
		}
	})

	t.Run("header_transformer_rejected_at_registration", func(t *testing.T) {
		reg := NewRegistry()
		tr := &rewritingTransformer{
			id:   "hdr-transformer",
			caps: Capabilities{Phases: []Phase{Header}, CanTransform: true, ReadContent: true},
		}
		err := reg.Register(tr)
		if !errors.Is(err, ErrTransformerPhase) {
			t.Fatalf("Register() error = %v, want ErrTransformerPhase", err)
		}
		if n := len(reg.Transformers(Header)); n != 0 {
			t.Fatalf("Transformers(Header) = %d, want 0 after rejection", n)
		}
	})

	t.Run("response_transformer_registered_and_invoked", func(t *testing.T) {
		reg := NewRegistry()
		tr := &rewritingTransformer{
			id:   "resp-transformer",
			caps: Capabilities{Phases: []Phase{ResponseContent}, CanTransform: true, ReadContent: true},
			mark: "X-",
		}
		if err := reg.Register(tr); err != nil {
			t.Fatalf("Register() error = %v, want nil", err)
		}
		got := reg.Transformers(ResponseContent)
		if len(got) != 1 || got[0].ID() != "resp-transformer" {
			t.Fatalf("Transformers(ResponseContent) = %v, want the registered transformer", got)
		}
		if n := len(reg.Transformers(RequestContent)); n != 0 {
			t.Fatalf("Transformers(RequestContent) = %d, want 0", n)
		}
		if n := len(reg.Transformers(Metadata)); n != 0 {
			t.Fatalf("Transformers(Metadata) = %d, want 0 (only ResponseContent was declared)", n)
		}

		doc := &Document{Phase: ResponseContent, Leaves: []Leaf{{Path: "/a", Content: []byte("b"), Len: 1}}}
		view, err := Gate(doc, got[0].Capabilities())
		if err != nil {
			t.Fatalf("Gate() error = %v, want nil", err)
		}
		out, err := got[0].Transform(view)
		if err != nil {
			t.Fatalf("Transform() error = %v, want nil", err)
		}
		if got := string(out.Leaves[0].Content); got != "X-b" {
			t.Fatalf("Transform() produced %q, want %q", got, "X-b")
		}
	})

	t.Run("wrong_phase_rejected_before_invoke", func(t *testing.T) {
		insp := &gatingInspector{id: "resp-only", caps: Capabilities{Phases: []Phase{ResponseContent}, ReadContent: true}}
		_, err := Gate(&Document{Phase: RequestContent}, insp.Capabilities())
		if !errors.Is(err, ErrPhaseNotDeclared) {
			t.Fatalf("Gate() error = %v, want ErrPhaseNotDeclared", err)
		}
	})

	t.Run("nil_document_rejected", func(t *testing.T) {
		_, err := Gate(nil, Capabilities{Phases: []Phase{RequestContent}})
		if !errors.Is(err, ErrNilDocument) {
			t.Fatalf("Gate() error = %v, want ErrNilDocument", err)
		}
	})
}
