package extension

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// notAPlugin implements neither Inspector nor Transformer.
type notAPlugin struct{}

func (notAPlugin) ID() string                 { return "not-a-plugin" }
func (notAPlugin) Capabilities() Capabilities { return Capabilities{Phases: []Phase{RequestContent}} }

func validInspectorCaps(phases ...Phase) Capabilities {
	return Capabilities{Phases: phases, ReadContent: true}
}

// TestRegisterRejectsMalformedPlugin drives every registration-time validation
// with deliberately malformed plugins: wrong type, typed-nil, empty id,
// duplicate id, no phases, unknown phase, negative priority and network access.
func TestRegisterRejectsMalformedPlugin(t *testing.T) {
	newInspector := func(id string, caps Capabilities) *gatingInspector {
		return &gatingInspector{id: id, caps: caps}
	}

	cases := []struct {
		name    string
		prepare func(t *testing.T) (*Registry, Plugin)
		wantErr error
	}{
		{
			name: "nil_plugin",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				return NewRegistry(), nil
			},
			wantErr: ErrNotAPlugin,
		},
		{
			name: "typed_nil_pointer",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				var nilInsp *gatingInspector
				return NewRegistry(), nilInsp
			},
			wantErr: ErrNotAPlugin,
		},
		{
			name: "textbook_non_plugin",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				return NewRegistry(), notAPlugin{}
			},
			wantErr: ErrNotAPlugin,
		},
		{
			name: "empty_id",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				return NewRegistry(), newInspector("   ", validInspectorCaps(RequestContent))
			},
			wantErr: ErrMissingID,
		},
		{
			name: "duplicate_id_same_kind",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				reg := NewRegistry()
				if err := reg.Register(newInspector("dup", validInspectorCaps(RequestContent))); err != nil {
					t.Fatalf("first Register() error = %v, want nil", err)
				}
				return reg, newInspector("dup", validInspectorCaps(RequestContent))
			},
			wantErr: ErrDuplicateID,
		},
		{
			name: "duplicate_id_across_kinds",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				reg := NewRegistry()
				if err := reg.Register(&rewritingTransformer{
					id:   "shared",
					caps: Capabilities{Phases: []Phase{ResponseContent}, CanTransform: true},
				}); err != nil {
					t.Fatalf("first Register() error = %v, want nil", err)
				}
				return reg, newInspector("shared", validInspectorCaps(RequestContent))
			},
			wantErr: ErrDuplicateID,
		},
		{
			name: "no_phases",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				return NewRegistry(), newInspector("no-phases", Capabilities{ReadContent: true})
			},
			wantErr: ErrNoPhases,
		},
		{
			name: "unknown_phase",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				return NewRegistry(), newInspector("bad-phase", validInspectorCaps(Phase("bogus")))
			},
			wantErr: ErrInvalidPhase,
		},
		{
			name: "negative_priority",
			prepare: func(t *testing.T) (*Registry, Plugin) {
				return NewRegistry(), newInspector("neg-prio", Capabilities{
					Phases:      []Phase{RequestContent},
					ReadContent: true,
					Priority:    -1,
				})
			},
			wantErr: ErrInvalidPriority,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, p := tc.prepare(t)
			before := len(reg.inspectors) + len(reg.transformers)
			err := reg.Register(p)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Register() error = %v, want %v", err, tc.wantErr)
			}
			if after := len(reg.inspectors) + len(reg.transformers); after != before {
				t.Fatalf("rejected plugin was registered anyway (%d -> %d entries)", before, after)
			}
		})
	}
}

// TestNetworkCapabilityDenied proves the least-privilege rule for compiled-in
// plugins: a CanNetwork capability is refused at registration for both plugin
// kinds, so a third-party tier can never request egress.
func TestNetworkCapabilityDenied(t *testing.T) {
	t.Run("inspector", func(t *testing.T) {
		reg := NewRegistry()
		insp := &gatingInspector{id: "net-inspector", caps: Capabilities{
			Phases:      []Phase{RequestContent},
			ReadContent: true,
			CanNetwork:  true,
		}}
		err := reg.Register(insp)
		if !errors.Is(err, ErrNetworkDenied) {
			t.Fatalf("Register(inspector CanNetwork) error = %v, want ErrNetworkDenied", err)
		}
		if n := len(reg.Inspectors(RequestContent)); n != 0 {
			t.Fatalf("Inspectors(RequestContent) = %d, want 0 after network rejection", n)
		}
		t.Logf("Register(inspector CanNetwork=true) error: %v", err)
	})

	t.Run("transformer", func(t *testing.T) {
		reg := NewRegistry()
		tr := &rewritingTransformer{id: "net-transformer", caps: Capabilities{
			Phases:       []Phase{ResponseContent},
			ReadContent:  true,
			CanTransform: true,
			CanNetwork:   true,
		}}
		err := reg.Register(tr)
		if !errors.Is(err, ErrNetworkDenied) {
			t.Fatalf("Register(transformer CanNetwork) error = %v, want ErrNetworkDenied", err)
		}
		if n := len(reg.Transformers(ResponseContent)); n != 0 {
			t.Fatalf("Transformers(ResponseContent) = %d, want 0 after network rejection", n)
		}
		t.Logf("Register(transformer CanNetwork=true) error: %v", err)
	})
}

// TestRegistryOrdering locks deterministic dispatch order: priority ascending,
// then plugin id ascending, independent of registration order and map
// iteration.
func TestRegistryOrdering(t *testing.T) {
	build := func(ids []string) *Registry {
		reg := NewRegistry()
		priorities := map[string]int{"a": 1, "b": 1, "c": 3, "z": 5}
		for _, id := range ids {
			insp := &gatingInspector{id: id, caps: Capabilities{
				Phases:      []Phase{RequestContent},
				ReadContent: true,
				Priority:    priorities[id],
			}}
			if err := reg.Register(insp); err != nil {
				t.Fatalf("Register(%q) error = %v", id, err)
			}
		}
		return reg
	}

	wantIDs := []string{"a", "b", "c", "z"}
	for name, ids := range map[string][]string{
		"forward": {"z", "b", "a", "c"},
		"reverse": {"z", "c", "b", "a"},
	} {
		t.Run(name, func(t *testing.T) {
			got := build(ids).Inspectors(RequestContent)
			if len(got) != len(wantIDs) {
				t.Fatalf("Inspectors() = %d entries, want %d", len(got), len(wantIDs))
			}
			for i, id := range wantIDs {
				if got[i].ID() != id {
					t.Fatalf("Inspectors()[%d].ID() = %q, want %q (order %v)", i, got[i].ID(), id, wantIDs)
				}
			}
		})
	}
}

// TestInspectorsFiltersByPhase proves a plugin is only returned for phases it
// declared, and that the returned slice is a copy a caller cannot use to
// mutate registry state.
func TestInspectorsFiltersByPhase(t *testing.T) {
	reg := NewRegistry()
	reqOnly := &gatingInspector{id: "req", caps: validInspectorCaps(RequestContent)}
	respOnly := &gatingInspector{id: "resp", caps: validInspectorCaps(ResponseContent)}
	for _, p := range []*gatingInspector{reqOnly, respOnly} {
		if err := reg.Register(p); err != nil {
			t.Fatalf("Register(%q) error = %v", p.id, err)
		}
	}

	got := reg.Inspectors(RequestContent)
	if len(got) != 1 || got[0].ID() != "req" {
		t.Fatalf("Inspectors(RequestContent) = %v, want [req]", got)
	}
	got[0] = nil // mutating the returned slice must not affect the registry
	if again := reg.Inspectors(RequestContent); len(again) != 1 || again[0].ID() != "req" {
		t.Fatalf("Inspectors(RequestContent) after caller mutation = %v, want [req]", again)
	}
	if n := len(reg.Inspectors(Metadata)); n != 0 {
		t.Fatalf("Inspectors(Metadata) = %d, want 0", n)
	}
}

// TestActionPrecedence locks the severity ranking W4.2 relies on.
func TestActionPrecedence(t *testing.T) {
	order := []Action{Allow, Warn, Redact, Block}
	for i := 1; i < len(order); i++ {
		if order[i-1].Precedence() >= order[i].Precedence() {
			t.Fatalf("%s.Precedence()=%d must be < %s.Precedence()=%d",
				order[i-1], order[i-1].Precedence(), order[i], order[i].Precedence())
		}
	}
	if got := Action("bogus").Precedence(); got != -1 {
		t.Fatalf("unknown action Precedence() = %d, want -1", got)
	}
}

// TestNoSecretMappingSurface enforces the hard invariant that pkg/extension's
// exported API never exposes the placeholder<->secret mapping or the inbound
// backfill engine. Those live in pkg/redact and are core-only. The scan is
// structural (go/parser over the package's non-test sources), so it also fails
// if this package ever imports pkg/redact.
func TestNoSecretMappingSurface(t *testing.T) {
	forbidden := regexp.MustCompile(`(?i)(placeholder|backfill|secret)`)
	fset := token.NewFileSet()
	scanned := 0

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.) error = %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", name, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "/pkg/redact") {
				t.Errorf("%s imports %q; the placeholder/backfill engine must stay core-only", name, path)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch decl := n.(type) {
			case *ast.FuncDecl:
				checkExportedName(t, name, forbidden, decl.Name)
			case *ast.TypeSpec:
				checkExportedName(t, name, forbidden, decl.Name)
			case *ast.ValueSpec:
				for _, id := range decl.Names {
					checkExportedName(t, name, forbidden, id)
				}
			case *ast.Field:
				for _, id := range decl.Names {
					checkExportedName(t, name, forbidden, id)
				}
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("no non-test .go files scanned; the surface guard would pass vacuously")
	}
}

func checkExportedName(t *testing.T, file string, forbidden *regexp.Regexp, id *ast.Ident) {
	t.Helper()
	if id.IsExported() && forbidden.MatchString(id.Name) {
		t.Errorf("%s exports %q; pkg/extension must not expose the placeholder<->secret mapping", file, id.Name)
	}
}
