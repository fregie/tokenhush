package extension

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// inspectorEntry binds an Inspector to the capabilities captured at
// registration, so a mutable Capabilities() implementation cannot change phase
// filtering or ordering after the fact.
type inspectorEntry struct {
	insp Inspector
	caps Capabilities
}

// transformerEntry is the Transformer equivalent of inspectorEntry.
type transformerEntry struct {
	tr   Transformer
	caps Capabilities
}

// Registry holds the compiled-in plugins for one process. Register is expected
// to run at startup; it is not safe for concurrent use, but the Inspectors and
// Transformers read paths are safe once registration has finished. The zero
// value is usable; NewRegistry is preferred.
type Registry struct {
	inspectors   []inspectorEntry
	transformers []transformerEntry
	ids          map[string]struct{}
}

// NewRegistry returns an empty, ready registry.
func NewRegistry() *Registry { return &Registry{ids: make(map[string]struct{})} }

// Register validates and adds one plugin. A plugin is classified by the
// interfaces it implements: an Inspector, a Transformer, or (rarely) both. A
// plugin that implements both is held to the stricter Transformer phase rule,
// so it may only declare ResponseContent or Metadata.
//
// Registration is the security gate. It rejects, with a typed error:
//
//   - a nil, typed-nil, or non-plugin value (ErrNotAPlugin);
//   - an empty or already-registered id (ErrMissingID / ErrDuplicateID);
//   - a network capability (ErrNetworkDenied; compiled-in least privilege);
//   - a negative priority (ErrInvalidPriority);
//   - no phases or an unknown phase (ErrNoPhases / ErrInvalidPhase);
//   - a Transformer declaring RequestContent or Header (ErrTransformerPhase).
//
// Nothing is stored unless every check passes.
func (r *Registry) Register(p Plugin) error {
	if r == nil {
		return ErrNilRegistry
	}
	if isNilPlugin(p) {
		return ErrNotAPlugin
	}
	id := strings.TrimSpace(p.ID())
	if id == "" {
		return ErrMissingID
	}
	insp, isInspector := p.(Inspector)
	tr, isTransformer := p.(Transformer)
	if !isInspector && !isTransformer {
		return fmt.Errorf("%w: %T", ErrNotAPlugin, p)
	}
	caps := p.Capabilities().normalizePhases()
	if err := validateCapabilities(id, caps, isTransformer); err != nil {
		return err
	}
	if r.ids == nil {
		r.ids = make(map[string]struct{})
	}
	if _, ok := r.ids[id]; ok {
		return fmt.Errorf("%w: %q", ErrDuplicateID, id)
	}

	r.ids[id] = struct{}{}
	if isInspector {
		r.inspectors = append(r.inspectors, inspectorEntry{insp: insp, caps: caps})
	}
	if isTransformer {
		r.transformers = append(r.transformers, transformerEntry{tr: tr, caps: caps})
	}
	return nil
}

// Inspectors returns the inspectors registered for phase, ordered by ascending
// Priority then ascending id. The result is deterministic and independent of
// registration or map iteration order. The returned slice is a copy; a caller
// cannot use it to mutate registry state.
func (r *Registry) Inspectors(phase Phase) []Inspector {
	if r == nil {
		return nil
	}
	entries := make([]inspectorEntry, 0, len(r.inspectors))
	for _, e := range r.inspectors {
		if e.caps.AllowsPhase(phase) {
			entries = append(entries, e)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].caps.Priority != entries[j].caps.Priority {
			return entries[i].caps.Priority < entries[j].caps.Priority
		}
		return entries[i].insp.ID() < entries[j].insp.ID()
	})
	out := make([]Inspector, len(entries))
	for i, e := range entries {
		out[i] = e.insp
	}
	return out
}

// Transformers returns the transformers registered for phase, ordered by
// ascending Priority then ascending id, under the same determinism and copy
// guarantees as Inspectors. Only ResponseContent and Metadata can ever be
// populated, because registration rejects a Transformer on any other phase.
func (r *Registry) Transformers(phase Phase) []Transformer {
	if r == nil {
		return nil
	}
	entries := make([]transformerEntry, 0, len(r.transformers))
	for _, e := range r.transformers {
		if e.caps.AllowsPhase(phase) {
			entries = append(entries, e)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].caps.Priority != entries[j].caps.Priority {
			return entries[i].caps.Priority < entries[j].caps.Priority
		}
		return entries[i].tr.ID() < entries[j].tr.ID()
	})
	out := make([]Transformer, len(entries))
	for i, e := range entries {
		out[i] = e.tr
	}
	return out
}

// validateCapabilities enforces the capability contract before a plugin is
// stored. id is used only for error context and is known to be non-empty.
func validateCapabilities(id string, caps Capabilities, transformer bool) error {
	if caps.CanNetwork {
		return fmt.Errorf("%w: plugin %q", ErrNetworkDenied, id)
	}
	if caps.Priority < 0 {
		return fmt.Errorf("%w: plugin %q has priority %d", ErrInvalidPriority, id, caps.Priority)
	}
	if len(caps.Phases) == 0 {
		return fmt.Errorf("%w: plugin %q", ErrNoPhases, id)
	}
	for _, ph := range caps.Phases {
		if !ph.Valid() {
			return fmt.Errorf("%w: plugin %q declares %q", ErrInvalidPhase, id, ph)
		}
	}
	if transformer {
		for _, ph := range caps.Phases {
			if ph != ResponseContent && ph != Metadata {
				return fmt.Errorf("%w: plugin %q declares %q", ErrTransformerPhase, id, ph)
			}
		}
	}
	return nil
}

// isNilPlugin reports whether p is nil, including a typed-nil pointer stored in
// the interface (whose methods would panic if they were called).
func isNilPlugin(p Plugin) bool {
	if p == nil {
		return true
	}
	switch v := reflect.ValueOf(p); v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
