package proxy

import (
	"bytes"
	"fmt"

	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// selfProtectionExclusionType is the placeholder finding type of the C8 narrow
// exclusion set. It flows through the same pkg/redact grammar as a detector
// finding type, so the token renders as __PII_self_protection_<digest>__.
const selfProtectionExclusionType = "self_protection"

// exclusionSet is the immutable value published through
// Pipeline.exclusionValues. Publishing a whole new value is what makes a
// runtime refresh race-free: readers Load once per request and see either the
// old or the new set, never a mix.
type exclusionSet struct {
	values [][]byte
}

// SetSelfProtectionExclusions installs the current C8 narrow exclusion set: the
// session control-token value plus the current <DataDir>/allowlist.json content
// (exactly those two values; never allowlist entry values). The gateway calls
// it once the session token exists, and again whenever the allowlist changes,
// so the same state the force-redaction step reads stays current.
//
// It replaces the previously installed set (the construction-time
// PipelineConfig.Exclusions/ControlToken are merged in only at construction),
// copies every value so the caller keeps ownership, drops empty values and
// de-duplicates. It is safe on a nil receiver and a no-op when self-protection
// is disabled or the input is empty. Calls are safe concurrently with
// in-flight requests and with each other: the set is published through an
// atomic pointer, and the engine's never-backfill registration only grows (it
// takes its own lock), so a value once excluded stays excluded.
func (p *Pipeline) SetSelfProtectionExclusions(values [][]byte) {
	if p == nil || !p.selfProtectionEnabled {
		return
	}
	current := exclusionValues(values, "")
	p.exclusionValues.Store(&exclusionSet{values: current})
	if len(current) > 0 {
		p.engine.ExcludeFromBackfill(current...)
	}
}

// selfProtectionValues returns the currently installed exclusion set, or nil.
// The returned slices must be treated as read-only: they are shared with every
// concurrent reader of the same published set.
func (p *Pipeline) selfProtectionValues() [][]byte {
	if p == nil {
		return nil
	}
	set := p.exclusionValues.Load()
	if set == nil {
		return nil
	}
	return set.values
}

// exclusionValues merges the two frozen exclusion-set sources (the
// PipelineConfig.Exclusions values and the session control-token value),
// dropping empty entries and de-duplicating while preserving first-seen order.
// Empty sources yield nil, so the zero-value seam stays a complete no-op.
func exclusionValues(exclusions [][]byte, controlToken string) [][]byte {
	out := make([][]byte, 0, len(exclusions)+1)
	seen := make(map[string]struct{}, len(exclusions)+1)
	add := func(value []byte) {
		if len(value) == 0 {
			return
		}
		if _, dup := seen[string(value)]; dup {
			return
		}
		seen[string(value)] = struct{}{}
		out = append(out, append([]byte(nil), value...))
	}
	for _, value := range exclusions {
		add(value)
	}
	add([]byte(controlToken))
	if len(out) == 0 {
		return nil
	}
	return out
}

// forceRedactExclusions is the W6.1 prepend step: it runs over the freshly
// walked request body BEFORE p.policy.Evaluate (and therefore before
// detector.Inspect and the allowlist suppression inside it), replaces every
// occurrence of an exclusion-set value with its core placeholder, and re-walks
// the rewritten body so the policy sees the placeholders.
//
// Matching is on decoded leaf content, INCLUDING Encoded parent leaves: the
// <DataDir>/allowlist.json content is valid JSON, so when it appears as a JSON
// string value walkStringLeaf marks it an Encoded parent and terminalLeaves
// drops it, which is why a raw-byte or terminal-only scan would miss it. The
// placeholder is produced by the existing ApplyPlaceholders writer, so the
// mapping lands in byPlaceholder and the inbound direction can never restore it
// (Secret refuses it). Because the rewrite is applied to the bytes the rest of
// the transform operates on, the write-back happens on every decision branch,
// not only extension.Redact.
//
// It is a no-op (identical body and walk) when self-protection is disabled, the
// exclusion set is empty, or nothing matched.
func (p *Pipeline) forceRedactExclusions(body []byte, walked []protocol.Leaf) ([]byte, []protocol.Leaf, error) {
	if p == nil || !p.selfProtectionEnabled {
		return body, walked, nil
	}
	values := p.selfProtectionValues()
	if len(values) == 0 {
		return body, walked, nil
	}
	rewriter := &leafRewriter{
		walked: walked,
		edit: func(_ int, _ string, content []byte) ([]byte, bool) {
			return p.applyExclusionPlaceholders(content)
		},
		parentEdit: func(_ int, _ string, content []byte) ([]byte, bool) {
			return p.applyExclusionPlaceholders(content)
		},
	}
	forced, changed, err := rewriter.rewrite(body, "")
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: force-redact exclusions: %w", err)
	}
	if !changed {
		return body, walked, nil
	}
	rewalked, err := protocol.Walk(forced)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: re-walk force-redacted request: %w", err)
	}
	return forced, rewalked, nil
}

// applyExclusionPlaceholders replaces every exclusion-set occurrence in one
// decoded leaf content with its placeholder and reports whether it changed.
func (p *Pipeline) applyExclusionPlaceholders(content []byte) ([]byte, bool) {
	spans := p.exclusionSpans(content)
	if len(spans) == 0 {
		return content, false
	}
	out := p.engine.ApplyPlaceholders(content, spans)
	return out, !bytes.Equal(out, content)
}

// exclusionSpans finds every occurrence of every exclusion-set value in
// content and returns the redaction spans ApplyPlaceholders consumes. Overlaps
// are resolved by ApplyPlaceholders' own normalisation; values are non-empty
// and de-duplicated at construction.
func (p *Pipeline) exclusionSpans(content []byte) []redact.Redaction {
	var spans []redact.Redaction
	for _, value := range p.selfProtectionValues() {
		if len(value) == 0 || len(value) > len(content) {
			continue
		}
		for offset := 0; offset+len(value) <= len(content); {
			i := bytes.Index(content[offset:], value)
			if i < 0 {
				break
			}
			start := offset + i
			spans = append(spans, redact.Redaction{
				Start: start,
				End:   start + len(value),
				Type:  selfProtectionExclusionType,
			})
			offset = start + len(value)
		}
	}
	return spans
}
