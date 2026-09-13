package rules

// The data-driven interpreter: it turns a validated Config into an immutable,
// concurrent-safe extension.Inspector. Both the Pro local-rules wrapper and the
// signed remote-rule client run through this single implementation (ADR-0020
// §2), so "what was detected" is auditable in the open-source core.

import (
	"fmt"

	"github.com/fregie/tokenhush/pkg/extension"
)

// Options tune the interpreter's identity and ordering without changing rule
// semantics. The zero value falls back to DefaultPluginID/DefaultPriority.
type Options struct {
	// PluginID is the registry id and the Finding.PluginID stamped on every
	// finding. Empty selects DefaultPluginID.
	PluginID string
	// Priority orders the interpreter against other plugins. Zero selects
	// DefaultPriority; a negative value is rejected at registration time.
	Priority int
}

// DefaultOptions returns the identity the remote-rule interpreter uses.
func DefaultOptions() Options {
	return Options{PluginID: DefaultPluginID, Priority: DefaultPriority}
}

// Interpreter is the compiled rule document. It is immutable after Compile and
// safe for concurrent use.
type Interpreter struct {
	rules     []compiledRule
	allowlist [][]byte
	blocklist [][]byte
	canBlock  bool
	pluginID  string
	priority  int
}

var _ extension.Inspector = (*Interpreter)(nil)

// ID implements extension.Plugin.
func (i *Interpreter) ID() string {
	if i == nil || i.pluginID == "" {
		return DefaultPluginID
	}
	return i.pluginID
}

// Capabilities implements extension.Plugin. The interpreter reads both content
// phases and never transforms or reaches the network. CanBlock is declared only
// when the configuration actually contains a block-action rule or a blocklist
// entry; a warn/redact-only rule document can never request a block.
func (i *Interpreter) Capabilities() extension.Capabilities {
	return extension.Capabilities{
		Phases:       []extension.Phase{extension.RequestContent, extension.ResponseContent},
		ReadContent:  true,
		CanTransform: false,
		CanBlock:     i != nil && i.canBlock,
		CanNetwork:   false,
		Priority:     i.priorityOr(),
	}
}

// priorityOr resolves the effective priority for a possibly-nil interpreter.
func (i *Interpreter) priorityOr() int {
	if i == nil || i.priority == 0 {
		return DefaultPriority
	}
	return i.priority
}

// Inspect implements extension.Inspector. A nil document yields (nil, nil).
// Every rule is applied to every content-bearing leaf; allowlist-suppressed
// matches are dropped; blocklist occurrences always become Block findings.
// Findings are ordered by (leaf, start, end, type) with exact duplicates
// collapsed, and every finding carries Meta["rule_id"] for auditability. The
// interpreter never fails on arbitrary bytes; it fails only when a document
// exceeds the finding bound (ErrTooManyMatches).
func (i *Interpreter) Inspect(doc *extension.Document) ([]extension.Finding, error) {
	if i == nil || doc == nil {
		return nil, nil
	}
	var findings []extension.Finding
	for li := range doc.Leaves {
		content := doc.Leaves[li].Content
		if len(content) == 0 {
			continue
		}
		var folded []byte
		for ri := range i.rules {
			r := &i.rules[ri]
			if r.fold && folded == nil {
				folded = asciiFold(content)
			}
			spans, err := r.find(content, folded, MaxMatches+1)
			if err != nil {
				return nil, err
			}
			for _, s := range spans {
				if suppressed(content, s[0], s[1], i.allowlist, r.allow) {
					continue
				}
				findings = append(findings, extension.Finding{
					LeafIndex:  li,
					Start:      s[0],
					End:        s[1],
					Type:       r.finding,
					Confidence: r.confidence,
					Action:     r.action,
					PluginID:   i.ID(),
					Meta:       map[string]any{"rule_id": r.id, "rule_type": r.kind},
				})
			}
			if len(findings) > MaxMatches {
				return nil, fmt.Errorf("%w: more than %d matches in one document", ErrTooManyMatches, MaxMatches)
			}
		}
		spans, err := findLiterals(content, i.blocklist, MaxMatches+1)
		if err != nil {
			return nil, err
		}
		for _, s := range spans {
			findings = append(findings, extension.Finding{
				LeafIndex:  li,
				Start:      s[0],
				End:        s[1],
				Type:       TypeBlocklist,
				Confidence: 1,
				Action:     extension.Block,
				PluginID:   i.ID(),
				Meta:       map[string]any{"rule_id": "blocklist", "rule_type": "list"},
			})
		}
		if len(findings) > MaxMatches {
			return nil, fmt.Errorf("%w: more than %d matches in one document", ErrTooManyMatches, MaxMatches)
		}
	}
	sortFindings(findings)
	return dedupeFindings(findings), nil
}
