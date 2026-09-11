package redact

import (
	"bytes"
	"sort"

	"github.com/fregie/tokenhush/pkg/extension"
)

// Built-in detector ids. An id is both the value reported by Plugin.ID and the
// PluginID stamped on every finding.
const (
	detectorIDPrefix      = "prefix"
	detectorIDHighEntropy = "high_entropy"
	detectorIDJWT         = "jwt"
	detectorIDPrivateKey  = "private_key"
	detectorIDLuhn        = "luhn"
	detectorIDEmail       = "email"
)

// Finding types reported by the built-in detectors. docs/13 §5.1 freezes the
// detector set and docs/13 §14 freezes the threshold/confidence values, so
// changes here are deliberate and version-reviewed rather than silent drift.
const (
	typeAPIKey      = "api_key"
	typeHighEntropy = "high_entropy"
	typeJWT         = "jwt"
	typePrivateKey  = "private_key"
	typeCreditCard  = "credit_card"
	typeEmail       = "email"
)

// span is a half-open byte range [start,end) inside one leaf's Content.
type span struct {
	start int
	end   int
}

// finderFunc scans one leaf's content and returns non-overlapping spans in
// ascending order. Implementations must tolerate arbitrary bytes, including
// invalid UTF-8, and must never panic.
type finderFunc func(content []byte) []span

// Allowlist holds literal strings that are never redacted: a finding is
// suppressed when its span lies inside one occurrence of a listed literal.
// Empty literals are dropped because they would suppress every finding.
type Allowlist struct {
	literals []string
}

// NewAllowlist builds an Allowlist from the given literals. Empty literals are
// ignored.
func NewAllowlist(literals ...string) *Allowlist {
	kept := make([]string, 0, len(literals))
	for _, lit := range literals {
		if lit != "" {
			kept = append(kept, lit)
		}
	}
	return &Allowlist{literals: kept}
}

// suppresses reports whether [start,end) lies inside an occurrence of any
// listed literal in content. A nil Allowlist suppresses nothing.
func (a *Allowlist) suppresses(content []byte, start, end int) bool {
	if a == nil {
		return false
	}
	for _, lit := range a.literals {
		needle := []byte(lit)
		for offset := 0; offset <= len(content)-len(needle); {
			i := bytes.Index(content[offset:], needle)
			if i < 0 {
				break
			}
			occ := offset + i
			if occ <= start && end <= occ+len(needle) {
				return true
			}
			offset = occ + 1
		}
	}
	return false
}

// Option configures one built-in detector at construction time.
type Option func(*detectorConfig)

// WithAllowlist sets literal strings that are never redacted. A finding is
// suppressed when its span lies inside one occurrence of a listed literal.
func WithAllowlist(literals ...string) Option {
	return func(cfg *detectorConfig) {
		cfg.allowlist = NewAllowlist(literals...)
	}
}

// detectorConfig is the mutable state Options write into.
type detectorConfig struct {
	allowlist *Allowlist
}

// newDetectorConfig applies opts in order. Nil options are ignored.
func newDetectorConfig(opts []Option) detectorConfig {
	var cfg detectorConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// detector is the shared implementation behind every built-in Inspector: one
// fixed id, finding type, confidence and deterministic finder.
type detector struct {
	id         string
	finding    string
	confidence float64
	find       finderFunc
	allow      *Allowlist
}

// newDetector assembles a built-in detector.
func newDetector(id, finding string, confidence float64, find finderFunc, opts []Option) extension.Inspector {
	cfg := newDetectorConfig(opts)
	return &detector{
		id:         id,
		finding:    finding,
		confidence: confidence,
		find:       find,
		allow:      cfg.allowlist,
	}
}

// ID implements extension.Plugin.
func (d *detector) ID() string { return d.id }

// Capabilities implements extension.Plugin. Built-in detectors read content in
// both body phases at the default priority; they never transform, block or
// reach the network.
func (d *detector) Capabilities() extension.Capabilities {
	return extension.Capabilities{
		Phases:      []extension.Phase{extension.RequestContent, extension.ResponseContent},
		ReadContent: true,
		Priority:    0,
	}
}

// Inspect implements extension.Inspector. A nil document yields (nil, nil), as
// does content-free input. Findings are ordered by leaf index, then start, then
// end, so output is deterministic and independent of finder internals.
func (d *detector) Inspect(doc *extension.Document) ([]extension.Finding, error) {
	if doc == nil {
		return nil, nil
	}
	var findings []extension.Finding
	for i := range doc.Leaves {
		content := doc.Leaves[i].Content
		if len(content) == 0 {
			continue
		}
		for _, s := range d.find(content) {
			if s.start < 0 || s.start >= s.end || s.end > len(content) {
				continue
			}
			if d.allow.suppresses(content, s.start, s.end) {
				continue
			}
			findings = append(findings, extension.Finding{
				LeafIndex:  i,
				Start:      s.start,
				End:        s.end,
				Type:       d.finding,
				Confidence: d.confidence,
				Action:     extension.Redact,
				PluginID:   d.id,
			})
		}
	}
	sortFindings(findings)
	return findings, nil
}

// sortFindings orders findings by (LeafIndex, Start, End).
func sortFindings(findings []extension.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.LeafIndex != b.LeafIndex {
			return a.LeafIndex < b.LeafIndex
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		return a.End < b.End
	})
}

// isASCIIDigit reports whether b is an ASCII digit.
func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// isASCIIAlnum reports whether b is an ASCII letter or digit.
func isASCIIAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isTokenByte reports whether b can appear inside a credential-shaped token.
// It is the word-boundary test shared by the prefix detector: a candidate is
// rejected when a neighbouring byte could extend the same token.
func isTokenByte(b byte) bool {
	return isASCIIAlnum(b) || b == '_' || b == '-'
}
