package filter

// compat_v1.go pins the v1 wire compatibility surface. Schema-v1 field names
// and rule type ids decode unchanged (the decoder only ever adds defaults), and
// a command rule is signalled instead of rejected: activation is pkg/supply's
// decision behind the rules-manifest v2 gate, so this layer must never turn a
// command document into a decode failure and must never silently drop one.

// CommandSignal is the non-fatal signal raised when a decoded document carries
// command rules. RuleIDs preserves declaration order and Count mirrors its
// length; both are zero for a document without command rules.
type CommandSignal struct {
	RuleIDs []string
	Count   int
}

// Present reports whether the decoded document carried any command rule.
func (s *CommandSignal) Present() bool { return s != nil && s.Count > 0 }

// DecodeDocumentWithSignal decodes a v1 (or later) rule document and reports
// the command rules it carries. Every v1 field name and wire id decodes
// unchanged through DecodeDocument; this wrapper only adds the signal. A
// command rule is never a hard decode error here and is never dropped: it stays
// in Document.Rules with ExcludedFromEvaluation set, so the rest of the
// document is always intact.
func DecodeDocumentWithSignal(data []byte) (*Document, *CommandSignal, error) {
	doc, err := DecodeDocument(data)
	if err != nil {
		return nil, nil, err
	}
	signal := &CommandSignal{}
	for _, rule := range doc.Rules {
		if rule.ExcludedFromEvaluation {
			signal.RuleIDs = append(signal.RuleIDs, rule.ID)
		}
	}
	signal.Count = len(signal.RuleIDs)
	return doc, signal, nil
}
