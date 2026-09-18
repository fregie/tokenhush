package redact

import "github.com/fregie/tokenhush/pkg/protocol"

// Substitution is one decoded secret occurrence to replace on the request
// path: [Start, End) is a byte range of Leaf.Value (the DECODED string the
// walker emitted), not a range of the raw request body.
type Substitution struct {
	Leaf     protocol.Leaf
	Start    int
	End      int
	Category string
}

// Applied is one substitution that really changed the body: Index refers to
// the subs slice the caller passed in, Length is the decoded secret length
// (for the frozen redaction log line).
type Applied struct {
	Index    int
	Category string
	Length   int
}

// Substitute mints a placeholder for every LOCATABLE substitution and splices
// it in at the raw bytes that spell that decoded span. A substitution whose
// raw span cannot be located is skipped and is NEVER minted (G3: the reverse
// map must not hold a placeholder for a secret that was never sent). Only
// substitutions that actually changed bytes are returned, in ascending raw
// order, because protocol.Apply is the sole authority on overlaps and no-ops.
func (b *Backfiller) Substitute(w *ForwardWriter, body []byte, subs []Substitution) ([]byte, []Applied, error) {
	var (
		edits []protocol.Edit
		owner []int
	)
	for i := range subs {
		sub := subs[i]
		if sub.Start < 0 || sub.End <= sub.Start || sub.End > len(sub.Leaf.Value) {
			continue
		}
		if _, _, ok := sub.Leaf.RawSpan(sub.Start, sub.End); !ok {
			continue
		}
		secret := sub.Leaf.Value[sub.Start:sub.End]
		placeholder, err := b.Mint(w, secret, sub.Category)
		if err != nil {
			return nil, nil, err
		}
		edits = append(edits, protocol.Edit{Leaf: sub.Leaf, Start: sub.Start, End: sub.End, Replacement: []byte(placeholder)})
		owner = append(owner, i)
	}
	out, appliedIdx := protocol.Apply(body, edits)
	applied := make([]Applied, 0, len(appliedIdx))
	for _, idx := range appliedIdx {
		sub := subs[owner[idx]]
		applied = append(applied, Applied{Index: owner[idx], Category: sub.Category, Length: sub.End - sub.Start})
	}
	return out, applied, nil
}
