package redact

import (
	"bytes"
	"sort"
	"sync"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// Backfiller owns the session-scoped REVERSE map (placeholder -> secret).
// It is the ONLY place a reverse map exists; a restart creates a new, empty
// Backfiller so a stale placeholder surfaces rather than a wrong secret.
type Backfiller struct {
	mu       sync.RWMutex
	reverse  map[string][]byte   // placeholder -> secret
	excluded map[string]struct{} // secret values that must never be restored
}

// pair is one placeholder -> secret snapshot entry.
type pair struct {
	placeholder string
	secret      []byte
}

// NewBackfiller returns an empty, session-scoped Backfiller.
func NewBackfiller() *Backfiller {
	return &Backfiller{
		reverse:  make(map[string][]byte),
		excluded: make(map[string]struct{}),
	}
}

// Map records placeholder -> secret for later Backfill. The secret is copied:
// the mapping must not alias a caller-owned buffer.
func (b *Backfiller) Map(placeholder string, secret []byte) {
	if placeholder == "" {
		return
	}
	owned := make([]byte, len(secret))
	copy(owned, secret)

	b.mu.Lock()
	defer b.mu.Unlock()
	b.reverse[placeholder] = owned
}

// Mint mints (or reuses) the placeholder for secret through the forward
// writer, then records the reverse mapping on this Backfiller.
func (b *Backfiller) Mint(w *ForwardWriter, secret []byte, kind string) (string, error) {
	p, err := w.Placeholder(secret, kind)
	if err != nil {
		return "", err
	}
	b.Map(p, secret)
	return p, nil
}

// Backfill restores every mapped, non-excluded placeholder in body. It is
// called with a whole client-bound body (buffered) and with a single token
// (SSE ReplaceFunc); a lone token is not a JSON document, so it returns the
// raw secret there and the SSE wrapper (SSEBackfiller) is what applies the
// escaping for that shape.
//
// JSON bodies restore through protocol.Walk + protocol.Apply: every occurrence
// inside a string leaf is re-spelled with RawSpelling(secret), so a secret
// carrying `"`, `\` or a control byte cannot break the surrounding JSON.
// Object keys are never emitted by Walk, so placeholders left over after Apply
// (a key) get exactly one escaping level. A body that is not a JSON document
// keeps the raw bytes.ReplaceAll behaviour. Longer placeholders are replaced
// first so a longer token is never shadowed by a shorter one. Bytes that are
// not a mapped placeholder are never touched: a foreign or unknown placeholder
// is returned byte-identical, never fabricated into a secret.
func (b *Backfiller) Backfill(body []byte) []byte {
	if !bytes.Contains(body, []byte(placeholderPrefix)) {
		return body
	}
	snapshot := b.snapshot()
	leaves, err := protocol.Walk(body)
	if err != nil {
		out := body
		for _, p := range snapshot {
			if b.excludes(p.secret) {
				continue
			}
			out = bytes.ReplaceAll(out, []byte(p.placeholder), p.secret)
		}
		return out
	}
	var edits []protocol.Edit
	for _, leaf := range leaves {
		for _, p := range snapshot {
			if b.excludes(p.secret) {
				continue
			}
			edits = appendLeaves(edits, leaf, p)
		}
	}
	out, _ := protocol.Apply(body, edits)
	for _, p := range snapshot {
		if b.excludes(p.secret) {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(p.placeholder), protocol.EscapeJSONString(p.secret))
	}
	return out
}

// appendLeaves appends one Edit per occurrence of the placeholder in
// leaf.Value, all spelling the secret at the leaf's raw position.
func appendLeaves(edits []protocol.Edit, leaf protocol.Leaf, p pair) []protocol.Edit {
	token := []byte(p.placeholder)
	spelled := leaf.RawSpelling(p.secret)
	for pos := 0; ; {
		i := bytes.Index(leaf.Value[pos:], token)
		if i < 0 {
			return edits
		}
		start := pos + i
		edits = append(edits, protocol.Edit{
			Leaf:        leaf,
			Start:       start,
			End:         start + len(token),
			Replacement: spelled,
		})
		pos = start + len(token)
	}
}

// snapshot copies the reverse map out under a read lock and orders it by
// DESCENDING placeholder length.
func (b *Backfiller) snapshot() []pair {
	b.mu.RLock()
	pairs := make([]pair, 0, len(b.reverse))
	for placeholder, secret := range b.reverse {
		pairs = append(pairs, pair{placeholder: placeholder, secret: secret})
	}
	b.mu.RUnlock()

	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].placeholder) > len(pairs[j].placeholder)
	})
	return pairs
}
