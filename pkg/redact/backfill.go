package redact

import (
	"bytes"
	"sort"
	"sync"
)

// BackfillFunc restores every mapped placeholder in a client-bound body.
type BackfillFunc func(body []byte) []byte

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

// Backfill restores every mapped, non-excluded placeholder in body. Longer
// placeholders are replaced first so a longer token is never shadowed by a
// shorter one. Bytes that are not a mapped placeholder are never touched: a
// foreign or unknown placeholder is returned byte-identical, never fabricated
// into a secret.
func (b *Backfiller) Backfill(body []byte) []byte {
	snapshot := b.snapshot()
	out := body
	for _, p := range snapshot {
		if b.Excludes(p.secret) {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(p.placeholder), p.secret)
	}
	return out
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

// Func returns b.Backfill as a BackfillFunc.
func (b *Backfiller) Func() BackfillFunc { return b.Backfill }
