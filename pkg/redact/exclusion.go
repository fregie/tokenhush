package redact

// ExcludeFromBackfill adds values to the exclusion set. Additive and idempotent.
func (b *Backfiller) ExcludeFromBackfill(values ...[]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, value := range values {
		b.excluded[string(value)] = struct{}{}
	}
}

// excludes reports whether value is in the exclusion set.
func (b *Backfiller) excludes(value []byte) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.excluded[string(value)]
	return ok
}

// excludedCount returns the number of distinct excluded values.
func (b *Backfiller) excludedCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.excluded)
}
