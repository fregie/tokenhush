// rules_activate.go owns pack activation, cache loading and the transport
// fallback, split out of rules.go to keep that file under the 250-pure-LOC
// guard ceiling. The order these helpers implement is the safety property
// documented in rules.go: cache-write, publish, then advance the mark.
package supply

import "errors"

// replay applies the anti-rollback rule to a manifest whose serial equals the
// mark: a replayed manifest keeps the active pack and never re-fetches the
// bundle. The cache is consulted only when it already points at the same
// serial, so a restart that has not loaded it yet still ends up with the
// verified pack instead of the built-ins, and can never be moved backwards.
func (s *RulesSync) replay(serial uint64) error {
	if s.Active().Serial == serial {
		return nil
	}
	if cached, err := s.cache.ActiveSerial(); err != nil || cached != serial {
		return err
	}
	return s.loadCache()
}

// activate caches the accepted documents, publishes the pack and then advances
// the mark. The mark advances last, so a pack that is already active stays
// active if the mark write fails, and the next sync retries the same serial.
func (s *RulesSync) activate(accepted acceptedPack, manifestRaw, bundleRaw []byte, source RuleSource) error {
	if err := s.cache.Store(accepted.Serial, manifestRaw, bundleRaw); err != nil {
		return err
	}
	s.setActive(RulesState{Source: source, Serial: accepted.Serial, Pack: accepted.Pack, Warnings: accepted.Warnings})
	return s.highWater.Advance(int64(accepted.Serial))
}

// loadCache activates the cached verified pack. Startup and the transport
// fallback use it; it never fetches. The cached manifest is re-verified with
// its SIGNATURE but not with its freshness window: it was fresh when it was
// fetched, and dropping to the built-ins merely because the client has been
// offline would weaken the protection that is already in force. No cache and a
// rejected cached pack both leave the active state unchanged.
func (s *RulesSync) loadCache() error {
	cached, err := s.cache.LoadActive()
	if errors.Is(err, ErrNoCachedPack) {
		return nil
	}
	if err != nil {
		return err
	}
	manifest, err := DecodeRulesManifest(cached.ManifestRaw)
	if err != nil {
		return err
	}
	if err := verifyRulesManifestSignature(manifest, s.verifier); err != nil {
		return err
	}
	open, err := checkManifestFields(manifest, s.binary)
	if err != nil {
		return err
	}
	accepted, err := s.accept(manifest, cached.BundleRaw, open)
	if err != nil {
		return err
	}
	s.setActive(RulesState{Source: SourceCache, Serial: accepted.Serial, Pack: accepted.Pack, Warnings: accepted.Warnings})
	return nil
}

// fallback keeps the strongest available pack after a transport failure and
// returns the transport error for the caller to report. A loaded pack stays
// active; otherwise the cached verified pack is loaded; otherwise the
// built-ins stay in force.
func (s *RulesSync) fallback(fetchErr error) error {
	if s.Active().Serial == 0 {
		if cacheErr := s.loadCache(); cacheErr != nil {
			return errors.Join(fetchErr, cacheErr)
		}
	}
	return fetchErr
}

// setActive publishes one state.
func (s *RulesSync) setActive(state RulesState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = state
}
