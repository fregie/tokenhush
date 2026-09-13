package rules

// The rule client: it fetches the signed rule manifest and bundle from the
// Cloudflare rule service, verifies them with the shared Verifier, enforces the
// monotonic serial against a persisted high-water mark, honours the signed
// revocation list, caches the verified bytes and selects the active pack. Any
// failure falls back to the compiled-in defaults with a warning — never
// silently. The Worker only distributes bytes; every trust decision is here.

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// Endpoint paths of the Cloudflare rule service (ADR-0020, B6 contract).
const (
	// ManifestPath serves the signed rule manifest for a channel.
	ManifestPath = "/v1/rules/manifest"
	// BundlePath serves the signed rule bundle for a channel.
	BundlePath = "/v1/rules/bundle"
	// RevocationsPath serves the independent signed rule kill-switch document.
	// It is fetched separately from the manifest so a frozen manifest feed can
	// never hide a revocation.
	RevocationsPath = "/v1/rules/revocations"
)

// DefaultBaseURL is the rule service origin.
const DefaultBaseURL = "https://updates.tokenhush.com"

// DefaultChannel is the rule channel synced unless overridden.
const DefaultChannel = "stable"

// SyncStatus is the outcome of one Sync.
type SyncStatus string

const (
	// SyncUpdated means a newer pack was verified, cached and activated.
	SyncUpdated SyncStatus = "updated"
	// SyncCurrent means the offered serial is the one already accepted.
	SyncCurrent SyncStatus = "current"
	// SyncAvailable means --check found a newer serial without writing it.
	SyncAvailable SyncStatus = "available"
	// SyncCached means the service was unreachable and the cached pack is used.
	SyncCached SyncStatus = "cached"
	// SyncBuiltin means the compiled-in defaults are in effect after a fallback.
	SyncBuiltin SyncStatus = "builtin-default"
)

// SyncResult describes a Sync: the status, the serial involved and the warnings
// that must be surfaced (a fallback is never silent).
type SyncResult struct {
	Status   SyncStatus
	Serial   uint64
	Warnings []string
}

// ActiveRules is the currently selected remote rule set. A nil Config means the
// compiled-in defaults (no remote rules).
type ActiveRules struct {
	Config   *Config
	Serial   uint64
	Warnings []string
}

// Client syncs signed remote rule packs. BaseURL, Channel, Verifier, Cache and
// HighWater are required; HTTPClient defaults to a bounded https-only client
// and Warn receives every fallback warning.
type Client struct {
	BaseURL    string
	Channel    string
	Verifier   *Verifier
	Cache      CacheStore
	HighWater  HighWaterStore
	HTTPClient *http.Client
	Warn       func(string)
}

// validate rejects an incomplete client before any network call or disk write.
func (c *Client) validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil client", ErrClientConfig)
	}
	if c.Verifier == nil {
		return fmt.Errorf("%w: verifier is required", ErrClientConfig)
	}
	if c.Cache == nil {
		return fmt.Errorf("%w: cache is required", ErrClientConfig)
	}
	if c.HighWater == nil {
		return fmt.Errorf("%w: high-water store is required", ErrClientConfig)
	}
	if strings.TrimSpace(c.Channel) == "" {
		return fmt.Errorf("%w: channel is required", ErrClientConfig)
	}
	return validateBaseURL(strings.TrimRight(strings.TrimSpace(c.BaseURL), "/"))
}

// warn emits one fallback warning to the optional sink.
func (c *Client) warn(msg string) {
	if c.Warn != nil {
		c.Warn(msg)
	}
}

// Sync fetches, verifies, caches and activates the current rule pack. On
// check=true it probes the channel and reports whether a newer serial exists
// without downloading the bundle or writing anything. It returns a non-nil
// error when a received document was rejected (the client has already fallen
// back to the built-in defaults); transport failures fall back without an
// error because offline use is normal.
func (c *Client) Sync(ctx context.Context, check bool) (SyncResult, error) {
	if err := c.validate(); err != nil {
		return SyncResult{}, err
	}
	rawRev, err := c.get(ctx, c.revocationsURL())
	if err != nil {
		return c.offline("fetch rules revocations", err)
	}
	rev, err := c.Verifier.VerifyRevocations(rawRev)
	if err != nil {
		return c.reject(check, "rules revocations rejected", err)
	}
	if rev.Channel != c.Channel {
		return c.reject(check, "rules revocations channel mismatch", ErrChannelMismatch)
	}
	if err := c.checkRevocationRollback(rev.Serial); err != nil {
		return c.reject(check, "rules revocations rollback", err)
	}
	if !check {
		if err := c.storeRevocations(rev); err != nil {
			return SyncResult{}, fmt.Errorf("rules: persist revocations: %w", err)
		}
	}

	rawManifest, err := c.get(ctx, c.manifestURL())
	if err != nil {
		return c.offline("fetch rules manifest", err)
	}
	m, err := c.Verifier.VerifyManifest(rawManifest)
	if err != nil {
		return c.reject(check, "rules manifest rejected", err)
	}
	if m.Channel != c.Channel {
		return c.reject(check, "rules manifest channel mismatch", ErrChannelMismatch)
	}
	if rev.Revokes(m.Serial) || c.cachedRevoked(m.Serial) {
		return c.reject(check, "rules manifest serial revoked", ErrPackRevoked)
	}
	highest, ok, err := c.HighWater.Highest(KindRules)
	if err != nil {
		return c.reject(check, "rules high-water unreadable", err)
	}
	if ok && m.Serial < highest {
		return c.reject(check, "rules manifest rollback", fmt.Errorf("%w: serial %d below high-water %d", ErrPackReplayed, m.Serial, highest))
	}
	if ok && m.Serial == highest {
		return SyncResult{Status: SyncCurrent, Serial: m.Serial}, nil
	}
	if check {
		return SyncResult{Status: SyncAvailable, Serial: m.Serial}, nil
	}
	rawBundle, err := c.get(ctx, c.bundleURL())
	if err != nil {
		return c.offline("fetch rules bundle", err)
	}
	p, err := c.Verifier.VerifyPack(rawBundle)
	if err != nil {
		return c.reject(false, "rules bundle rejected", err)
	}
	if p.Channel != c.Channel || p.Channel != m.Channel {
		return c.reject(false, "rules bundle channel mismatch", ErrChannelMismatch)
	}
	if p.Serial != m.Serial {
		return c.reject(false, "rules bundle serial does not match manifest", ErrPackMalformed)
	}
	if !hashMatches(m.BundleSHA256, rawBundle) {
		return c.reject(false, "rules bundle sha256 mismatch", ErrBundleHashMismatch)
	}
	if err := c.Cache.Save(m.Serial, rawManifest, rawBundle); err != nil {
		return SyncResult{}, fmt.Errorf("rules: cache serial %d: %w", m.Serial, err)
	}
	if err := c.Cache.SetActive(m.Serial); err != nil {
		return SyncResult{}, fmt.Errorf("rules: activate serial %d: %w", m.Serial, err)
	}
	if err := c.HighWater.Advance(KindRules, m.Serial); err != nil {
		return SyncResult{}, fmt.Errorf("rules: advance high-water: %w", err)
	}
	if err := c.storeRevocations(rev, m.RevokedSerials); err != nil {
		return SyncResult{}, fmt.Errorf("rules: persist revocation list: %w", err)
	}
	return SyncResult{Status: SyncUpdated, Serial: m.Serial}, nil
}

// storeRevocations merges the given serial lists into the persisted revocation
// list (monotonic: revocations are never dropped), evicts every revoked cached
// pack and advances the independent revocation high-water mark.
func (c *Client) storeRevocations(rev RevocationList, extra ...[]uint64) error {
	cached, err := c.Cache.Revoked()
	if err != nil {
		return err
	}
	lists := append([][]uint64{cached.Serials, rev.RevokedSerials}, extra...)
	merged := unionRevoked(lists...)
	if err := c.Cache.SetRevoked(merged); err != nil {
		return err
	}
	for _, serial := range merged.Serials {
		_ = c.Cache.Remove(serial)
	}
	return c.advanceRevocationHighWater(rev.Serial)
}

// advanceRevocationHighWater records the accepted independent revocation serial
// without ever moving the mark backwards.
func (c *Client) advanceRevocationHighWater(serial uint64) error {
	highest, ok, err := c.HighWater.Highest(KindRuleRevocations)
	if err != nil {
		return err
	}
	if ok && serial <= highest {
		return nil
	}
	return c.HighWater.Advance(KindRuleRevocations, serial)
}

// checkRevocationRollback refuses an independent revocation document whose
// serial is below the persisted high-water mark, i.e. a rollback attempt.
func (c *Client) checkRevocationRollback(serial uint64) error {
	highest, ok, err := c.HighWater.Highest(KindRuleRevocations)
	if err != nil {
		return err
	}
	if ok && serial < highest {
		return fmt.Errorf("%w: revocations serial %d below high-water %d", ErrPackReplayed, serial, highest)
	}
	return nil
}

// cachedRevoked reports whether serial is on the persisted revocation list.
func (c *Client) cachedRevoked(serial uint64) bool {
	rev, err := c.Cache.Revoked()
	return err == nil && rev.Revokes(serial)
}

// unionRevoked merges serial lists into one sorted, deduplicated revocation
// list.
func unionRevoked(lists ...[]uint64) RevokedList {
	var out []uint64
	for _, l := range lists {
		out = append(out, l...)
	}
	slices.Sort(out)
	return RevokedList{Serials: slices.Compact(out)}
}

// reject refuses a received document, records the reason as a warning and, when
// not in check mode, drops the active pack so the built-in defaults apply.
func (c *Client) reject(check bool, msg string, cause error) (SyncResult, error) {
	w := fmt.Sprintf("rules: %s: %v; falling back to built-in defaults", msg, cause)
	if !check {
		_ = c.Cache.SetActive(0)
	}
	c.warn(w)
	return SyncResult{Status: SyncBuiltin, Warnings: []string{w}}, cause
}

// offline handles an unreachable service: keep the verified cache when one
// exists, otherwise use the built-in defaults. Either way it warns.
func (c *Client) offline(op string, cause error) (SyncResult, error) {
	active, err := c.Active()
	if err == nil && active.Config != nil {
		w := fmt.Sprintf("rules: %s failed: %v; using cached serial %d", op, cause, active.Serial)
		c.warn(w)
		return SyncResult{Status: SyncCached, Serial: active.Serial, Warnings: append([]string{w}, active.Warnings...)}, nil
	}
	w := fmt.Sprintf("rules: %s failed: %v; no usable cached rules, using built-in defaults", op, cause)
	c.warn(w)
	return SyncResult{Status: SyncBuiltin, Warnings: []string{w}}, nil
}
