// rules.go is the rule-pack sync layer (W5.5). It is the only place that
// decides whether a fetched pack becomes the ACTIVE pack, and the only place
// that decides the OD-2 command gate: the gate needs the rules-manifest
// schema_version (the OD-4 signal) and the pack's typed command signal at the
// same time, so it can live neither in pkg/filter (which never sees a
// manifest) nor in pkg/filter's floor (which must stay allowlist-neutral).
//
// The ORDER below is the safety property. Every check runs before any state
// changes, the fetched documents are cached only after all of them passed, and
// the anti-rollback mark advances last, once the pack is active. A rejected
// pack can therefore never displace the verified pack that is already in
// force, and a failed step can never block a retry of that serial.
//
//  1. fetch the rules manifest (bounded by the injected Fetcher);
//  2. manifest: Ed25519 over tokenhush-rules-manifest-v1, freshness, the
//     stable channel, minimum binary version, revoked serial, and the serial
//     against the anti-rollback mark (read-only here);
//  3. fetch the bundle from the FROZEN path: a manifest can never redirect the
//     client to another document or another origin;
//  4. pack: strict decode and Ed25519 over tokenhush-rules-pack-v1;
//  5. minimum binary version of the pack;
//  6. the pkg/filter non-weakening floor, which is allowlist-neutral (OD-3):
//     global and per-rule allowlists are deliberately not inspected, so a real
//     signed pack carrying them is accepted;
//  7. pack.serial == manifest.serial;
//  8. the bundle's SHA-256, compared in constant time;
//  9. cache-write, then activate.
//
// The OD-2 rule: a pack carrying command rules is ACCEPTED with a warning
// while the manifest reports schema_version 1 — the remaining rules stay
// active, the warning names the command rule ids and states that a command
// rule does nothing in this rewrite — and is REFUSED with the previous pack
// retained once the manifest reports schema_version 2. The refusal is the
// dedicated ErrCommandGate, never ErrSchemaVersion.
//
// Startup is cache-only (Startup makes no network request), and
// TOKENHUSH_NO_RULE_SYNC=1 makes Sync itself return before any request.
package supply

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fregie/tokenhush/pkg/filter"
)

// Version is the compiled-in binary version (OD-1): the version line starts at
// v0.5.0 and the signed fixtures require at least 0.3.0, so the shipped binary
// satisfies the minimum-version gate without a shim.
const Version = "0.5.0"

// Frozen sync inputs. The channel is the only accepted one, the two URLs are
// composed from the frozen constants, and no base URL or key is configurable.
const (
	rulesChannel  = "stable"
	noRuleSyncEnv = "TOKENHUSH_NO_RULE_SYNC"
	manifestURL   = BaseURL + RulesManifestPath + ChannelQuery
	bundleURL     = BaseURL + RulesBundlePath + ChannelQuery
)

// Typed rejections. Callers branch on them with errors.Is; no error text ever
// echoes untrusted document content.
var (
	// ErrBadConfig reports an unusable RulesSyncConfig.
	ErrBadConfig = errors.New("supply: invalid rules sync configuration")
	// ErrChannelMismatch reports a rules manifest on another channel.
	ErrChannelMismatch = errors.New("supply: rules manifest is not on the stable channel")
	// ErrSerialMismatch reports a bundle whose serial is not the serial the
	// manifest points at. The active pack is retained.
	ErrSerialMismatch = errors.New("supply: rules pack serial does not match the manifest")
	// ErrCommandGate reports a pack carrying command rules under a manifest
	// whose schema_version opens the OD-2 gate. It is deliberately distinct
	// from ErrSchemaVersion: the gate signal and the gate verdict are two
	// different failures.
	ErrCommandGate = errors.New("supply: command rules are refused while the command gate is open")
)

// CommandGateError carries the command rule ids the OD-2 gate refused. Unwrap
// returns ErrCommandGate, so errors.Is(err, ErrCommandGate) classifies it while
// errors.Is(err, ErrSchemaVersion) stays false.
type CommandGateError struct{ RuleIDs []string }

// Error renders the sentinel followed by the offending rule ids.
func (e *CommandGateError) Error() string {
	return ErrCommandGate.Error() + ": " + strings.Join(e.RuleIDs, ", ")
}

// Unwrap returns the ErrCommandGate sentinel.
func (e *CommandGateError) Unwrap() error { return ErrCommandGate }

// RuleSource names where the active rule set came from.
type RuleSource string

// The three states of the active rule set. Builtin means "use pkg/filter's
// compiled-in detectors"; a state with Source builtin never carries a pack.
// The values are part of RulesState's observable contract, pinned by
// internal/cli tests.
const (
	SourceRemote  RuleSource = "remote"
	SourceCache   RuleSource = "cache"
	SourceBuiltin RuleSource = "builtin"
)

// RulesState is the rule set a caller should evaluate with. It is always
// usable: with no verified pack, Source is builtin and Pack is nil. Pack is
// immutable once published, so a returned state is safe for concurrent use.
type RulesState struct {
	Source   RuleSource
	Serial   uint64
	Pack     *filter.Compiled
	Warnings []string
}

// RulesSyncConfig wires the injectable seams. DataDir, Fetcher and Verifier are
// required; HighWater defaults to the frozen file store under DataDir, Now to
// time.Now, BinaryVersion to Version and LookupEnv to os.LookupEnv.
type RulesSyncConfig struct {
	DataDir       string
	Fetcher       Fetcher
	Verifier      Verifier
	HighWater     HighWater
	Now           func() time.Time
	BinaryVersion string
	LookupEnv     func(string) (string, bool)
}

// RulesSync runs the signed sync sequence and owns the active pack. Its
// methods are safe for concurrent use.
type RulesSync struct {
	cache     *RulesCache
	fetcher   Fetcher
	verifier  Verifier
	highWater HighWater
	now       func() time.Time
	binary    version
	lookupEnv func(string) (string, bool)

	mu     sync.Mutex
	active RulesState
}

// NewRulesSync returns a sync layer with the built-ins active. It performs no
// I/O beyond reading the persisted anti-rollback mark.
func NewRulesSync(cfg RulesSyncConfig) (*RulesSync, error) {
	if cfg.DataDir == "" || cfg.Fetcher == nil || cfg.Verifier == nil {
		return nil, fmt.Errorf("%w: data dir, fetcher and verifier are required", ErrBadConfig)
	}
	highWater := cfg.HighWater
	if highWater == nil {
		mark, err := NewRulesHighWater(cfg.DataDir)
		if err != nil {
			return nil, err
		}
		highWater = mark
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	lookupEnv := cfg.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if cfg.BinaryVersion == "" {
		cfg.BinaryVersion = Version
	}
	parsed, err := parseVersion(cfg.BinaryVersion)
	if err != nil {
		return nil, err
	}
	return &RulesSync{
		cache: NewRulesCache(cfg.DataDir), fetcher: cfg.Fetcher, verifier: cfg.Verifier,
		highWater: highWater, now: now, binary: parsed, lookupEnv: lookupEnv,
		active: RulesState{Source: SourceBuiltin},
	}, nil
}

// Startup loads the active pack from the LOCAL cache only. It issues no
// network request, so a daemon start never depends on reachability and can
// never be redirected by a live server. An empty cache leaves the built-ins
// active; a corrupt cache fails closed and is never rewritten.
func (s *RulesSync) Startup() error { return s.loadCache() }

// Active returns the rule set to evaluate with, always usable.
func (s *RulesSync) Active() RulesState {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Clone in place: a caller must not be able to mutate the published state
	// through the returned slice.
	s.active.Warnings = slices.Clone(s.active.Warnings)
	return s.active
}

// Sync runs the frozen sequence and activates a newly fetched pack. A
// rejection leaves the active pack and the cache untouched; a transport
// failure falls back to the active pack, then to the cached verified pack,
// then to the built-ins, and still returns the transport error.
func (s *RulesSync) Sync(ctx context.Context) error {
	if value, ok := s.lookupEnv(noRuleSyncEnv); ok && value == "1" {
		return nil
	}
	manifestRaw, err := s.fetcher.Get(ctx, manifestURL)
	if err != nil {
		return s.fallback(err)
	}
	manifest, err := DecodeRulesManifest(manifestRaw)
	if err != nil {
		return err
	}
	if err := VerifyRulesManifest(manifest, s.verifier, s.now()); err != nil {
		return err
	}
	open, err := checkManifestFields(manifest, s.binary)
	if err != nil {
		return err
	}
	if slices.Contains(manifest.RevokedSerials, manifest.Serial) {
		return fmt.Errorf("%w: serial %d", ErrRevokedSerial, manifest.Serial)
	}
	switch mark := s.highWater.Current(); {
	case manifest.Serial < uint64(mark):
		return &ReplayError{Current: mark, Attempted: int64(manifest.Serial)}
	case manifest.Serial == uint64(mark):
		return s.replay(manifest.Serial)
	}
	bundleRaw, err := s.fetcher.Get(ctx, bundleURL)
	if err != nil {
		return s.fallback(err)
	}
	accepted, err := s.accept(manifest, bundleRaw, open)
	if err != nil {
		return err
	}
	return s.activate(accepted, manifestRaw, bundleRaw, SourceRemote)
}

// accept runs every pack-side check, in the frozen order, and returns the
// activatable pack. It mutates nothing: a rejection leaves the active pack and
// the cache exactly as they were.
func (s *RulesSync) accept(manifest RulesManifestPayload, bundleRaw []byte, gateOpen bool) (acceptedPack, error) {
	pack, err := DecodeRulesPack(bundleRaw)
	if err != nil {
		return acceptedPack{}, err
	}
	if err := VerifyRulesPack(pack, s.verifier); err != nil {
		return acceptedPack{}, err
	}
	if err := checkMinBinaryVersion(pack.MinBinaryVersion, s.binary); err != nil {
		return acceptedPack{}, err
	}
	doc, signal, err := decodePackContent(bundleRaw)
	if err != nil {
		return acceptedPack{}, err
	}
	if err := filter.DefaultFloorBaseline().Check(doc); err != nil {
		return acceptedPack{}, err
	}
	compiled, err := filter.Compile(doc)
	if err != nil {
		return acceptedPack{}, err
	}
	if pack.Serial != manifest.Serial {
		return acceptedPack{}, fmt.Errorf("%w: pack serial %d, manifest serial %d", ErrSerialMismatch, pack.Serial, manifest.Serial)
	}
	if pack.Serial > math.MaxInt64 {
		return acceptedPack{}, fmt.Errorf("%w: serial above the supported range", ErrMalformedDoc)
	}
	if err := checkBundleDigest(manifest.BundleSHA256, bundleRaw); err != nil {
		return acceptedPack{}, err
	}
	warnings, err := commandWarnings(manifest, signal, pack.Serial, gateOpen)
	if err != nil {
		return acceptedPack{}, err
	}
	return acceptedPack{Serial: pack.Serial, Pack: compiled, Warnings: warnings}, nil
}

// acceptedPack is a pack that passed every check and may be activated.
type acceptedPack struct {
	Serial   uint64
	Pack     *filter.Compiled
	Warnings []string
}

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

// commandWarnings applies the OD-2 gate. A pack without command rules is
// unaffected. Once the manifest schema_version opens the gate, a command pack
// is refused with ErrCommandGate; while the gate is closed, it is accepted and
// the command rules are counted and warned about — never silently dropped —
// with a warning that names them and says they do nothing in this rewrite.
func commandWarnings(manifest RulesManifestPayload, signal *filter.CommandSignal, serial uint64, gateOpen bool) ([]string, error) {
	if !signal.Present() {
		return nil, nil
	}
	if gateOpen {
		return nil, &CommandGateError{RuleIDs: slices.Clone(signal.RuleIDs)}
	}
	message := fmt.Sprintf("rules pack %d carries %d command rule(s) (%s): a command rule does nothing in this rewrite, "+
		"and the command gate stays closed while the rules manifest schema_version is %d",
		serial, signal.Count, strings.Join(signal.RuleIDs, ", "), manifest.SchemaVersion)
	return []string{message}, nil
}
