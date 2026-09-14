// Self-update engine for self-managed installs. It fetches the signed manifest
// and the independent signed revocation document, verifies both with the B4
// Verifier, downloads the artifact over https, checks its sha256 against the
// signed manifest, then commits it with the crash-safe two-phase replacement in
// replace.go. Any rejection leaves the running binary byte-for-byte unchanged.
//
// The engine never applies to Homebrew, Scoop or an unrecognised install, and
// it never consults the license trust chain or its revocation list: the update
// channel has its own keys and its own kill-switch (ADR-0019, ADR-0021).
package update

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
)

// MaxArtifactSize bounds a downloaded artifact before it is written to disk.
const MaxArtifactSize = 256 << 20

// Endpoint paths of the Cloudflare update service (B2 contract).
const (
	// ManifestPath serves the signed release manifest for a channel.
	ManifestPath = "/v1/update/manifest"
	// RevocationsPath serves the independent signed kill-switch document.
	RevocationsPath = "/v1/update/revocations"
	// KeyListPath serves the root-signed update key list for a channel.
	KeyListPath = "/v1/update/keylist"
)

// DefaultBaseURL is the update service origin.
const DefaultBaseURL = "https://updates.tokenhush.com"

// DefaultChannel is the release channel checked unless overridden.
const DefaultChannel = "stable"

// Errors classify engine refusals. Callers branch on them with errors.Is.
var (
	// ErrNotSelfManaged reports a brew/scoop/unknown install the engine must
	// never overwrite.
	ErrNotSelfManaged = errors.New("update: self-update is only available for self-managed installs")
	// ErrHashMismatch reports an artifact whose sha256 differs from the signed
	// manifest.
	ErrHashMismatch = errors.New("update: downloaded artifact sha256 does not match the signed manifest")
	// ErrArtifactTooLarge reports an artifact above MaxArtifactSize.
	ErrArtifactTooLarge = errors.New("update: artifact exceeds the size limit")
	// ErrHTTPStatus reports a non-200 response from the update service.
	ErrHTTPStatus = errors.New("update: unexpected HTTP status from the update service")
	// ErrChannelMismatch reports a validly signed document for a different
	// channel than the one requested.
	ErrChannelMismatch = errors.New("update: document channel does not match the requested channel")
	// ErrPlatformMismatch reports a validly signed manifest for another
	// os/arch: installing it would replace the running binary with a foreign
	// artifact.
	ErrPlatformMismatch = errors.New("update: manifest targets a different os/arch")
	// ErrMissingConfig reports an incomplete Applier configuration.
	ErrMissingConfig = errors.New("update: incomplete applier configuration")
)

// ApplyStatus is the outcome of one Apply call.
type ApplyStatus string

const (
	// ApplyUpdated means the binary was replaced in place.
	ApplyUpdated ApplyStatus = "updated"
	// ApplyUpToDate means the candidate was not newer than the running version,
	// or was an identical re-fetch already accepted.
	ApplyUpToDate ApplyStatus = "up-to-date"
	// ApplyPending means Windows staged the update for the next restart.
	ApplyPending ApplyStatus = "pending-restart"
)

// ApplyResult describes an accepted update.
type ApplyResult struct {
	Version string
	Serial  uint64
	Status  ApplyStatus
}

// ApplyConfig configures an Applier. Source and Verifier are required; Target
// defaults to Source.Exe. GOOS and GOARCH are the target platform an artifact
// must match; both default to the running process platform.
type ApplyConfig struct {
	Source     Source
	Channel    string
	BaseURL    string
	Target     string
	Verifier   *Verifier
	HTTPClient *http.Client
	GOOS       string
	GOARCH     string
	MaxSize    int64
}

// Applier downloads, verifies and installs signed updates for one install.
type Applier struct {
	source   Source
	channel  string
	baseURL  string
	target   string
	verifier *Verifier
	client   *http.Client
	goos     string
	goarch   string
	maxSize  int64
}

// NewApplier validates cfg and returns an engine. Non-self-managed sources are
// refused here, before any network call or disk write.
func NewApplier(cfg ApplyConfig) (*Applier, error) {
	if cfg.Source.Kind != SourceSelfManaged {
		return nil, fmt.Errorf("%w: %s", ErrNotSelfManaged, RefusalMessage(cfg.Source))
	}
	if cfg.Verifier == nil {
		return nil, fmt.Errorf("%w: verifier is required", ErrMissingConfig)
	}
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		target = strings.TrimSpace(cfg.Source.Exe)
	}
	if target == "" {
		return nil, fmt.Errorf("%w: target binary path is required", ErrMissingConfig)
	}
	if _, err := newLayout(target); err != nil {
		return nil, err
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if err := validateBaseURL(base); err != nil {
		return nil, err
	}
	channel := strings.TrimSpace(cfg.Channel)
	if channel == "" {
		return nil, fmt.Errorf("%w: channel is required", ErrMissingConfig)
	}
	goos := cfg.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := cfg.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	client := cfg.HTTPClient
	if client == nil {
		client = defaultApplyClient()
	}
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = MaxArtifactSize
	}
	return &Applier{
		source:   cfg.Source,
		channel:  channel,
		baseURL:  base,
		target:   target,
		verifier: cfg.Verifier,
		client:   client,
		goos:     goos,
		goarch:   goarch,
		maxSize:  maxSize,
	}, nil
}

// Apply fetches, verifies and installs the current channel release. It returns
// an error, leaving the original binary untouched, on any rejection.
func (a *Applier) Apply(ctx context.Context) (ApplyResult, error) {
	if a.source.Kind != SourceSelfManaged {
		return ApplyResult{}, ErrNotSelfManaged
	}
	rev, err := a.fetchRevocations(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	if rev.Channel != a.channel {
		return ApplyResult{}, ErrChannelMismatch
	}
	m, replayed, err := a.fetchManifest(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	if m.Channel != a.channel {
		return ApplyResult{}, ErrChannelMismatch
	}
	if candidateRevoked(rev, m) {
		return ApplyResult{}, fmt.Errorf("%w: version %s", ErrRevoked, m.Version)
	}
	if replayed && a.appliedAtLeast(m.Serial) {
		return ApplyResult{Version: m.Version, Serial: m.Serial, Status: ApplyUpToDate}, nil
	}
	if cur := a.verifier.CurrentVersion; cur != "" {
		cmp, err := CompareVersions(m.Version, cur)
		if err != nil {
			return ApplyResult{}, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if cmp == 0 {
			return ApplyResult{Version: m.Version, Serial: m.Serial, Status: ApplyUpToDate}, nil
		}
	}
	if m.OS != a.goos || m.Arch != a.goarch {
		return ApplyResult{}, fmt.Errorf("%w: manifest targets %s/%s, running %s/%s",
			ErrPlatformMismatch, m.OS, m.Arch, a.goos, a.goarch)
	}
	l, err := newLayout(a.target)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := a.download(ctx, m, l); err != nil {
		_ = os.Remove(l.new)
		return ApplyResult{}, err
	}
	restart, err := l.commit(a.goos, m.Version, m.Serial)
	if err != nil {
		return ApplyResult{}, err
	}
	_ = a.markApplied(m.Serial)
	status := ApplyUpdated
	if restart {
		status = ApplyPending
	}
	return ApplyResult{Version: m.Version, Serial: m.Serial, Status: status}, nil
}

// candidateRevoked reports whether the candidate is on the independent
// revocation document or on the manifest's own advisory lists. Authority stays
// with the independent document; the manifest lists are defence in depth (a
// valid manifest may not revoke itself, validate enforces that).
func candidateRevoked(rev RevocationList, m Manifest) bool {
	if rev.IsRevoked(m.Version, m.Serial) {
		return true
	}
	return slices.Contains(m.RevokedVersions, m.Version) || slices.Contains(m.RevokedSerials, m.Serial)
}

// appliedAtLeast reports whether serial has already been installed (the applied
// high-water reaches it). When false a replayed manifest still has to be
// fetched and installed, so a failed download can never silently suppress the
// update.
func (a *Applier) appliedAtLeast(serial uint64) bool {
	highest, ok, err := a.verifier.store().Highest(KindApplied)
	return err == nil && ok && highest >= serial
}

// markApplied records serial as installed. It never moves the mark backwards,
// so a re-verify of an older-but-installed serial is a no-op.
func (a *Applier) markApplied(serial uint64) error {
	hw := a.verifier.store()
	if highest, ok, err := hw.Highest(KindApplied); err != nil || (ok && serial <= highest) {
		return nil
	}
	return hw.Advance(KindApplied, serial)
}

// RefusalMessage explains why a non-self-managed install cannot self-update and
// how to upgrade instead.
func RefusalMessage(src Source) string {
	switch src.Kind {
	case SourceBrew:
		return "Homebrew manages this binary; run `brew upgrade --cask tokenhush`. Self-update never overwrites a package-managed install."
	case SourceScoop:
		return "Scoop manages this binary; run `scoop update tokenhush`. Self-update never overwrites a package-managed install."
	default:
		return "this install is not self-managed; upgrade via Homebrew, Scoop, or the install script. Self-update never overwrites a package-managed install."
	}
}
