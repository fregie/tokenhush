// Online update check: the client half that turns a root-signed key list and a
// signed manifest into a yes/no answer without touching disk or trusting an
// unverified byte. Every signature, freshness and anti-rollback decision is the
// B4 Verifier's; the bounded https-only GET is shared with the update engine.
//
// Order is deliberate: the key list is applied first, so the manifest can only
// be verified once its update key has entered through the offline root. A
// failure or an unreachable service is returned as an error and nothing is
// written anywhere.
package update

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
)

// CheckConfig configures a Checker. Source must be self-managed and Verifier
// must trust the embedded roots; HTTPClient defaults to a bounded https-only
// client.
type CheckConfig struct {
	Source     Source
	Channel    string
	BaseURL    string
	Verifier   *Verifier
	HTTPClient *http.Client
	GOOS       string
	GOARCH     string
}

// CheckResult is the user-visible outcome of one update check.
type CheckResult struct {
	CurrentVersion   string
	LatestVersion    string
	UpdateAvailable  bool
	PlatformMismatch bool
	Warnings         []string
}

// Checker fetches and verifies the key list then the manifest. It never writes
// to disk on its own: any anti-rollback mark lives in the caller-supplied
// high-water store, so a caller that must not write supplies an in-process one.
type Checker struct {
	source   Source
	channel  string
	baseURL  string
	verifier *Verifier
	client   *http.Client
	goos     string
	goarch   string
}

// NewChecker validates cfg and returns a checker. A non-self-managed source is
// refused here, before any network call or disk write.
func NewChecker(cfg CheckConfig) (*Checker, error) {
	if cfg.Source.Kind != SourceSelfManaged {
		return nil, fmt.Errorf("%w: %s", ErrNotSelfManaged, RefusalMessage(cfg.Source))
	}
	if cfg.Verifier == nil {
		return nil, fmt.Errorf("%w: verifier is required", ErrMissingConfig)
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
	return &Checker{
		source:   cfg.Source,
		channel:  channel,
		baseURL:  base,
		verifier: cfg.Verifier,
		client:   cfg.HTTPClient,
		goos:     goos,
		goarch:   goarch,
	}, nil
}

// RefreshKeys fetches the root-signed key list and installs its update keys on
// the verifier. It must run before a manifest can be verified.
func (c *Checker) RefreshKeys(ctx context.Context) error {
	raw, err := httpGet(ctx, c.client, c.keyListURL())
	if err != nil {
		return fmt.Errorf("update: fetch key list: %w", err)
	}
	if err := c.verifier.applyKeyList(raw, true); err != nil {
		return fmt.Errorf("update: key list rejected: %w", err)
	}
	return nil
}

// Check refreshes the update keys and then verifies the channel manifest,
// reporting whether a newer release exists for this platform. It writes
// nothing.
func (c *Checker) Check(ctx context.Context) (CheckResult, error) {
	if err := c.RefreshKeys(ctx); err != nil {
		return CheckResult{}, err
	}
	raw, err := httpGet(ctx, c.client, c.manifestURL())
	if err != nil {
		return CheckResult{}, fmt.Errorf("update: fetch manifest: %w", err)
	}
	m, err := c.verifier.VerifyManifest(raw)
	if err != nil {
		return CheckResult{}, fmt.Errorf("update: manifest rejected: %w", err)
	}
	if m.Channel != c.channel {
		return CheckResult{}, ErrChannelMismatch
	}
	res := CheckResult{CurrentVersion: c.verifier.CurrentVersion, LatestVersion: m.Version}
	if m.OS != c.goos || m.Arch != c.goarch {
		res.PlatformMismatch = true
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"update: manifest targets %s/%s, running %s/%s; not offering it", m.OS, m.Arch, c.goos, c.goarch))
		return res, nil
	}
	if res.CurrentVersion == "" {
		res.UpdateAvailable = true
		return res, nil
	}
	cmp, err := CompareVersions(m.Version, res.CurrentVersion)
	if err != nil {
		return CheckResult{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	res.UpdateAvailable = cmp > 0
	return res, nil
}

// keyListURL builds the channel key-list URL.
func (c *Checker) keyListURL() string {
	return c.baseURL + KeyListPath + "?channel=" + url.QueryEscape(c.channel)
}

// manifestURL builds the channel manifest URL.
func (c *Checker) manifestURL() string {
	return c.baseURL + ManifestPath + "?channel=" + url.QueryEscape(c.channel)
}
