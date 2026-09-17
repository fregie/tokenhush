// update.go is the binary update layer (W5.6): the ordered signed sequence and
// the install-source routing of D17. The sequence itself lives in selfUpdate;
// the signatures, document verification and the source policy live in
// source.go, and the artifact staging and two-phase commit live in replace.go.
//
// The ORDER is the safety property: no artifact is downloaded and nothing is
// installed until every earlier check has passed, and a rejection at any step
// leaves the running binary byte-identical.
//
//  1. revocations: fetch, decode, Ed25519 over tokenhush-update-revocations-v1
//     and freshness;
//  2. manifest: fetch, decode, Ed25519 over tokenhush-update-manifest-v1 and
//     freshness;
//  3. channel: both documents must be on the frozen stable channel;
//  4. revoked: the candidate serial and version must not be revoked by the
//     independent document or by the manifest's own advisory lists;
//  5. replay: the manifest serial against the persisted high-water mark; an
//     equal serial is up to date, a lower one is a replay;
//  6. version: the OD-1 gate; an older candidate is a downgrade unless the
//     caller's flag AND TOKENHUSH_ALLOW_DOWNGRADE both admit it;
//  7. platform: the manifest must target the running os/arch;
//  8. download: the artifact is fetched bounded by MaxArtifactBytes and its
//     SHA-256 compared in CONSTANT TIME with the digest the signed manifest
//     declares;
//  9. commit: the two-phase replace, then the anti-rollback mark.
//
// Freshness lives inside document verification, exactly as it does for the
// rules manifest. `--check` stops after step 7 and writes no state at all: no
// high-water advance, no journal, no candidate and no download to disk. The
// D17 source routing runs before the sequence, so a Homebrew, Scoop or
// unrecognised install is never self-replaced.
package supply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"
)

// updateChannel is the one accepted channel: the same frozen stable channel
// the rules stream serves.
const updateChannel = rulesChannel

// Typed rejections. Callers branch on them with errors.Is; no error text ever
// echoes untrusted document content.
var (
	// ErrUpdateChannel reports an update document on another channel.
	ErrUpdateChannel = errors.New("supply: update document is not on the stable channel")
	// ErrPlatformMismatch reports a validly signed manifest for another
	// os/arch: installing it would replace the running binary with a foreign
	// artifact.
	ErrPlatformMismatch = errors.New("supply: update targets a different os/arch")
	// ErrDowngrade reports a candidate below the running version.
	ErrDowngrade = errors.New("supply: downgrade refused")
	// ErrDelegateFailed reports a package-manager command that did not
	// succeed. Nothing was self-replaced.
	ErrDelegateFailed = errors.New("supply: package-manager delegation failed")
)

// UpdateStatus is the outcome of one update run.
type UpdateStatus string

const (
	// UpdateInstalled means a self-managed install was replaced in place.
	UpdateInstalled UpdateStatus = "installed"
	// UpdateUpToDate means the high-water mark already covers the manifest.
	UpdateUpToDate UpdateStatus = "up-to-date"
	// UpdateChecked means --check reported a verdict and changed nothing.
	UpdateChecked UpdateStatus = "checked"
	// UpdateDelegated means a package manager ran the upgrade itself.
	UpdateDelegated UpdateStatus = "delegated"
	// UpdateManual means an unrecognised install got guidance only.
	UpdateManual UpdateStatus = "manual"
)

// UpdateResult describes one update run. Command is the exact argv a
// delegation used or would use, and Message is the human-readable line Update
// wrote to Out.
type UpdateResult struct {
	Status  UpdateStatus
	Version string
	Serial  uint64
	Command []string
	Message string
}

// UpdateConfig wires the injectable seams. DataDir, Fetcher and Verifier are
// required; ArtifactFetcher defaults to Fetcher, HighWater to the frozen file
// store under DataDir, Now to time.Now, BinaryVersion to Version, Runner to a
// direct exec, LookupEnv to os.LookupEnv, Out to os.Stderr and Source to
// DefaultSource. Target defaults to the running executable.
type UpdateConfig struct {
	DataDir         string
	Target          string
	Source          InstallSource
	Fetcher         Fetcher
	ArtifactFetcher Fetcher
	Verifier        Verifier
	HighWater       HighWater
	Now             func() time.Time
	BinaryVersion   string
	GOOS            string
	GOARCH          string
	Runner          CommandRunner
	AllowDowngrade  bool
	LookupEnv       func(string) (string, bool)
	Out             io.Writer
}

// Updater runs the ordered update sequence for one install.
type Updater struct {
	fetcher        Fetcher
	artifacts      Fetcher
	verifier       Verifier
	highWater      HighWater
	now            func() time.Time
	binary         version
	binaryVersion  string
	lookupEnv      func(string) (string, bool)
	target         string
	source         InstallSource
	goos           string
	goarch         string
	runner         CommandRunner
	allowDowngrade bool
	out            io.Writer

	// kill is the crash-injection seam of the interrupted-commit tests: it is
	// invoked after a named commit step and returns a sentinel to simulate a
	// process death between two renames. Production leaves it nil.
	kill killFunc
}

// NewUpdater validates cfg and returns an updater. It performs no network
// request and writes nothing; the anti-rollback mark is only read.
func NewUpdater(cfg UpdateConfig) (*Updater, error) {
	if cfg.DataDir == "" || cfg.Fetcher == nil || cfg.Verifier == nil {
		return nil, fmt.Errorf("%w: data dir, fetcher and verifier are required", ErrBadConfig)
	}
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("%w: resolve the running binary: %w", ErrBadConfig, err)
		}
		target = exe
	}
	if _, err := newLayout(target); err != nil {
		return nil, err
	}
	highWater := cfg.HighWater
	if highWater == nil {
		mark, err := NewUpdateHighWater(cfg.DataDir)
		if err != nil {
			return nil, err
		}
		highWater = mark
	}
	if cfg.BinaryVersion == "" {
		cfg.BinaryVersion = Version
	}
	parsed, err := parseVersion(cfg.BinaryVersion)
	if err != nil {
		return nil, err
	}
	now, lookupEnv, out := cfg.Now, cfg.LookupEnv, cfg.Out
	if now == nil {
		now = time.Now
	}
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if out == nil {
		out = os.Stderr
	}
	artifacts, runner, source := cfg.ArtifactFetcher, cfg.Runner, cfg.Source
	if artifacts == nil {
		artifacts = cfg.Fetcher
	}
	if runner == nil {
		runner = execRunner
	}
	if source == "" {
		source = DefaultSource()
	}
	return &Updater{
		fetcher: cfg.Fetcher, artifacts: artifacts, verifier: cfg.Verifier, highWater: highWater,
		now: now, binary: parsed, binaryVersion: cfg.BinaryVersion, lookupEnv: lookupEnv,
		target: target, source: source, goos: firstString(cfg.GOOS, runtime.GOOS),
		goarch: firstString(cfg.GOARCH, runtime.GOARCH), runner: runner,
		allowDowngrade: cfg.AllowDowngrade, out: out,
	}, nil
}

// Update runs the D17 routing and then, for a self-managed install, the signed
// sequence. The human-readable Message is written to Out.
func (u *Updater) Update(ctx context.Context, check bool) (UpdateResult, error) {
	result, err := u.route(ctx, check)
	if err != nil {
		return result, err
	}
	if result.Message != "" {
		fmt.Fprintln(u.out, result.Message)
	}
	return result, nil
}

// selfUpdate runs the frozen sequence for a self-managed install.
func (u *Updater) selfUpdate(ctx context.Context, check bool) (UpdateResult, error) {
	if !check {
		// Self-heal first: an interrupted earlier update must be repaired
		// rather than confused with the new one.
		if _, err := Recover(u.target); err != nil {
			return UpdateResult{}, err
		}
	}
	revocations, store, err := u.fetchRevocations(ctx)
	if err != nil {
		return UpdateResult{}, err
	}
	manifest, err := u.fetchManifest(ctx)
	if err != nil {
		return UpdateResult{}, err
	}
	if revocations.Channel != updateChannel {
		return UpdateResult{}, fmt.Errorf("%w: revocations channel is %q", ErrUpdateChannel, revocations.Channel)
	}
	if manifest.Channel != updateChannel {
		return UpdateResult{}, fmt.Errorf("%w: manifest channel is %q", ErrUpdateChannel, manifest.Channel)
	}
	if err := store.Check(manifest.Serial, manifest.Version); err != nil {
		return UpdateResult{}, err
	}
	if slices.Contains(manifest.RevokedSerials, manifest.Serial) {
		return UpdateResult{}, fmt.Errorf("%w: manifest serial %d", ErrRevokedSerial, manifest.Serial)
	}
	if slices.Contains(manifest.RevokedVersions, manifest.Version) {
		return UpdateResult{}, fmt.Errorf("%w: manifest version %s", ErrRevokedVersion, manifest.Version)
	}
	switch mark := u.highWater.Current(); {
	case int64(manifest.Serial) < mark:
		return UpdateResult{}, &ReplayError{Current: mark, Attempted: int64(manifest.Serial)}
	case int64(manifest.Serial) == mark:
		return UpdateResult{Status: UpdateUpToDate, Version: manifest.Version, Serial: manifest.Serial,
			Message: fmt.Sprintf("tokenhush v%s is up to date on the %s channel (serial %d).",
				u.binaryVersion, updateChannel, manifest.Serial)}, nil
	}
	if err := checkUpdateVersion(manifest.Version, u.binary, u.allowDowngrade, u.lookupEnv); err != nil {
		return UpdateResult{}, err
	}
	if manifest.OS != u.goos || manifest.Arch != u.goarch {
		return UpdateResult{}, fmt.Errorf("%w: manifest targets %s/%s, running %s/%s",
			ErrPlatformMismatch, manifest.OS, manifest.Arch, u.goos, u.goarch)
	}
	available := fmt.Sprintf("tokenhush v%s -> v%s (serial %d) is available on the %s channel",
		u.binaryVersion, manifest.Version, manifest.Serial, updateChannel)
	if check {
		return UpdateResult{Status: UpdateChecked, Version: manifest.Version, Serial: manifest.Serial,
			Message: available + ". --check made no changes: nothing was installed, downloaded or written."}, nil
	}
	artifact, err := downloadArtifact(ctx, u.artifacts, manifest)
	if err != nil {
		return UpdateResult{}, err
	}
	if err := commitArtifact(u.target, artifact, manifest.Version, manifest.Serial, u.kill); err != nil {
		return UpdateResult{}, err
	}
	// The mark advances last: a commit that failed above stays retryable.
	if err := u.highWater.Advance(int64(manifest.Serial)); err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{Status: UpdateInstalled, Version: manifest.Version, Serial: manifest.Serial,
		Message: fmt.Sprintf("%s; installed to %s.", available, u.target)}, nil
}

func firstString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
