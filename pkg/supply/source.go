// source.go owns where an update comes from. On the install side that is the
// D17 install-source table: a plain enum (homebrew, scoop, self-managed,
// unknown), the exact delegated argv and the OD-1 rule that decides which
// candidate version this install may accept. On the release side it is the
// frozen stable channel: the two document URLs and the decode, Ed25519
// verification and freshness check the update sequence applies to them.
//
// The classification is a plain enum and nothing more: there is no action
// type, no plan and no refusal-message machinery. The updater switches on the
// enum directly, so the only fact a caller needs is which manager owns this
// binary. Detection is path- and environment-based and every input is
// injectable, so all four outcomes are reachable in a unit test without a real
// brew or scoop. An install we cannot classify is reported as unknown and is
// never self-replaced.
package supply

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// InstallSource is the install channel that owns the running binary.
type InstallSource string

const (
	// SourceHomebrew is a Homebrew install, detected from the Cellar/Caskroom
	// keg layout or a path under $HOMEBREW_PREFIX.
	SourceHomebrew InstallSource = "homebrew"
	// SourceScoop is a Scoop install, detected from the apps/shims layout, a
	// path under $SCOOP/$SCOOP_GLOBAL or the default ~/scoop root.
	SourceScoop InstallSource = "scoop"
	// SourceSelfManaged is the install script's default location,
	// <home>/.local/bin: the only install this package may self-replace.
	SourceSelfManaged InstallSource = "self-managed"
	// SourceUnknown is any install this package cannot classify. It is never
	// self-replaced.
	SourceUnknown InstallSource = "unknown"
)

// CommandRunner runs one delegated package-manager command. It is a direct
// exec, never a shell.
type CommandRunner func(ctx context.Context, argv []string) error

// DefaultSource classifies the running process with the real environment. A
// failure to resolve the executable path degrades to SourceUnknown rather
// than guessing.
func DefaultSource() InstallSource {
	exe, err := os.Executable()
	if err != nil {
		return SourceUnknown
	}
	home, _ := os.UserHomeDir()
	return DetectSource(runtime.GOOS, exe, os.Getenv, home)
}

// DetectSource is the injectable core of DefaultSource: every OS- and
// environment-dependent input is a parameter, so the darwin/linux/windows
// classification is testable from any host.
func DetectSource(goos, exe string, getenv func(string) string, home string) InstallSource {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	norm := normalizePath(goos, exe)
	if norm == "" {
		return SourceUnknown
	}
	home = normalizePath(goos, home)
	switch {
	case isBrewPath(norm, goos, getenv):
		return SourceHomebrew
	case isScoopPath(norm, goos, getenv, home):
		return SourceScoop
	case isSelfManagedPath(norm, home):
		return SourceSelfManaged
	default:
		return SourceUnknown
	}
}

// route applies the D17 install-source table before any network request: a
// package manager owns its own upgrade, and an install we cannot classify is
// only ever told how to upgrade.
func (u *Updater) route(ctx context.Context, check bool) (UpdateResult, error) {
	switch u.source {
	case SourceHomebrew:
		return u.delegate(ctx, check, brewUpgradeArgv())
	case SourceScoop:
		return u.delegate(ctx, check, scoopUpdateArgv())
	case SourceSelfManaged:
		return u.selfUpdate(ctx, check)
	default:
		// SourceUnknown — and any value this build does not recognise — gets
		// guidance only: an unclassified install is never self-replaced.
		return UpdateResult{Status: UpdateManual, Message: manualUpgradeGuidance()}, nil
	}
}

// delegate hands the upgrade to the manager that owns the binary. With check
// set it only reports the command it would run, so --check installs nothing.
func (u *Updater) delegate(ctx context.Context, check bool, argv []string) (UpdateResult, error) {
	command := strings.Join(argv, " ")
	result := UpdateResult{Status: UpdateDelegated, Command: argv}
	if check {
		result.Status = UpdateChecked
		result.Message = fmt.Sprintf("install source: %s; would run `%s`. --check made no changes: nothing was installed, downloaded or written.",
			u.source, command)
		return result, nil
	}
	if err := u.runner(ctx, argv); err != nil {
		return result, fmt.Errorf("%w: %s: %w", ErrDelegateFailed, command, err)
	}
	result.Message = fmt.Sprintf("install source: %s; delegated the upgrade to `%s`, which owns this binary and performed the replacement. tokenhush did not self-replace.",
		u.source, command)
	return result, nil
}

// brewUpgradeArgv and scoopUpdateArgv are the exact delegated commands (D17).
func brewUpgradeArgv() []string { return []string{"brew", "upgrade", "--cask", "tokenhush"} }
func scoopUpdateArgv() []string { return []string{"scoop", "update", "tokenhush"} }

// execRunner is the production CommandRunner: one direct exec, no shell, with
// the manager's own output inherited.
func execRunner(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("%w: empty command", ErrDelegateFailed)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// manualUpgradeGuidance is the message an unknown install prints instead of
// self-replacing: guidance only, never an install.
func manualUpgradeGuidance() string {
	return "could not determine how tokenhush was installed; self-update is disabled for an unrecognised install. " +
		"Upgrade manually: macOS `brew upgrade --cask tokenhush`, Windows `scoop update tokenhush`, " +
		"or re-run the install script from the release page."
}

// EnvAllowDowngrade must be set, alongside the caller's downgrade flag,
// before a downgrade is permitted: the flag alone is never enough.
const EnvAllowDowngrade = "TOKENHUSH_ALLOW_DOWNGRADE"

// checkUpdateVersion is the OD-1 gate applied to a verified manifest. A
// candidate above the running version passes; an equal one is an idempotent
// re-install; a lower one is a downgrade and needs the caller's flag AND the
// TOKENHUSH_ALLOW_DOWNGRADE opt-in, never one of them alone.
func checkUpdateVersion(candidate string, binary version, allowDowngrade bool, lookupEnv func(string) (string, bool)) error {
	parsed, err := parseVersion(candidate)
	if err != nil {
		return err
	}
	for i := range binary {
		switch {
		case parsed[i] > binary[i]:
			return nil
		case parsed[i] < binary[i]:
			if allowDowngrade && AllowDowngradeEnabled(lookupEnv) {
				return nil
			}
			return fmt.Errorf("%w: manifest version %s is below the running %d.%d.%d",
				ErrDowngrade, candidate, binary[0], binary[1], binary[2])
		}
	}
	return nil
}

// AllowDowngradeEnabled reports whether the environment opt-in is set. It is
// only half of the permission: the caller's flag is required too.
func AllowDowngradeEnabled(lookupEnv func(string) (string, bool)) bool {
	if lookupEnv == nil {
		return false
	}
	value, ok := lookupEnv(EnvAllowDowngrade)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// Frozen document URLs, composed from the W5.1 constants. Neither is
// configurable.
const (
	updateManifestURL    = BaseURL + UpdateManifestPath + ChannelQuery
	updateRevocationsURL = BaseURL + UpdateRevocationsPath + ChannelQuery
)

// fetchRevocations performs step 1: fetch, decode, verify the independent
// revocation document and return the store holding its verdict.
func (u *Updater) fetchRevocations(ctx context.Context) (UpdateRevocationsPayload, *RevocationStore, error) {
	raw, err := u.fetcher.Get(ctx, updateRevocationsURL)
	if err != nil {
		return UpdateRevocationsPayload{}, nil, err
	}
	doc, err := DecodeUpdateRevocations(raw)
	if err != nil {
		return UpdateRevocationsPayload{}, nil, err
	}
	store := NewRevocationStore()
	if err := store.ApplyUpdate(doc, u.verifier); err != nil {
		return UpdateRevocationsPayload{}, nil, err
	}
	if err := checkFreshness(doc.NotBefore, doc.Expires, u.now()); err != nil {
		return UpdateRevocationsPayload{}, nil, err
	}
	return doc, store, nil
}

// fetchManifest performs step 2: fetch, decode and verify the signed manifest.
func (u *Updater) fetchManifest(ctx context.Context) (UpdateManifestPayload, error) {
	raw, err := u.fetcher.Get(ctx, updateManifestURL)
	if err != nil {
		return UpdateManifestPayload{}, err
	}
	manifest, err := DecodeUpdateManifest(raw)
	if err != nil {
		return UpdateManifestPayload{}, err
	}
	if err := VerifyUpdateManifest(manifest, u.verifier, u.now()); err != nil {
		return UpdateManifestPayload{}, err
	}
	return manifest, nil
}

// DecodeUpdateManifest strictly decodes one raw update-manifest document under
// the update cap.
func DecodeUpdateManifest(data []byte) (UpdateManifestPayload, error) {
	var manifest UpdateManifestPayload
	if err := decodeFrozenDoc(DomainUpdateManifest, data, &manifest); err != nil {
		return UpdateManifestPayload{}, err
	}
	return manifest, nil
}

// VerifyUpdateManifest verifies a decoded update manifest: the Ed25519
// signature over the frozen tokenhush-update-manifest-v1 projection, then the
// freshness window.
func VerifyUpdateManifest(manifest UpdateManifestPayload, verifier Verifier, now time.Time) error {
	signingInput := UpdateManifestSigningInput(manifest)
	if err := verifyFrozen(verifier, DomainUpdateManifest, manifest.KeyID, manifest.Signature, signingInput); err != nil {
		return err
	}
	return checkFreshness(manifest.NotBefore, manifest.Expires, now)
}

// checkFreshness rejects a document outside its validity window.
func checkFreshness(notBefore, expires, now time.Time) error {
	if now.Before(notBefore) {
		return fmt.Errorf("%w: document is not valid before %d", ErrNotYetValid, notBefore.Unix())
	}
	if now.After(expires) {
		return fmt.Errorf("%w: document expired at %d", ErrExpired, expires.Unix())
	}
	return nil
}

// isBrewPath reports the Homebrew keg layout. The markers are capitalised on
// case-sensitive filesystems, so they are matched on a lowercased copy.
func isBrewPath(norm, goos string, getenv func(string) string) bool {
	lower := strings.ToLower(norm)
	if strings.Contains(lower, "/cellar/") || strings.Contains(lower, "/caskroom/") ||
		strings.Contains(lower, "/homebrew/") {
		return true
	}
	prefix := normalizePath(goos, getenv("HOMEBREW_PREFIX"))
	return prefix != "" && hasPathPrefix(norm, prefix)
}

// isScoopPath reports the Scoop apps/shims layout, an explicit $SCOOP root or
// the default <home>/scoop root.
func isScoopPath(norm, goos string, getenv func(string) string, home string) bool {
	if strings.Contains(norm, "/scoop/apps/") || strings.Contains(norm, "/scoop/shims/") {
		return true
	}
	for _, base := range []string{getenv("SCOOP"), getenv("SCOOP_GLOBAL")} {
		if root := normalizePath(goos, base); root != "" && hasPathPrefix(norm, root) {
			return true
		}
	}
	return home != "" && strings.HasPrefix(norm, home+"/scoop/")
}

// isSelfManagedPath reports the install script's default <home>/.local/bin. A
// blank home disables the check, so a missing home never turns a system path
// into a claimable install.
func isSelfManagedPath(norm, home string) bool {
	return home != "" && dirOf(norm) == home+"/.local/bin"
}

// normalizePath maps a path to a comparable form: backslashes become forward
// slashes, trailing separators are dropped, and Windows paths are lowercased
// because its filesystems are case-insensitive.
func normalizePath(goos, path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, `\`, "/")
	path = strings.TrimRight(path, "/")
	if goos == "windows" {
		path = strings.ToLower(path)
	}
	return path
}

// hasPathPrefix reports whether norm is prefix itself or nested below it.
func hasPathPrefix(norm, prefix string) bool {
	return norm == prefix || strings.HasPrefix(norm, prefix+"/")
}

// dirOf returns the "/"-separated parent of an already-normalized path, or ""
// when there is none.
func dirOf(norm string) string {
	idx := strings.LastIndex(norm, "/")
	switch {
	case idx < 0:
		return ""
	case idx == 0:
		return "/"
	default:
		return norm[:idx]
	}
}
