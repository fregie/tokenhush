// Package update classifies how a Tokenhush binary was installed and plans the
// package-manager-first upgrade path (ADR-0019).
//
// Plan A never self-replaces: Homebrew and Scoop installs are delegated to their
// own managers, a self-managed install only prints a "ships in a later release"
// notice, and an unknown origin gets manual guidance. Nothing in this package
// downloads, installs or writes files, and `--check` returns an informational
// plan with no executable command attached.
package update

import (
	"os"
	"runtime"
	"strings"
)

// SourceKind identifies the install channel that owns the running binary.
type SourceKind string

const (
	// SourceBrew is a Homebrew install (formula keg or cask), detected from the
	// Cellar/Caskroom layout or $HOMEBREW_PREFIX.
	SourceBrew SourceKind = "brew"
	// SourceScoop is a Scoop install on Windows, detected from the scoop
	// apps/shims layout or $SCOOP/$SCOOP_GLOBAL.
	SourceScoop SourceKind = "scoop"
	// SourceSelfManaged is a manual install such as the install script's
	// default `~/.local/bin`.
	SourceSelfManaged SourceKind = "self-managed"
	// SourceUnknown is any install this package cannot classify.
	SourceUnknown SourceKind = "unknown"
)

// ActionKind is what `update` should do for a detected source.
type ActionKind string

const (
	// ActionBrewUpgrade delegates to `brew upgrade --cask <pkg>`.
	ActionBrewUpgrade ActionKind = "brew-upgrade"
	// ActionScoopUpdate delegates to `scoop update <pkg>`.
	ActionScoopUpdate ActionKind = "scoop-update"
	// ActionSelfManaged prints the "self-update ships later" notice only.
	ActionSelfManaged ActionKind = "self-managed-notice"
	// ActionManual prints manual upgrade guidance.
	ActionManual ActionKind = "manual"
	// ActionCheck reports the source and the planned action without installing.
	ActionCheck ActionKind = "check"
)

// Source is the detected install origin of a binary.
type Source struct {
	// Kind is the classified install channel.
	Kind SourceKind
	// Exe is the executable path that was classified. It is kept for the
	// human-facing header and never appears in an executed command.
	Exe string
}

// Plan is the decided upgrade action for a Source. Command is nil for
// informational actions and for every --check plan, so an informational plan
// can never be executed.
type Plan struct {
	Source  Source
	Action  ActionKind
	Command []string
	Message string
}

// DetectSource classifies the running binary using the real process
// environment. A failure to resolve the executable path degrades safely to
// SourceUnknown rather than guessing.
func DetectSource() Source {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	home, _ := os.UserHomeDir()
	return detectSource(runtime.GOOS, exe, os.Getenv, home)
}

// PlanFor decides the upgrade action for src, where pkg is the package name
// the manager tracks (for example "tokenhush" or "tokenhush-pro").
//
// When check is true the plan is informational only: Command is nil, so no
// package-manager command can run and nothing is installed or written.
func PlanFor(src Source, pkg string, check bool) Plan {
	base := basePlan(src, pkg)
	if !check {
		return base
	}
	return Plan{
		Source:  src,
		Action:  ActionCheck,
		Message: checkMessage(base),
	}
}

// basePlan is the non-check routing table.
func basePlan(src Source, pkg string) Plan {
	switch src.Kind {
	case SourceBrew:
		command := []string{"brew", "upgrade", "--cask", pkg}
		return Plan{
			Source:  src,
			Action:  ActionBrewUpgrade,
			Command: command,
			Message: "tokenhush is managed by Homebrew; delegating the upgrade to `" +
				strings.Join(command, " ") +
				"`. Homebrew owns this binary and performs the replacement.",
		}
	case SourceScoop:
		command := []string{"scoop", "update", pkg}
		return Plan{
			Source:  src,
			Action:  ActionScoopUpdate,
			Command: command,
			Message: "tokenhush is managed by Scoop; delegating the upgrade to `" +
				strings.Join(command, " ") +
				"`. Scoop owns this binary and performs the replacement.",
		}
	case SourceSelfManaged:
		return Plan{
			Source: src,
			Action: ActionSelfManaged,
			Message: "tokenhush was installed manually (self-managed). Self-update ships in a later " +
				"release; this build only prints this notice and changes nothing on disk. To upgrade " +
				"now, re-run the install script from the release page, or install with Homebrew/Scoop.",
		}
	default:
		return Plan{
			Source: src,
			Action: ActionManual,
			Message: "could not determine how tokenhush was installed. Upgrade manually: macOS `brew upgrade --cask " +
				pkg + "`, Windows `scoop update " + pkg + "`, or re-run the install script from the release page.",
		}
	}
}

// checkMessage renders the --check report: the detected source, the action that
// would run, and the explicit statement that nothing changed.
func checkMessage(base Plan) string {
	var action string
	switch base.Action {
	case ActionBrewUpgrade, ActionScoopUpdate:
		action = "would run `" + strings.Join(base.Command, " ") + "`"
	case ActionSelfManaged:
		action = "no self-update is available in this build"
	default:
		action = "no automatic upgrade is available; manual guidance only"
	}
	return "install source: " + string(base.Source.Kind) + "; " + action +
		". --check made no changes: nothing was installed, downloaded, or written."
}

// detectSource is the pure core of DetectSource. Every OS- and
// environment-dependent input is injected so the darwin/linux/windows logic is
// testable from any host.
func detectSource(goos, exe string, getenv func(string) string, home string) Source {
	exe = strings.TrimSpace(exe)
	if exe == "" {
		return Source{Kind: SourceUnknown}
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}

	norm := normalizeForMatch(goos, exe)
	home = normalizeForMatch(goos, home)

	switch {
	case isBrewPath(goos, norm, getenv):
		return Source{Kind: SourceBrew, Exe: exe}
	case isScoopPath(goos, norm, getenv, home):
		return Source{Kind: SourceScoop, Exe: exe}
	case isSelfManagedPath(norm, home):
		return Source{Kind: SourceSelfManaged, Exe: exe}
	default:
		return Source{Kind: SourceUnknown, Exe: exe}
	}
}

// isBrewPath reports a Homebrew-managed binary: the Cellar/Caskroom keg layout
// (symlinks are resolved before this point by os.Executable) or a path under
// the configured $HOMEBREW_PREFIX.
func isBrewPath(goos, norm string, getenv func(string) string) bool {
	// The keg markers are capitalised ("Cellar", "Caskroom") on case-sensitive
	// filesystems, so match them case-insensitively on a lowercased copy.
	lower := strings.ToLower(norm)
	if strings.Contains(lower, "/cellar/") ||
		strings.Contains(lower, "/caskroom/") ||
		lower == "/cellar" || lower == "/caskroom" ||
		strings.Contains(lower, "/homebrew/") {
		return true
	}
	if prefix := normalizeForMatch(goos, getenv("HOMEBREW_PREFIX")); prefix != "" {
		return hasPathPrefix(norm, prefix)
	}
	return false
}

// isScoopPath reports a Scoop-managed binary: the apps/shims layout, a path
// under $SCOOP / $SCOOP_GLOBAL, or the default `%USERPROFILE%\scoop` root.
func isScoopPath(goos, norm string, getenv func(string) string, home string) bool {
	if strings.Contains(norm, "/scoop/apps/") || strings.Contains(norm, "/scoop/shims/") {
		return true
	}
	for _, base := range []string{getenv("SCOOP"), getenv("SCOOP_GLOBAL")} {
		if b := normalizeForMatch(goos, base); b != "" && hasPathPrefix(norm, b) {
			return true
		}
	}
	return home != "" && strings.HasPrefix(norm, home+"/scoop/")
}

// isSelfManagedPath reports the install script's default location,
// `<home>/.local/bin`. A blank home disables the check so a missing home never
// misclassifies a system path as self-managed.
func isSelfManagedPath(norm, home string) bool {
	if home == "" {
		return false
	}
	return dirOf(norm) == home+"/.local/bin"
}

// normalizeForMatch maps a path to a comparable form: backslashes become
// forward slashes, trailing separators are dropped, and Windows comparisons are
// case-insensitive because its filesystems are.
func normalizeForMatch(goos, p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimRight(p, "/")
	if goos == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// hasPathPrefix reports whether norm is prefix itself or nested below it.
func hasPathPrefix(norm, prefix string) bool {
	return norm == prefix || strings.HasPrefix(norm, prefix+"/")
}

// dirOf returns the "/"-separated parent directory of norm, or "" when there is
// none. It is used on already-normalized paths only.
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
