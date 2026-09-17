package proxy

import (
	"fmt"
	"strings"
)

// This file is the C8 rule model. The mutation-channel guard intercepts
// SPECIFIC high-risk commands, never generic shell surface: a rule names one or
// more concrete executables (or the concrete request verbs / write commands of
// the control-plane and allowlist-file classes), optionally the mutating
// subcommand/verb shape and extra targets. A rule whose command vocabulary is a
// generic shell or interpreter (`sh`, `bash`, `python`, ...), a wrapper
// (`sudo`, `env`, ...), a redirection (`>`, `>>`) or a wildcard is invalid and
// is rejected at load time — see mutationChannelGenericCommands and
// (*rules compile path) for remote packs.
//
// The initial built-in set is exactly three rules, one per frozen class:
//
//   - cli-command/allowlist-mutation — the allowlist CLI's MUTATING subcommands
//     (`add`/`remove`); the read-only `list` is not a mutation and never matches.
//   - control-port/mutating-control-request — the control-plane write path (a
//     non-GET / mutating reach at `/allowlist` or an evidence-backed `/status`).
//   - file-write/allowlist-file — a write to the persisted allowlist file.
//
// A rule match additionally requires the named command to sit at an EXECUTION
// POSITION — the simple boundary set implemented by mutationChannelAtBoundary:
// the start of the text, or just after `;`, `&&`, `||`, `|`, a newline, a
// backtick, `$(`, or an `sh -c "`/`bash -c '` command-string opener. The
// earlier wrapper-command / wrapper-flag / command-word recomputation is
// deliberately gone: a guarded token behind a wrapper (`sudo tokenhush ...`,
// `sudo -u root ...`) is now a recorded residual rather than a modelled
// invocation. Everything else is a mention and is allowed, on top of the
// rule-independent mention exemptions (the frozen carrier-command list, the
// content-tool list and non-interpreter here-document bodies) in
// mentioninvocation.go.
//
// Rule-pack extensibility: the data-driven rules engine (pkg/rules) can add a
// high-risk command as content (`type: command`), and pkg/gateway installs the
// compiled rules through SetMutationChannelCommandRules. Adding a new high-risk
// command then needs no binary change; only the signed rule content changes.
// The proxy-side type is MutationChannelCommandRule below.

// mutationChannelRule is one built-in high-risk change-channel rule. Commands is
// the specific executable/verb vocabulary the rule is about (required, and
// validated non-generic); Subcommand/Verbs/Targets document the mutating shape
// the matcher enforces. match implements the class-specific detection on top of
// the shared execution-position qualifier.
type mutationChannelRule struct {
	ID         string
	Class      string
	Commands   []string
	Subcommand string
	Verbs      []string
	Targets    []string
	match      func(t mutationChannelText, ctx MutationChannelContext, r *mutationChannelRule) bool
}

// mutationChannelRules is the built-in rule set. It is deliberately minimal:
// exactly three specific rules, one per frozen class. Widening the built-in set
// is a security-relevant edit; new commands belong in the signed rule pack.
var mutationChannelRules = []mutationChannelRule{
	{
		ID:         "cli-command/allowlist-mutation",
		Class:      MutationChannelCLI,
		Commands:   []string{"tokenhush", "tokenhush-pro"},
		Subcommand: mutationChannelSubcommand,
		Verbs:      []string{"add", "remove"},
		match:      matchCLIAllowlistMutation,
	},
	{
		ID:       "control-port/mutating-control-request",
		Class:    MutationChannelControlPort,
		Commands: []string{"curl", "wget", "nc", "netcat", "post", "put", "patch", "delete"},
		Verbs:    []string{"post", "put", "patch", "delete"},
		Targets:  mutationChannelControlPaths,
		match:    matchControlPortRule,
	},
	{
		ID:       "file-write/allowlist-file",
		Class:    MutationChannelFileWrite,
		Commands: []string{"tee", "cp", "mv", "dd", "install", "rsync", "set-content", "add-content", "out-file", "new-item"},
		Targets:  []string{mutationChannelAllowlistFileName},
		match:    matchFileWriteRule,
	},
}

// mutationChannelRulePatterns adapts the rule table to the auditable pattern
// inventory the classifier iterates, so the pattern ids and the rule ids cannot
// drift.
func mutationChannelRulePatterns(rules []mutationChannelRule) []mutationChannelPattern {
	out := make([]mutationChannelPattern, 0, len(rules))
	for i := range rules {
		rule := rules[i]
		out = append(out, mutationChannelPattern{
			ID:    rule.ID,
			Class: rule.Class,
			match: func(t mutationChannelText, ctx MutationChannelContext) bool {
				return rule.match(t, ctx, &rule)
			},
		})
	}
	return out
}

// MutationChannelRuleIDs returns the ordered ids of the built-in high-risk
// rules, one per class. It exists so the built-in set is auditable from outside
// the package (tests, the security documentation) without exporting the
// matchers.
func MutationChannelRuleIDs() []string {
	out := make([]string, 0, len(mutationChannelRules))
	for i := range mutationChannelRules {
		out = append(out, mutationChannelRules[i].ID)
	}
	return out
}

// MutationChannelRuleCommands returns each built-in rule's specific command
// vocabulary, keyed by rule id. It exists so a test can assert that no built-in
// rule names a generic shell, wrapper, redirection or wildcard.
func MutationChannelRuleCommands() map[string][]string {
	out := make(map[string][]string, len(mutationChannelRules))
	for i := range mutationChannelRules {
		cmds := make([]string, len(mutationChannelRules[i].Commands))
		copy(cmds, mutationChannelRules[i].Commands)
		out[mutationChannelRules[i].ID] = cmds
	}
	return out
}

// --- Execution position -----------------------------------------------------

// mutationChannelCommandWordStart walks left from i over the bytes of a
// path-like command word and returns its first byte, so a path-prefixed
// executable (`/usr/local/bin/tokenhush`) is placed by the start of its path
// rather than by its basename.
func mutationChannelCommandWordStart(text string, i int) int {
	for i > 0 {
		c := text[i-1]
		ok := c == '/' || c == '\\' || c == '_' || c == '-' || c == '.' ||
			(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			break
		}
		i--
	}
	return i
}

// mutationChannelAtBoundary reports whether byte i starts a token that a shell
// would execute: the start of the text, or immediately after (whitespace past)
// `;`, `&`, `&&`, `|`, a newline, a backtick, `$(`, or an `sh -c "`/`bash -c '`
// command-string opener.
func mutationChannelAtBoundary(text string, i int) bool {
	if i <= 0 {
		return true
	}
	k := i - 1
	for k >= 0 && (text[k] == ' ' || text[k] == '\t') {
		k--
	}
	if k < 0 {
		return true
	}
	switch text[k] {
	case ';', '&', '|', '\n', '\r', '`':
		return true
	case '(':
		return k > 0 && text[k-1] == '$'
	case '"', '\'':
		return mutationChannelCommandStringQuote(text, k)
	}
	return false
}

// mutationChannelExecutionPosition reports whether the token at i (which may be
// a specific command name inside a path-prefixed word) is in an execution
// position. It never consults the wrapper-command list: `sudo tokenhush ...` is
// not in an execution position for `tokenhush`, which is the recorded residual.
func mutationChannelExecutionPosition(text string, i int) bool {
	return mutationChannelAtBoundary(text, mutationChannelCommandWordStart(text, i))
}

// mutationChannelCommandAt reports whether a command name at index j is a
// mention-exempt token that sits at an execution position. A name that is not
// the first byte of its word is accepted only when a path separator separates
// it from that word's start (a path-prefixed executable).
func mutationChannelCommandAt(t mutationChannelText, text string, j int) bool {
	if t.tokenIsMention(j) {
		return false
	}
	if w := mutationChannelCommandWordStart(text, j); w != j {
		if text[j-1] != '/' && text[j-1] != '\\' {
			return false
		}
	}
	return mutationChannelAtBoundary(text, mutationChannelCommandWordStart(text, j))
}

// mutationChannelCommandWordTokenAt reports whether token occurs at index j as a
// complete shell token (a command-start boundary before it and a command
// terminator after it) that sits at an execution position.
func mutationChannelCommandWordTokenAt(text string, j int, token string) bool {
	if j > 0 && !isCommandStartBoundary(text[j-1]) {
		return false
	}
	if end := j + len(token); end < len(text) && !isCommandTerminator(text[end]) {
		return false
	}
	return mutationChannelExecutionPosition(text, j)
}

// mutationChannelSegmentHasToken reports whether any of the given tokens occurs
// as a standalone token in text[from:end] (the remaining part of the command's
// own shell segment).
func mutationChannelSegmentHasToken(text string, from int, tokens []string) bool {
	if from >= len(text) {
		return false
	}
	end := mutationChannelSegmentEnd(text, from)
	segment := text[from:end]
	for _, token := range tokens {
		if containsCommandToken(segment, token) {
			return true
		}
	}
	return false
}

// --- Built-in rule matchers -------------------------------------------------

// matchCLIAllowlistMutation matches the allowlist CLI's mutating subcommands: a
// specific executable at an execution position, the `allowlist` subcommand, and
// a mutating verb (`add`/`remove`) in the same shell segment. The read-only
// `list` subcommand is not a mutation and never matches.
func matchCLIAllowlistMutation(t mutationChannelText, _ MutationChannelContext, r *mutationChannelRule) bool {
	text := t.raw
	for _, name := range r.Commands {
		for i := 0; ; {
			j := indexFoldFrom(text, name, i)
			if j < 0 {
				break
			}
			i = j + 1
			if !mutationChannelCommandAt(t, text, j) {
				continue
			}
			end := j + len(name)
			if hasFoldAt(text, end, ".exe") {
				end += len(".exe")
			}
			if end < len(text) && !isCommandTerminator(text[end]) {
				continue
			}
			sub := skipCommandSpace(text, end)
			if !hasFoldAt(text, sub, r.Subcommand) {
				continue
			}
			after := sub + len(r.Subcommand)
			if after < len(text) && !isCommandTerminator(text[after]) {
				continue
			}
			if !mutationChannelSegmentHasToken(text, after, r.Verbs) {
				continue
			}
			return true
		}
	}
	return false
}

// matchControlPortRule matches the control-plane write path: the host:port
// evidence, the space-separated netcat spelling, or a request line aimed at a
// control endpoint. The three control evidence forms stay in their own
// predicates; the rule only records that they are one specific class rule.
func matchControlPortRule(t mutationChannelText, ctx MutationChannelContext, _ *mutationChannelRule) bool {
	return matchControlPortHostPort(t, ctx) ||
		matchControlPortNetcat(t, ctx) ||
		matchControlPortRequestLine(t, ctx)
}

// matchFileWriteRule matches a write to the persisted allowlist file: the
// runtime path, the frozen basename, or a candidate that is exactly the path
// (a path-valued argument leaf is a direct write target for a file-writing
// tool).
func matchFileWriteRule(t mutationChannelText, ctx MutationChannelContext, _ *mutationChannelRule) bool {
	return matchFileWriteDataDirPath(t, ctx) ||
		matchFileWriteAllowlistJSON(t, ctx) ||
		matchFileWriteTargetPath(t, ctx)
}

// --- Generic-command rejection ----------------------------------------------

// mutationChannelGenericCommands are the command words a high-risk rule must
// NOT name: generic shells and interpreters, wrappers, redirection/separator
// operators and the wildcard. A rule over one of these is a blanket rule over
// generic shell surface, which is exactly what this design removes.
var mutationChannelGenericCommands = []string{
	"sh", "bash", "zsh", "ksh", "dash", "ash", "fish", "csh", "tcsh",
	"python", "python2", "python3", "perl", "ruby", "node", "nodejs", "deno",
	"php", "lua", "pwsh", "powershell", "cmd", "command", "osascript", "expect",
	"sudo", "doas", "pkexec", "runuser", "su", "env", "nohup", "exec", "eval",
	"nice", "time", "ionice", "setsid", "stdbuf", "timeout", "chrt", "taskset",
	"busybox", "xargs", "ssh", "sh -c", "bash -c",
	"*", "?", ">", ">>", "<", "|", "&", ";",
}

// mutationChannelCommandIsGeneric reports whether cmd is a generic command word
// a high-risk rule must not name. The comparison strips a path prefix and folds
// ASCII case, so `/bin/bash` is still generic.
func mutationChannelCommandIsGeneric(cmd string) bool {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" || trimmed != cmd {
		return true
	}
	if idx := strings.LastIndexAny(trimmed, `/\`); idx >= 0 {
		trimmed = trimmed[idx+1:]
	}
	for _, generic := range mutationChannelGenericCommands {
		if equalFoldASCII(trimmed, generic) {
			return true
		}
	}
	return false
}

// MutationChannelCommandRule is one rule-pack-provided high-risk command: the
// data-only form of mutationChannelRule. The gateway installs the compiled rules
// from the active signed pack through SetMutationChannelCommandRules. Command is
// the specific executable basename (required, non-generic); Subcommand is an
// optional token that must follow it; Verbs are optional mutating tokens of
// which at least one must appear in the same shell segment; Targets are optional
// literal shapes of which at least one must appear in that segment. A matched
// rule is refused with the cli-command channel class.
type MutationChannelCommandRule struct {
	ID         string
	Command    string
	Subcommand string
	Verbs      []string
	Targets    []string
}

// ValidateMutationChannelCommandRules rejects a rule set that names a generic
// command or omits the required fields. It is the proxy-side guard for the
// installed rules, mirroring pkg/rules' compile-time validation; the gateway
// compiles the pack first, so a violation here is a programming error.
func ValidateMutationChannelCommandRules(rules []MutationChannelCommandRule) error {
	for i := range rules {
		r := &rules[i]
		if strings.TrimSpace(r.Command) == "" {
			return fmt.Errorf("proxy: mutation-channel command rule %d: command is required", i)
		}
		if mutationChannelCommandIsGeneric(r.Command) {
			return fmt.Errorf("proxy: mutation-channel command rule %q: generic command %q is not a valid high-risk rule", r.ID, r.Command)
		}
	}
	return nil
}

// SetMutationChannelCommandRules installs the rule-pack-provided high-risk
// commands. It is safe on a nil receiver and a no-op when self-protection is
// disabled, matching SetSelfProtectionChannel. The rules are published through
// an atomic pointer, so a call is race-free against in-flight request
// goroutines reading them. A rule set that names a generic command is dropped
// (the built-in rules stay in force) rather than installed.
func (p *Pipeline) SetMutationChannelCommandRules(rules []MutationChannelCommandRule) {
	if p == nil || !p.selfProtectionEnabled {
		return
	}
	if len(rules) == 0 {
		p.commandRules.Store(nil)
		return
	}
	if err := ValidateMutationChannelCommandRules(rules); err != nil {
		p.commandRules.Store(nil)
		return
	}
	installed := make([]MutationChannelCommandRule, len(rules))
	for i := range rules {
		installed[i] = cloneMutationChannelCommandRule(rules[i])
	}
	p.commandRules.Store(&installed)
}

// MutationChannelCommandRules returns a copy of the currently installed
// rule-pack high-risk commands (nil when none). The returned rules belong to
// the caller.
func (p *Pipeline) MutationChannelCommandRules() []MutationChannelCommandRule {
	if p == nil {
		return nil
	}
	stored := p.commandRules.Load()
	if stored == nil {
		return nil
	}
	out := make([]MutationChannelCommandRule, len(*stored))
	for i := range *stored {
		out[i] = cloneMutationChannelCommandRule((*stored)[i])
	}
	return out
}

// cloneMutationChannelCommandRule deep-copies the slice fields so an installed
// rule cannot be mutated through the caller's slice.
func cloneMutationChannelCommandRule(r MutationChannelCommandRule) MutationChannelCommandRule {
	out := r
	out.Verbs = append([]string(nil), r.Verbs...)
	out.Targets = append([]string(nil), r.Targets...)
	return out
}

// matchMutationChannelCommandRules runs the installed rule-pack rules over text
// and reports whether any is an invocation. Every rule is refused with the
// cli-command class: an externally added high-risk command is a change-channel
// CLI command by construction.
func (p *Pipeline) matchMutationChannelCommandRules(text string, ctx MutationChannelContext) (string, bool) {
	if p == nil {
		return "", false
	}
	stored := p.commandRules.Load()
	if stored == nil || len(*stored) == 0 {
		return "", false
	}
	if !p.selfProtectionModeEnabled(MutationChannelCLI) {
		return "", false
	}
	candidate := newMutationChannelText(text)
	for i := range *stored {
		if matchMutationChannelCommandRule(candidate, &(*stored)[i]) {
			return MutationChannelCLI, true
		}
	}
	return "", false
}

// matchMutationChannelCommandRule reports whether one rule-pack rule matches
// text: its specific command at an execution position, with the optional
// subcommand, at least one mutating verb and at least one target all present in
// that command's shell segment.
func matchMutationChannelCommandRule(t mutationChannelText, r *MutationChannelCommandRule) bool {
	text := t.raw
	for i := 0; ; {
		j := indexFoldFrom(text, r.Command, i)
		if j < 0 {
			return false
		}
		i = j + 1
		if !mutationChannelCommandAt(t, text, j) {
			continue
		}
		end := j + len(r.Command)
		if hasFoldAt(text, end, ".exe") {
			end += len(".exe")
		}
		if end < len(text) && !isCommandTerminator(text[end]) {
			continue
		}
		segEnd := mutationChannelSegmentEnd(text, end)
		if r.Subcommand != "" && !mutationChannelSegmentHasToken(text, end, []string{r.Subcommand}) {
			continue
		}
		if len(r.Verbs) > 0 && !mutationChannelSegmentHasToken(text, end, r.Verbs) {
			continue
		}
		if len(r.Targets) > 0 && !mutationChannelSegmentHasAny(text[end:segEnd], r.Targets) {
			continue
		}
		return true
	}
}

// mutationChannelSegmentHasAny reports whether any of the literals occurs in
// segment (case-insensitive). Targets are literal shapes, not command tokens, so
// a path may appear inside a larger token.
func mutationChannelSegmentHasAny(segment string, targets []string) bool {
	for _, target := range targets {
		if indexFoldFrom(segment, target, 0) >= 0 {
			return true
		}
	}
	return false
}
