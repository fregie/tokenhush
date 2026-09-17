package proxy

import (
	"path/filepath"
	"strings"
)

// This file is the W6.2 mutation-channel detector: a pure, side-effect-free
// classifier over one candidate text — a tool-call argument value, or one
// nested leaf's decoded content — that reports whether the text looks like an
// attempt to reach the change channel that can weaken redaction, and which
// class matched:
//
//   - cli-command: the tokenhush / tokenhush-pro executable with the
//     `allowlist` subcommand, in the common shell wrappings;
//   - control-port: a reach for the bound control plane by its loopback
//     address or control request line, carrying a control endpoint path;
//   - file-write: a write to the persisted allowlist file
//     (<DataDir>/allowlist.json), by its runtime path or its frozen basename.
//
// The class ids are deliberately identical to pkg/config's self-protection
// mode ids (SelfProtectionModeCLICommand / ControlPort / FileWrite), so
// `self_protection.modes` gates exactly the classes below; a test pins the
// equality so the two vocabularies cannot drift.
//
// The pattern inventory is an explicitly enumerated, package-level table (see
// mutationChannelPatterns and MutationChannelPatternInventory), not scattered
// inline literals: it is testable and auditable, and the security
// documentation cites it. Matching is plain byte scanning with ASCII case
// folding — no regular expressions are compiled at call time and no allocation
// happens per call beyond the returned string constants, so the classifier is
// O(len(text)) with a small constant and safe to run over attacker-influenced
// text.
//
// Detection is high-confidence interception, not a closed guarantee: the
// deliberately uncovered classes are enumerated in
// KnownUncoveredMutationChannels and testdata/known_uncovered_mutations.txt.

// Frozen mutation-channel class ids. They are the same strings as pkg/config's
// SelfProtectionMode* constants, so the config's Modes list gates the classes
// one-to-one; TestMutationChannelFrozenIDs asserts the equality.
const (
	// MutationChannelCLI is class 1: the tokenhush / tokenhush-pro executable
	// invoked with the `allowlist` subcommand.
	MutationChannelCLI = "cli-command"
	// MutationChannelControlPort is class 2: a direct HTTP-ish connection to
	// the bound control port on a loopback address.
	MutationChannelControlPort = "control-port"
	// MutationChannelFileWrite is class 3: a direct write to the persisted
	// allowlist file (<DataDir>/allowlist.json).
	MutationChannelFileWrite = "file-write"
)

// mutationChannelClasses is the frozen, ordered class set. The order is the
// pkg/config canonical mode order, and it is the order the classifier reports
// a class in when a text hits more than one (for example a curl command that
// both connects to the control port and writes the allowlist file).
var mutationChannelClasses = [...]string{
	MutationChannelCLI,
	MutationChannelControlPort,
	MutationChannelFileWrite,
}

// MutationChannelContext carries the runtime facts the classifier needs. Both
// are known only after pkg/gateway binds the listener and resolves the data
// root, so the gateway installs them through
// (*Pipeline).SetSelfProtectionChannel once the session token exists — the
// same install point as the W6.1 exclusion set. The zero value is a complete
// no-op for the classes that need them.
type MutationChannelContext struct {
	// ControlPort is the bound control-plane port. <= 0 means unknown: the
	// control-port class then does not match any port instead of guessing.
	ControlPort int
	// AllowlistPath is the absolute path of the persisted allowlist file
	// (<DataDir>/allowlist.json). Empty means unknown: the class-3 patterns
	// that need the path stay inert (the basename-only pattern does not).
	AllowlistPath string
}

// mutationChannelPattern is one auditable entry of the detector's inventory:
// a stable id, the class it implements, and its matching predicate. The
// predicates are pure: they read the pre-analysed candidate text and ctx only.
type mutationChannelPattern struct {
	ID    string
	Class string
	match func(text mutationChannelText, ctx MutationChannelContext) bool
}

// mutationChannelPatterns is the ordered union of the three class tables,
// built once at package init. Nothing is compiled or allocated at match time.
var mutationChannelPatterns = concatMutationChannelPatterns(
	mutationChannelCLIPatterns,
	mutationChannelPortPatterns,
	mutationChannelFilePatterns,
)

// concatMutationChannelPatterns flattens the per-class tables in class order.
func concatMutationChannelPatterns(groups ...[]mutationChannelPattern) []mutationChannelPattern {
	var all []mutationChannelPattern
	for _, group := range groups {
		all = append(all, group...)
	}
	return all
}

// MutationChannelPatternInventory returns the ordered, human-readable ids of
// every pattern the detector matches, one per table entry. It exists so the
// pattern set is auditable from outside the package (tests, the security
// documentation) without exporting the predicates.
func MutationChannelPatternInventory() []string {
	out := make([]string, 0, len(mutationChannelPatterns))
	for _, pattern := range mutationChannelPatterns {
		out = append(out, pattern.ID)
	}
	return out
}

// ClassifyMutationChannel reports whether text looks like an attempt to reach
// the mutation channel and, if so, which class matched. It is pure: it reads
// no pipeline state and never mutates anything.
//
// The pipeline-level entry point W6.3/W6.4 should call is
// (*Pipeline).DetectMutationChannel, which additionally honours the
// self-protection switch and the configured mode list.
func ClassifyMutationChannel(text string, ctx MutationChannelContext) (class string, matched bool) {
	if text == "" {
		return "", false
	}
	return matchMutationChannelPatterns(mutationChannelPatterns, text, ctx)
}

// ClassifyMutationChannelContentTool is the classifier for a content-bearing
// file tool's arguments (see mutationChannelContentTools). Its content is a
// mention for the CLI and control-port classes — a document, test or fixture may
// freely reference the CLI form and the control path — so only the file-write
// class runs, and only as the target-path pattern: using the tool to write the
// listed file itself (a path-valued leaf that is exactly the file) is still
// refused. It is pure, like ClassifyMutationChannel.
func ClassifyMutationChannelContentTool(text string, ctx MutationChannelContext) (class string, matched bool) {
	if text == "" {
		return "", false
	}
	return matchMutationChannelPatterns(mutationChannelContentPatterns, text, ctx)
}

// matchMutationChannelPatterns runs the first matching entry of a pattern table
// over one candidate text, building the shared mention analysis once.
func matchMutationChannelPatterns(patterns []mutationChannelPattern, text string, ctx MutationChannelContext) (string, bool) {
	candidate := newMutationChannelText(text)
	for _, pattern := range patterns {
		if pattern.match(candidate, ctx) {
			return pattern.Class, true
		}
	}
	return "", false
}

// SetSelfProtectionChannel installs the runtime mutation-channel context (the
// bound control port and the absolute allowlist file path). The gateway calls
// it once the listener is bound and the data root is resolved — neither value
// exists at pipeline construction time — and it is safe to call again with
// refreshed values.
//
// It is safe on a nil receiver and a no-op when self-protection is disabled,
// keeping the zero value of the seam a complete no-op. The context is
// published through an atomic pointer, so a call is race-free against
// in-flight request goroutines reading it.
func (p *Pipeline) SetSelfProtectionChannel(ctx MutationChannelContext) {
	if p == nil || !p.selfProtectionEnabled {
		return
	}
	p.channelContext.Store(&ctx)
}

// MutationChannelContext returns the currently installed runtime context, or
// the zero value when none was installed (or the receiver is nil). The zero
// value leaves the control-port class and the exact-path class inert.
func (p *Pipeline) MutationChannelContext() MutationChannelContext {
	if p == nil {
		return MutationChannelContext{}
	}
	ctx := p.channelContext.Load()
	if ctx == nil {
		return MutationChannelContext{}
	}
	return *ctx
}

// DetectMutationChannel classifies one candidate text (a tool-call argument
// value or a nested leaf's content) under the pipeline's self-protection
// switch and enabled mode list, and reports the matched class. A nil or
// disabled pipeline, or a class whose mode string is not enabled, never
// matches: this is the entry point W6.3/W6.4 consume on the response path.
func (p *Pipeline) DetectMutationChannel(text string) (class string, matched bool) {
	if p == nil || !p.selfProtectionEnabled || text == "" {
		return "", false
	}
	ctx := p.MutationChannelContext()
	candidate := newMutationChannelText(text)
	for _, pattern := range mutationChannelPatterns {
		if !p.selfProtectionModeEnabled(pattern.Class) {
			continue
		}
		if pattern.match(candidate, ctx) {
			return pattern.Class, true
		}
	}
	return "", false
}

// DetectMutationChannelContentTool is the pipeline-level entry point for a
// content-bearing file tool's arguments (see ClassifyMutationChannelContentTool).
// It honours the same self-protection switch and mode list as
// DetectMutationChannel, so the file-write mode still gates it.
func (p *Pipeline) DetectMutationChannelContentTool(text string) (class string, matched bool) {
	if p == nil || !p.selfProtectionEnabled || text == "" {
		return "", false
	}
	ctx := p.MutationChannelContext()
	candidate := newMutationChannelText(text)
	for _, pattern := range mutationChannelContentPatterns {
		if !p.selfProtectionModeEnabled(pattern.Class) {
			continue
		}
		if pattern.match(candidate, ctx) {
			return pattern.Class, true
		}
	}
	return "", false
}

// selfProtectionModeEnabled reports whether class is in the pipeline's enabled
// mode list. A nil or empty list matches nothing: the mode list is the
// config-derived gate (pkg/config rejects `enabled: true` with no modes), and
// guessing a default here would silently widen what the config chose.
func (p *Pipeline) selfProtectionModeEnabled(class string) bool {
	for _, mode := range p.selfProtectionModes {
		if mode == class {
			return true
		}
	}
	return false
}

// Class 1 — the CLI.
//
// The shape is "executable name (optionally path-prefixed and quoted, with the
// Windows .exe suffix) followed by the allowlist subcommand". The bare word
// "allowlist", a different subcommand (status, doctor, ...) or a different
// binary never matches. Because the match is on text, every shell wrapping
// carries it: quotes (sh -c "..."), backticks, $(...), pipes, &&, sudo, env,
// path prefixes and line continuations.
var (
	mutationChannelCommandNames = []string{"tokenhush-pro", "tokenhush"}
	mutationChannelSubcommand   = "allowlist"
)

var mutationChannelCLIPatterns = []mutationChannelPattern{
	{ID: "cli-command/tokenhush-allowlist", Class: MutationChannelCLI, match: matchCLIAllowlistCommand},
}

// matchCLIAllowlistCommand reports whether text contains the tokenhush or
// tokenhush-pro executable followed by the allowlist subcommand at a position
// that executes it. An occurrence owned by a mention-carrier command (a search
// pattern, a quoted or printed string) or inside a content here-document body is
// a mention and does not match.
func matchCLIAllowlistCommand(t mutationChannelText, _ MutationChannelContext) bool {
	text := t.raw
	for _, name := range mutationChannelCommandNames {
		for i := 0; ; {
			j := indexFoldFrom(text, name, i)
			if j < 0 {
				break
			}
			i = j + 1
			if j > 0 && !isCommandStartBoundary(text[j-1]) {
				continue
			}
			if t.tokenIsMention(j) {
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
			if !hasFoldAt(text, sub, mutationChannelSubcommand) {
				continue
			}
			if after := sub + len(mutationChannelSubcommand); after < len(text) && !isCommandTerminator(text[after]) {
				continue
			}
			return true
		}
	}
	return false
}

// Class 2 — the control port.
//
// A loopback host with the real bound port is control evidence only when the
// same text also carries evidence of the control channel, never on the bare
// port alone: a data-plane path on the same port (for example
// http://127.0.0.1:8787/v1/chat/completions) is legitimate traffic and must not
// be refused. Two kinds of evidence count:
//
//   - a control endpoint path adjacent to the host:port (host:port/allowlist or
//     host:port/status), or a control path plus an HTTP client/verb anywhere in
//     the text (POST /allowlist with Host: 127.0.0.1:8787);
//   - a control request line against the control path (see
//     matchControlPortRequestLine), which also covers a bare `DELETE /allowlist`
//     with no host spelled at all.
//
// /status is read-only metadata (it reports counters; it cannot weaken
// redaction), so it is evidence only together with a mutation: a write verb
// (POST/PUT/PATCH/DELETE) or a curl data flag anywhere in the text. A read-only
// GET/HEAD of /status is deliberately NOT refused. /allowlist stays
// unconditional: a read of it is still a control-plane reach, and GET/DELETE to
// it remain evidence.
//
// The port stays dynamic (the real bound port from the installed context), so a
// different port, a non-loopback host, or the number in prose never matches.
var (
	mutationChannelLoopbackHosts = []string{"127.0.0.1", "localhost", "[::1]"}
	// mutationChannelControlPaths are the control-plane endpoint paths. Both are
	// required for the class to recognise the channel: /allowlist changes the
	// allowlist, /status reads the control plane's own state (read-only, so it
	// needs mutation evidence; see controlPathIsEvidence).
	mutationChannelControlPaths = []string{"/allowlist", "/status"}
	// mutationChannelHTTPSignals are distinctive, case-insensitive substrings
	// that put a host:port occurrence in an HTTP request context.
	mutationChannelHTTPSignals = []string{
		"http://", "https://", "curl", "wget", "netcat",
		"invoke-webrequest", "invoke-restmethod",
	}
	// mutationChannelHTTPVerbs are matched as standalone tokens so a verb
	// inside another word (input, compute, ...) is not a signal.
	mutationChannelHTTPVerbs = []string{"nc", "post", "delete", "put", "patch"}
	// mutationChannelRequestVerbs are the write verbs a control request line can
	// open with (DELETE /allowlist, POST /allowlist, ...). GET is deliberately
	// absent: a status read is only control evidence together with the port.
	mutationChannelRequestVerbs = []string{"post", "delete", "put", "patch"}
	// mutationChannelStatusMutationVerbs are the write verbs that make a /status
	// reach mutating rather than a read.
	mutationChannelStatusMutationVerbs = []string{"post", "delete", "put", "patch"}
	// mutationChannelStatusDataFlags are the curl/HTTP client flags that imply a
	// request body, hence a non-GET method, even when the verb is not spelled.
	mutationChannelStatusDataFlags = []string{"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"}
)

var mutationChannelPortPatterns = []mutationChannelPattern{
	{ID: "control-port/host-port", Class: MutationChannelControlPort, match: matchControlPortHostPort},
	{ID: "control-port/netcat-host-port", Class: MutationChannelControlPort, match: matchControlPortNetcat},
	{ID: "control-port/control-request-line", Class: MutationChannelControlPort, match: matchControlPortRequestLine},
}

// matchControlPortHostPort reports whether text carries a loopback host with the
// bound control port AND evidence of the control channel. The port alone is not
// evidence: an HTTP-ish context around a bare port (a URL scheme, curl/wget/nc)
// used to be enough, which refused legitimate data-plane calls to the same port.
func matchControlPortHostPort(t mutationChannelText, ctx MutationChannelContext) bool {
	if ctx.ControlPort <= 0 || ctx.ControlPort > 65535 {
		return false
	}
	text := t.raw
	var signal bool
	var signalKnown bool
	for _, host := range mutationChannelLoopbackHosts {
		for i := 0; ; {
			j := indexFoldFrom(text, host, i)
			if j < 0 {
				break
			}
			i = j + 1
			if t.tokenIsMention(j) {
				continue
			}
			colon := j + len(host)
			if colon >= len(text) || text[colon] != ':' {
				continue
			}
			end, ok := portMatchesAt(text, colon+1, ctx.ControlPort)
			if !ok {
				continue
			}
			// The direct spelling: a control endpoint immediately after the
			// host:port (host:port/allowlist, host:port/status).
			if hasControlPathAt(text, end) {
				return true
			}
			// Otherwise the text must carry a control path and an HTTP client
			// or verb (a request line the Host header points at this port). A
			// data-plane path on the same port has no control path and stays
			// unmatched.
			if !hasControlPath(text) {
				continue
			}
			if !signalKnown {
				signal, signalKnown = hasHTTPClientSignal(text), true
			}
			if signal {
				return true
			}
		}
	}
	return false
}

// matchControlPortRequestLine reports an HTTP request line whose target is a
// control endpoint path (`DELETE /allowlist HTTP/1.1`). The control path is the
// evidence: the allowlist endpoint exists only on the control plane, so a write
// verb aimed at it is a control-channel attempt even when no host:port is
// spelled (the Host header may carry the port separately, or be omitted).
func matchControlPortRequestLine(t mutationChannelText, _ MutationChannelContext) bool {
	text := t.raw
	for _, verb := range mutationChannelRequestVerbs {
		for i := 0; ; {
			j := indexFoldFrom(text, verb, i)
			if j < 0 {
				break
			}
			i = j + 1
			if j > 0 && !isCommandStartBoundary(text[j-1]) {
				continue
			}
			if t.tokenIsMention(j) {
				continue
			}
			if end := j + len(verb); end < len(text) && !isCommandTerminator(text[end]) {
				continue
			}
			if hasControlPathAt(text, skipCommandSpace(text, j+len(verb))) {
				return true
			}
		}
	}
	return false
}

// matchControlPortNetcat reports the space-separated netcat spelling
// (`nc 127.0.0.1 8787`), which carries no colon.
func matchControlPortNetcat(t mutationChannelText, ctx MutationChannelContext) bool {
	if ctx.ControlPort <= 0 || ctx.ControlPort > 65535 {
		return false
	}
	text := t.raw
	if !containsCommandToken(text, "nc") && !containsCommandToken(text, "netcat") {
		return false
	}
	for _, host := range mutationChannelLoopbackHosts {
		for i := 0; ; {
			j := indexFoldFrom(text, host, i)
			if j < 0 {
				break
			}
			i = j + 1
			if t.tokenIsMention(j) {
				continue
			}
			afterHost := j + len(host)
			port := skipCommandSpace(text, afterHost)
			if port == afterHost {
				continue
			}
			if _, ok := portMatchesAt(text, port, ctx.ControlPort); ok {
				return true
			}
		}
	}
	return false
}

// Class 3 — the allowlist file.
//
// A write-ish signal plus the allowlist file: the runtime path, its frozen
// basename, or a candidate that is exactly the path (a path-valued argument
// leaf is a direct write target for a file-writing tool). A read
// (`cat allowlist.json`) or an unrelated path never matches.
const (
	// mutationChannelAllowlistFileName is pkg/allowlist.FileName, the frozen
	// C7 persistence file name; TestMutationChannelFrozenIDs pins the equality.
	mutationChannelAllowlistFileName = "allowlist.json"
)

var mutationChannelFilePatterns = []mutationChannelPattern{
	{ID: "file-write/data-dir-path", Class: MutationChannelFileWrite, match: matchFileWriteDataDirPath},
	{ID: "file-write/allowlist-json", Class: MutationChannelFileWrite, match: matchFileWriteAllowlistJSON},
	{ID: "file-write/target-path", Class: MutationChannelFileWrite, match: matchFileWriteTargetPath},
}

// mutationChannelContentPatterns is the reduced table a content-bearing file
// tool is classified with: only the file-write class, and only its target-path
// pattern. It is a subset of mutationChannelFilePatterns, so the mode gating and
// the class vocabulary are identical; the two textual patterns are omitted
// because a document/test/fixture body mentioning the path with a redirection is
// a mention, not a write to the listed file.
var mutationChannelContentPatterns = []mutationChannelPattern{
	{ID: "file-write/target-path", Class: MutationChannelFileWrite, match: matchFileWriteTargetPath},
}

// matchFileWriteDataDirPath matches the runtime allowlist path when a write form
// targets it: the path must be preceded, in the same shell segment, by a
// redirection or write command, and must not sit inside a content here-document
// body. A bare mention of the path never matches.
func matchFileWriteDataDirPath(text mutationChannelText, ctx MutationChannelContext) bool {
	path := strings.TrimSpace(ctx.AllowlistPath)
	return path != "" && mutationChannelPathWritten(text, path)
}

// matchFileWriteAllowlistJSON matches the frozen basename under the same
// positional write rule. It deliberately needs no data directory: a relative
// write inside the data root (or a path spelled differently) still carries the
// basename.
func matchFileWriteAllowlistJSON(text mutationChannelText, _ MutationChannelContext) bool {
	return mutationChannelPathWritten(text, mutationChannelAllowlistFileName)
}

// matchFileWriteTargetPath matches a candidate that is exactly the runtime
// path (or its basename), quoted or not: a path-valued argument leaf is what a
// file-writing tool call looks like, and it also covers the read-only access
// W6.1's exclusion set protects the file content from. It is the pattern that
// keeps the file-write class strict for content-bearing file tools.
func matchFileWriteTargetPath(text mutationChannelText, ctx MutationChannelContext) bool {
	path := strings.TrimSpace(ctx.AllowlistPath)
	if path == "" {
		return false
	}
	value := trimValueQuotes(strings.TrimSpace(text.raw))
	if value == "" {
		return false
	}
	if equalFoldASCII(value, path) || equalFoldASCII(value, filepath.ToSlash(path)) {
		return true
	}
	base := filepath.Base(path)
	return base != "" && base != "." && base != "/" && equalFoldASCII(value, base)
}

// hasWriteSignal reports whether text carries a write-ish signal from the
// enumerated list: a shell redirection, a file-writing command token, a
// distinctive interpreter/API marker, an interpreter open-for-write spelling,
// a download-to-file flag or an in-place edit.
func hasWriteSignal(text string) bool {
	if strings.IndexByte(text, '>') >= 0 {
		return true
	}
	for _, token := range mutationChannelWriteTokens {
		if containsCommandToken(text, token) {
			return true
		}
	}
	for _, marker := range mutationChannelWriteMarkers {
		if indexFoldFrom(text, marker, 0) >= 0 {
			return true
		}
	}
	if hasOpenForWrite(text) {
		return true
	}
	if hasDownloadToFile(text) {
		return true
	}
	return hasSedInPlace(text)
}

// mutationChannelWriteTokens are standalone command tokens that create,
// replace, rename or truncate files.
var mutationChannelWriteTokens = []string{
	"tee", "cp", "mv", "dd", "touch", "truncate", "install", "rsync",
	"set-content", "add-content", "out-file", "new-item",
}

// mutationChannelWriteMarkers are distinctive write APIs/markers that are not
// command tokens.
var mutationChannelWriteMarkers = []string{
	"writefile", "writefilesync", "writealltext", "write_text", "file_put_contents",
}

// hasOpenForWrite reports a Python-style open-for-write spelling: an `open(`
// call and a write/append mode literal anywhere in the same text.
func hasOpenForWrite(text string) bool {
	if indexFoldFrom(text, "open(", 0) < 0 {
		return false
	}
	for _, mode := range []string{`'w'`, `"w"`, `'a'`, `"a"`} {
		if strings.Contains(text, mode) {
			return true
		}
	}
	return false
}

// hasDownloadToFile reports a curl/wget output-to-file flag.
func hasDownloadToFile(text string) bool {
	if !containsCommandToken(text, "curl") && !containsCommandToken(text, "wget") {
		return false
	}
	for _, flag := range []string{"-o", "--output", "--output-document"} {
		if containsCommandToken(text, flag) {
			return true
		}
	}
	return false
}

// hasSedInPlace reports an in-place sed edit.
func hasSedInPlace(text string) bool {
	return containsCommandToken(text, "sed") && containsCommandToken(text, "-i")
}

// --- Shared byte scanning helpers -----------------------------------------
//
// The helpers below implement ASCII-case-insensitive search and shell-token
// boundary checks with plain byte loops: no regexp, no allocation, and every
// index bound-checked so arbitrary bytes (invalid UTF-8 included) can never
// panic.

// asciiFoldLower returns the ASCII lower-case of b; every other byte passes
// through unchanged, so non-ASCII bytes compare byte-exactly.
func asciiFoldLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// hasFoldAt reports whether text from index i spells want (which must already
// be lower-case ASCII) under ASCII case folding.
func hasFoldAt(text string, i int, want string) bool {
	if i < 0 || i+len(want) > len(text) {
		return false
	}
	for k := 0; k < len(want); k++ {
		if asciiFoldLower(text[i+k]) != want[k] {
			return false
		}
	}
	return true
}

// indexFoldFrom returns the first index at or after from where want occurs in
// text under ASCII case folding, or -1.
func indexFoldFrom(text, want string, from int) int {
	if from < 0 {
		from = 0
	}
	last := len(text) - len(want)
	for i := from; i <= last; i++ {
		if hasFoldAt(text, i, want) {
			return i
		}
	}
	return -1
}

// equalFoldASCII reports byte-wise equality under ASCII case folding.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if asciiFoldLower(a[i]) != asciiFoldLower(b[i]) {
			return false
		}
	}
	return true
}

// isCommandStartBoundary reports whether b can precede a shell command or
// token: whitespace, a shell control operator, a quote, a path separator, an
// assignment or a substitution opener.
func isCommandStartBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', ';', '&', '|', '`', '(', ')', '"', '\'', '<', '>',
		'/', '\\', '=', '$', '[', '{', ',':
		return true
	}
	return false
}

// isCommandTerminator reports whether b can follow a shell command or token.
// A name character or '-' is deliberately not a terminator, so "tokenhush"
// inside "tokenhush-pro" and "allowlist" inside "allowlist.json" are not
// mistaken for complete command tokens.
func isCommandTerminator(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', ';', '&', '|', '`', ')', '"', '\'', '<', '>',
		',', ']', '}':
		return true
	}
	return false
}

// skipCommandSpace advances past shell whitespace and backslash-newline line
// continuations.
func skipCommandSpace(text string, i int) int {
	for i < len(text) {
		switch text[i] {
		case ' ', '\t', '\n', '\r':
			i++
		case '\\':
			if i+1 < len(text) && (text[i+1] == '\n' || text[i+1] == '\r') {
				i += 2
				continue
			}
			return i
		default:
			return i
		}
	}
	return i
}

// containsCommandToken reports whether token (lower-case ASCII) appears in
// text as a standalone command or verb token: preceded by a command-start
// boundary or the start of text, and followed by a command terminator or the
// end of text.
func containsCommandToken(text, token string) bool {
	for i := 0; ; {
		j := indexFoldFrom(text, token, i)
		if j < 0 {
			return false
		}
		i = j + 1
		if j > 0 && !isCommandStartBoundary(text[j-1]) {
			continue
		}
		if end := j + len(token); end < len(text) && !isCommandTerminator(text[end]) {
			continue
		}
		return true
	}
}

// hasHTTPClientSignal reports whether text carries an HTTP client or verb
// signal, putting a nearby host:port occurrence in an HTTP request context.
func hasHTTPClientSignal(text string) bool {
	for _, signal := range mutationChannelHTTPSignals {
		if indexFoldFrom(text, signal, 0) >= 0 {
			return true
		}
	}
	for _, verb := range mutationChannelHTTPVerbs {
		if containsCommandToken(text, verb) {
			return true
		}
	}
	return false
}

// controlPathIsEvidence reports whether a control endpoint path is control
// evidence in text. /allowlist always is: it is the mutating endpoint, and a
// read of it is still a control-plane reach. /status is read-only metadata, so
// it counts only when the text also carries mutation evidence (a write verb or
// a curl data flag); a plain GET/HEAD of /status is not the mutation channel.
func controlPathIsEvidence(text, path string) bool {
	return path != "/status" || hasStatusMutationEvidence(text)
}

// hasStatusMutationEvidence reports a write verb or a body-carrying curl/HTTP
// flag anywhere in text: either makes a /status reach mutating rather than a
// read.
func hasStatusMutationEvidence(text string) bool {
	for _, verb := range mutationChannelStatusMutationVerbs {
		if containsCommandToken(text, verb) {
			return true
		}
	}
	for _, flag := range mutationChannelStatusDataFlags {
		if containsCommandToken(text, flag) {
			return true
		}
	}
	return false
}

// hasControlPathAt reports whether text from index i spells a control endpoint
// path, terminated by a path, query, fragment or shell boundary.
func hasControlPathAt(text string, i int) bool {
	for _, path := range mutationChannelControlPaths {
		if !controlPathIsEvidence(text, path) {
			continue
		}
		if !hasFoldAt(text, i, path) {
			continue
		}
		end := i + len(path)
		if end == len(text) {
			return true
		}
		switch text[end] {
		case '/', '?', '#', '"', '\'', '`', ' ', '\t', '\r', '\n', ';', '&', '|', '>', '<', ')', ']', '}', ',':
			return true
		}
	}
	return false
}

// hasControlPath reports whether text contains a control endpoint path at a path
// boundary, anywhere. It is the non-adjacent half of the control evidence: a
// host:port occurrence counts only together with such a path (and an HTTP client
// or verb), so a data-plane path on the same port never matches. It applies the
// same /status read-only rule as hasControlPathAt.
func hasControlPath(text string) bool {
	for _, path := range mutationChannelControlPaths {
		if !controlPathIsEvidence(text, path) {
			continue
		}
		for i := 0; ; {
			j := indexFoldFrom(text, path, i)
			if j < 0 {
				break
			}
			i = j + 1
			if j > 0 && !isPathStartBoundary(text[j-1]) {
				continue
			}
			if hasControlPathAt(text, j) {
				return true
			}
		}
	}
	return false
}

// isPathStartBoundary reports whether b can precede a URL path token: whitespace,
// an opening quote, a grouping/assignment operator or a URL separator.
func isPathStartBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', '(', '=', ':':
		return true
	}
	return false
}

// portMatchesAt reports whether text from index i spells port in decimal
// exactly (no leading digits absorbed into a longer number) and returns the
// index just past it. It needs no allocation: the digits are recomputed from
// the integer. The loop is driven by the place value, not by p > 0, so a
// port with trailing zeros (43210) still consumes every digit.
func portMatchesAt(text string, i, port int) (int, bool) {
	if port <= 0 || i > len(text) {
		return 0, false
	}
	pow := 1
	for pow*10 <= port {
		pow *= 10
	}
	j := i
	for p := port; pow > 0; pow /= 10 {
		if j >= len(text) || text[j] != byte('0'+p/pow) {
			return 0, false
		}
		j++
		p %= pow
	}
	if j < len(text) && text[j] >= '0' && text[j] <= '9' {
		return 0, false
	}
	return j, true
}

// trimValueQuotes strips one layer of matching surrounding quotes (and any
// whitespace inside them), so a quoted path value is recognised.
func trimValueQuotes(s string) string {
	for len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') || (first == '`' && last == '`') {
			s = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		return s
	}
	return s
}
