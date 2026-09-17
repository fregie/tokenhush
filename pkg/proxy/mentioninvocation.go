package proxy

import (
	"strings"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// This file is the mention-vs-invocation precision layer of the mutation-channel
// detector. It exists because the detector originally matched the guarded
// shapes anywhere in an acting tool's argument text, which refused a tool call
// that merely MENTIONED a shape without ever executing it: live testing showed
// `grep -rn "<the CLI form>" docs/` refused while the same search assembled from
// shell fragments ran. The distinction the guard now draws is structural and
// positional, never a heuristic over prose length:
//
//   - The guarded token counts only when it sits at the position of a command
//     (the owner of its shell segment), not when it is an argument of an
//     enumerated mention-carrier command. The decisive fact is the position
//     BEFORE the token — the command whose argument it is.
//   - A non-interpreter here-document body is content, so a guarded token inside
//     it is a mention; a here-document fed to a shell/interpreter is code and
//     keeps the inspection.
//   - A file-write pattern matches only when a write form is positionally
//     associated with the listed file (a redirection or write command before the
//     path in the same shell segment), never on a bare path mention.
//
// The boundaries are deliberate and documented (docs/security.md): an attacker
// could hide a real invocation inside a quoting/search command's argument — for
// example piping it into a shell — and that is the already-recorded
// "indirect execution" uncovered class. The control-token force-redaction and
// the outbound re-check remain independent backstops.

// mutationChannelMentionCarriers is the frozen, enumerated list of commands
// whose arguments are read as text (a search pattern, a printed or quoted
// string, a path) rather than executed. When a guarded token is owned by one of
// these, it is a mention: the guard must not refuse the tool call. Entries are
// lower-case ASCII; a two-word entry (`git log`) matches the leading command
// word plus the subcommand word anywhere later in the same shell segment, so
// `git -C repo commit -m "..."` still counts. The list is deliberately closed
// and carries no user-facing config key: adding a name widens the mention
// exemption, so it is a security-relevant edit, not a convenience knob.
var mutationChannelMentionCarriers = []string{
	// search / stream editors / printers: the argument is a pattern or text.
	"grep", "rg", "ag", "ack",
	"sed", "awk",
	"echo", "printf",
	"cat", "head", "tail", "less", "more", "man",
	// read-only listings and name lookups.
	"ls", "find", "locate",
	// text utilities: the argument is text to count/sort/transform.
	"wc", "sort", "uniq", "cut", "tr",
	// xargs is enumerated as a carrier per the recorded decision: its argument
	// is treated as the pattern argument. This is a deliberate residual (it can
	// execute), documented in docs/security.md.
	"xargs",
	// git subcommands whose argument is a message, pattern or diff body.
	"git log", "git show", "git commit", "git grep", "git diff", "git blame",
}

// MutationChannelMentionCarrierCommands returns a copy of the frozen
// mention-carrier command list. It exists so the set is auditable from outside
// the package (tests, the security documentation) without exporting the mutable
// slice; the returned slice belongs to the caller.
func MutationChannelMentionCarrierCommands() []string {
	out := make([]string, len(mutationChannelMentionCarriers))
	copy(out, mutationChannelMentionCarriers)
	return out
}

// mutationChannelContentTools is the frozen, enumerated list of content-bearing
// file tools. Their arguments pair a target path with content destined for that
// file, so the content is a mention for the CLI and control-port classes: a
// document, test or fixture may freely reference the CLI form and the control
// path. The file-write class stays strict: using one of these tools to write the
// listed file itself is still refused (its target-path leaf is the write target).
//
// The list is keyed on the tool call's own `function.name`, never on the text,
// and is closed like the carrier list: an unknown name keeps the full
// inspection. See responseguard.go (buffered) and sseguard.go (streamed).
var mutationChannelContentTools = []string{
	"write", "edit", "multiedit", "apply_patch", "notebook_edit",
}

// MutationChannelContentTools returns a copy of the frozen content-bearing tool
// list. It exists so the set is auditable from outside the package (tests, the
// security documentation); the returned slice belongs to the caller.
func MutationChannelContentTools() []string {
	out := make([]string, len(mutationChannelContentTools))
	copy(out, mutationChannelContentTools)
	return out
}

// mutationChannelContentToolName reports whether name is on the frozen
// content-bearing tool list. The comparison is exact, like the carrier list, so
// a differently-spelled name fails toward inspecting.
func mutationChannelContentToolName(name string) bool {
	for _, tool := range mutationChannelContentTools {
		if name == tool {
			return true
		}
	}
	return false
}

// mutationChannelContentArgumentsPaths returns the set of walked arguments-leaf
// paths owned by a tool call whose function name is a content-bearing file tool.
// It mirrors mutationChannelCarrierArgumentsPaths, including the
// last-duplicate-key-wins rule, so the buffered guard can classify exactly those
// tool calls with the reduced content-tool table.
func mutationChannelContentArgumentsPaths(walked []protocol.Leaf) map[string]struct{} {
	var out map[string]struct{}
	for _, leaf := range walked {
		if !isMutationChannelFunctionNamePath(leaf.Path) {
			continue
		}
		argumentsPath := mutationChannelCarrierArgumentsPath(leaf.Path)
		if mutationChannelContentToolName(leaf.Content) {
			if out == nil {
				out = make(map[string]struct{}, 2)
			}
			out[argumentsPath] = struct{}{}
			continue
		}
		delete(out, argumentsPath)
	}
	return out
}

// mutationChannelInterpreterNames are the shells and interpreters whose
// here-document body is CODE, not content. A here-document fed to one of these
// keeps the full inspection; every other here-document body is a mention.
var mutationChannelInterpreterNames = []string{
	"sh", "bash", "zsh", "ksh", "dash", "ash", "fish", "csh", "tcsh",
	"python", "python2", "python3", "perl", "ruby", "node", "nodejs", "deno",
	"php", "lua", "pwsh", "powershell", "cmd", "osascript", "expect",
}

// mutationChannelText is one candidate text together with its precomputed
// mention spans. Computing the spans once per classify call keeps the match
// predicates linear in len(text) and free of repeated scans.
type mutationChannelText struct {
	raw   string
	spans []mutationChannelSpan
}

// newMutationChannelText wraps a candidate text and locates its here-document
// mention spans.
func newMutationChannelText(text string) mutationChannelText {
	return mutationChannelText{raw: text, spans: mutationChannelHeredocSpans(text)}
}

// inMentionSpan reports whether byte offset i falls inside a here-document body
// that is content rather than code.
func (t mutationChannelText) inMentionSpan(i int) bool {
	for _, span := range t.spans {
		if i >= span.start && i < span.end {
			return true
		}
	}
	return false
}

// tokenIsMention reports whether the guarded token starting at byte offset i is
// a mention rather than an invocation: it lies inside a content here-document
// body, or the command that owns its shell segment is a mention carrier.
func (t mutationChannelText) tokenIsMention(i int) bool {
	if t.inMentionSpan(i) {
		return true
	}
	return mutationChannelSegmentOwnerIsMentionCarrier(t.raw, mutationChannelSegmentStart(t.raw, i))
}

// mutationChannelSpan is a half-open byte range [start, end) of a content
// here-document body.
type mutationChannelSpan struct {
	start int
	end   int
}

// mutationChannelSegmentStart returns the index where the shell command segment
// containing byte i begins: after the nearest separator (`;`, `&`, `|`, newline),
// backtick, `$(` command substitution, or a `-c "`/`-c '` command-string
// opener. Quotes that are not a command string are transparent, so
// `grep "…"` keeps its `grep` owner.
func mutationChannelSegmentStart(text string, i int) int {
	for j := i - 1; j >= 0; j-- {
		switch text[j] {
		case ';', '&', '|', '\n', '\r', '`':
			return j + 1
		case '(':
			if j > 0 && text[j-1] == '$' {
				return j + 1
			}
		case '"', '\'':
			if mutationChannelCommandStringQuote(text, j) {
				return j + 1
			}
		}
	}
	return 0
}

// mutationChannelCommandStringQuote reports whether the quote at index j opens a
// shell command string (`sh -c "…"`, `bash -c '…'`): the previous non-space
// byte is `c` and the one before it `-`.
func mutationChannelCommandStringQuote(text string, j int) bool {
	k := j - 1
	for k >= 0 && (text[k] == ' ' || text[k] == '\t') {
		k--
	}
	return k >= 1 && (text[k] == 'c' || text[k] == 'C') && text[k-1] == '-'
}

// mutationChannelSegmentEnd returns the index where the shell command segment
// containing byte i ends (the next separator), or len(text).
func mutationChannelSegmentEnd(text string, i int) int {
	for ; i < len(text); i++ {
		switch text[i] {
		case ';', '&', '|', '\n', '\r':
			return i
		}
	}
	return len(text)
}

// mutationChannelFirstWord returns the first command-like word of text from
// segStart, skipping leading whitespace and shell punctuation (`(`, `$`,
// backtick, quotes, `<`), together with the index just past that word.
func mutationChannelFirstWord(text string, segStart int) (word string, after int) {
	i := segStart
	for i < len(text) {
		switch text[i] {
		case ' ', '\t', '\n', '\r', '(', '$', '`', '"', '\'', '<', '{', '[':
			i++
			continue
		}
		break
	}
	start := i
	for i < len(text) {
		switch text[i] {
		case ' ', '\t', '\n', '\r', ';', '&', '|', '`', '"', '\'', '<', '>',
			'(', ')', '{', '}', '[', ']', ',':
			return text[start:i], i
		}
		i++
	}
	return text[start:i], i
}

// mutationChannelSegmentOwnerIsMentionCarrier reports whether the command that
// owns text[segStart:] is on the frozen mention-carrier list. A two-word entry
// additionally requires its subcommand word later in the same segment.
func mutationChannelSegmentOwnerIsMentionCarrier(text string, segStart int) bool {
	word, after := mutationChannelFirstWord(text, segStart)
	if word == "" {
		return false
	}
	end := mutationChannelSegmentEnd(text, segStart)
	for _, entry := range mutationChannelMentionCarriers {
		space := strings.IndexByte(entry, ' ')
		if space < 0 {
			if equalFoldASCII(word, entry) {
				return true
			}
			continue
		}
		if !equalFoldASCII(word, entry[:space]) {
			continue
		}
		if after < end && containsCommandToken(text[after:end], entry[space+1:]) {
			return true
		}
	}
	return false
}

// mutationChannelHeredocSpans locates every here-document body that is content
// rather than code: the delimiter follows `<<` (optionally `<<-`, whitespace and
// a quote), the body runs from the line after the command line to the terminator
// line, and the command word introducing the here-document is not a shell or
// interpreter. A here-document fed to an interpreter returns no span, so its
// body keeps the inspection.
func mutationChannelHeredocSpans(text string) []mutationChannelSpan {
	var spans []mutationChannelSpan
	for i := 0; i+1 < len(text); i++ {
		if text[i] != '<' || text[i+1] != '<' {
			continue
		}
		delim, markupEnd, ok := mutationChannelHeredocMarker(text, i)
		if !ok {
			continue
		}
		nl := strings.IndexByte(text[markupEnd:], '\n')
		if nl < 0 {
			continue
		}
		bodyStart := markupEnd + nl + 1
		lineStart := strings.LastIndexByte(text[:i], '\n') + 1
		if word, _ := mutationChannelFirstWord(text, lineStart); mutationChannelInterpreterName(word) {
			continue
		}
		bodyEnd, terminator := mutationChannelHeredocBodyEnd(text, bodyStart, delim)
		spans = append(spans, mutationChannelSpan{start: bodyStart, end: bodyEnd})
		// Skip past the terminator line so a `<<` inside the body cannot start
		// a second, spurious span.
		i = terminator
	}
	return spans
}

// mutationChannelHeredocMarker parses a here-document operator at index i and
// returns its delimiter and the index just past the operator. `<<<` (a
// here-string, not a here-document) is not one.
func mutationChannelHeredocMarker(text string, i int) (delim string, after int, ok bool) {
	j := i + 2
	if j < len(text) && text[j] == '<' {
		return "", 0, false
	}
	if j < len(text) && text[j] == '-' {
		j++
	}
	for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
		j++
	}
	var quote byte
	if j < len(text) && (text[j] == '\'' || text[j] == '"') {
		quote = text[j]
		j++
	}
	start := j
	for j < len(text) && isHeredocDelimByte(text[j]) {
		j++
	}
	if j == start {
		return "", 0, false
	}
	delim = text[start:j]
	if quote != 0 {
		if j >= len(text) || text[j] != quote {
			return "", 0, false
		}
		j++
	}
	return delim, j, true
}

// mutationChannelHeredocBodyEnd returns the end of a here-document body (the
// start of its terminator line, or len(text)) and the index of the terminator
// line, so the caller can resume scanning after it.
func mutationChannelHeredocBodyEnd(text string, bodyStart int, delim string) (end int, terminator int) {
	for p := bodyStart; p <= len(text); {
		lineEnd := strings.IndexByte(text[p:], '\n')
		var line string
		if lineEnd < 0 {
			line = text[p:]
			lineEnd = len(text) - p
		} else {
			line = text[p : p+lineEnd]
		}
		if strings.TrimSpace(line) == delim {
			return p, p + lineEnd
		}
		if p+lineEnd >= len(text) {
			break
		}
		p += lineEnd + 1
	}
	return len(text), len(text)
}

// isHeredocDelimByte reports whether b is a here-document delimiter character.
func isHeredocDelimByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// mutationChannelInterpreterName reports whether word names a shell or
// interpreter whose here-document body is code. A path prefix is stripped, so
// `/bin/bash` still counts.
func mutationChannelInterpreterName(word string) bool {
	if idx := strings.LastIndexAny(word, `/\`); idx >= 0 {
		word = word[idx+1:]
	}
	for _, name := range mutationChannelInterpreterNames {
		if equalFoldASCII(word, name) {
			return true
		}
	}
	return false
}

// mutationChannelWritesPath reports whether a write form is positionally
// associated with the file path occurring at pathAt: a write form before the
// path within the same shell segment, and the path not inside a content
// here-document body. A bare path mention never matches.
func mutationChannelWritesPath(t mutationChannelText, pathAt int) bool {
	if t.inMentionSpan(pathAt) {
		return false
	}
	start := mutationChannelSegmentStart(t.raw, pathAt)
	before := t.raw[start:pathAt]
	if hasWriteSignal(before) {
		return true
	}
	// An open-for-write spells the mode after the path (`open('/p','w')`), so
	// the mode is searched across the whole segment while the call must precede
	// the path.
	if indexFoldFrom(before, "open(", 0) >= 0 {
		segment := t.raw[start:mutationChannelSegmentEnd(t.raw, pathAt)]
		if hasOpenForWrite(segment) {
			return true
		}
	}
	return false
}

// mutationChannelPathWritten reports whether any occurrence of needle in the
// text is a positional write target. It tries the slash-spelled variant too, so
// a Windows path written with forward slashes still matches.
func mutationChannelPathWritten(t mutationChannelText, needle string) bool {
	if needle == "" {
		return false
	}
	variants := []string{needle}
	if strings.IndexByte(needle, '\\') >= 0 {
		variants = append(variants, strings.ReplaceAll(needle, `\`, `/`))
	}
	for _, variant := range variants {
		for i := 0; ; {
			j := indexFoldFrom(t.raw, variant, i)
			if j < 0 {
				break
			}
			i = j + 1
			if mutationChannelWritesPath(t, j) {
				return true
			}
		}
	}
	return false
}
