package proxy

// knownUncoveredMutations is the canonical honesty list for the C8
// mutation-channel detector (W6.2). It mirrors
// testdata/known_uncovered_mutations.txt, the documentation artifact the
// security documentation (W6.6) cites; a test asserts the two stay byte-for-
// byte equal, so neither side can drift from the other.
//
// The detector is high-confidence interception, not a closed guarantee. This
// list states the residual risk explicitly instead of implying completeness.
var knownUncoveredMutations = []string{
	"base64- or otherwise encoded command text (the shell decodes it at run time; only the literal command shape is matched)",
	"indirect execution through a script file (the detector sees the argument text, not the file's contents)",
	"multi-step assembly across separate tool calls (no single candidate carries the full command)",
	"a command split across several leaves of one tool call in a shape the nested-leaf joins do not cover",
	"fragments assembled at run time by an interpreter (for example string concatenation inside python -c)",
	"a wrapper prefix the simple execution-position boundary set does not model (for example sudo, sudo -u root, env, or a Windows executable path containing spaces): the specific command is not at a boundary, so the invocation is treated as a mention",
	"a guarded command hidden as another command's argument or piped into a shell (for example echo \"<the CLI form>\" | sh, xargs, or find -exec): the carrier/argument position is a mention",
	"write mechanisms outside the enumerated write-signal list (for example an editor save, a custom program, or a CLI not listed)",
	"indirect path spellings for the data directory (for example a symlink or a bind mount; the basename form is covered)",
	"an acting tool deliberately named like a non-action carrier tool or a content-bearing file tool (the exemption keys on function.name, the only signal available)",
}

// KnownUncoveredMutationChannels returns a copy of the mutation-channel
// classes the C8 detector deliberately does not cover.
//
// Callers that must describe the guard's limits — the security documentation,
// for example — should cite this list rather than restate it, so the code and
// the prose cannot diverge. The list is not a claim that everything else is
// covered: an entry marks a boundary of the explicitly enumerated pattern set
// (see MutationChannelPatternInventory).
func KnownUncoveredMutationChannels() []string {
	out := make([]string, len(knownUncoveredMutations))
	copy(out, knownUncoveredMutations)
	return out
}
