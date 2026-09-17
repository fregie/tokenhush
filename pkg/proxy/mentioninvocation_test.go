package proxy

// Mention-vs-invocation precision regressions.
//
// Live testing exposed the false positive this file pins from both directions:
// an ACTING tool (bash) was refused per tool call whenever its command text
// merely MENTIONED a guarded shape — `grep -rn "<the CLI form>" docs/` was
// refused, while the same search with the pattern assembled from shell fragments
// ran. The guard now discriminates structurally: only a guarded token at the
// position of a command (never an argument of an enumerated mention-carrier
// command, never inside a content here-document body) is an invocation, and the
// file-write class matches only when a write form is positionally associated
// with the listed file. See mutationinvocation.go for the rule and the lists.
//
// The tests below are deliberately two-directional: every daily operation must
// now pass WITH the literal in the argument text (no fragment-assembly
// workaround), and every real invocation must still be refused with its observed
// channel class.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// mentionStartCases are daily operations that must now pass: the guarded literal
// is present in the argument text.
var mentionStartCases = []struct {
	name string
	text string
}{
	// The exact live case: searching the repository for where the CLI is
	// documented.
	{"grep_for_the_cli_form", `grep -rn "tokenhush allowlist add entry-value" docs/`},
	{"rg_for_the_cli_form", `rg 'tokenhush allowlist' .`},
	{"grep_with_dash_e_pattern", `grep -r -e 'tokenhush allowlist add' --include='*.md' .`},
	{"grep_for_the_control_path", `grep -rn 'curl -X POST http://127.0.0.1:8787/allowlist -d' docs/`},
	{"grep_for_the_file_path", `grep -rn 'allowlist.json' docs/`},
	// Printing a file that contains the shapes through a pattern argument.
	{"sed_prints_a_matching_line", `sed -n '/tokenhush allowlist/p' docs/security.md`},
	{"awk_prints_a_matching_line", `awk '/tokenhush allowlist/' docs/security.md`},
	// Quoting the form.
	{"echo_quotes_the_cli_form", `echo 'tokenhush allowlist add entry-value'`},
	{"printf_quotes_the_cli_form", `printf '%s\n' 'tokenhush allowlist add entry-value'`},
	{"echo_quotes_the_control_path", `echo 'curl -X POST http://127.0.0.1:8787/allowlist -d'`},
	// Committing and logging a message that names the form.
	{"git_commit_names_the_form", `git commit -m "docs: explain tokenhush allowlist add"`},
	{"git_log_greps_the_form", `git log --grep='tokenhush allowlist'`},
	{"git_show_names_the_form", `git show HEAD --stat --format='%s tokenhush allowlist'`},
	// Listing and finding the file.
	{"ls_the_file", `ls -la /home/u/.local/share/tokenhush/allowlist.json`},
	{"find_the_file", `find /home/u -name allowlist.json`},
	// Reading the file (read cannot write; the bytes stay force-redacted).
	{"cat_reads_the_file", `cat /home/u/.local/share/tokenhush/allowlist.json`},
	// A here-document document write whose content references all three shapes.
	{"heredoc_document_write", "cat > docs/notes.md <<'EOF'\nThe CLI form `tokenhush allowlist add` is refused.\nThe control path http://127.0.0.1:8787/allowlist is guarded.\nThe persisted file allowlist.json is in the exclusion set.\nEOF\n"},
	// A mention nested inside a shell command string.
	{"sh_c_wrapping_a_search", `sh -c "grep -rn 'tokenhush allowlist' docs/"`},
	// A prose string that only documents the form: the guarded token is not at an
	// execution position, so it must never be refused (the explicit FP guard).
	{"prose_documents_the_cli_form", `Please run tokenhush allowlist add x to register the host.`},
	{"prose_quotes_the_cli_form", `The command "tokenhush allowlist add x" is refused by the guard.`},
	// The read-only `list` subcommand is not a mutation.
	{"read_only_list_is_not_a_mutation", `tokenhush allowlist list`},
	// Wrapper prefixes and a Windows path with spaces are recorded residuals: the
	// simple execution-position boundary set does not model them, so they are
	// mentions, never false refusals.
	{"sudo_wrapper_is_a_residual_mention", `sudo tokenhush allowlist add entry-value`},
	{"env_wrapper_is_a_residual_mention", `env TOKENHUSH_HOME=/tmp/u tokenhush allowlist add entry-value`},
	{"windows_path_with_spaces_is_a_residual_mention", `C:\Program Files\Tokenhush\tokenhush.exe allowlist add entry-value`},
}

// mentionRefuseCases are real invocations that must still be refused, with the
// channel class the classifier must report.
var mentionRefuseCases = []struct {
	name  string
	class string
	text  string
}{
	// Class 1 — genuine CLI invocations in the common wrappings. The read-only
	// `list` subcommand is not a mutation (see the rule model in
	// mutationrules.go), so every case carries a mutating `add`/`remove` verb.
	{"cli_plain", MutationChannelCLI, `tokenhush allowlist add entry-value`},
	{"cli_sh_c", MutationChannelCLI, `sh -c "tokenhush allowlist add entry-value"`},
	{"cli_bash_c", MutationChannelCLI, `bash -c 'tokenhush allowlist add entry-value'`},
	{"cli_backticks", MutationChannelCLI, "`tokenhush allowlist add entry-value`"},
	{"cli_substitution", MutationChannelCLI, `echo done && $(tokenhush allowlist remove entry-value)`},
	{"cli_pipe", MutationChannelCLI, `cat entries.txt | tokenhush allowlist remove entry-value`},
	{"cli_absolute_path", MutationChannelCLI, `/usr/local/bin/tokenhush allowlist add entry-value`},
	{"cli_after_separator_in_sh_c", MutationChannelCLI, `sh -c "grep -n x file; tokenhush allowlist add entry-value"`},
	// Class 2 — genuine control-plane reaches (HTTP client + write verb/data).
	{"curl_post_with_data", MutationChannelControlPort, `curl -X POST http://127.0.0.1:8787/allowlist -d '{"entry":"evil"}'`},
	{"curl_localhost", MutationChannelControlPort, `curl -sS http://localhost:8787/allowlist`},
	{"request_line_bare_verb", MutationChannelControlPort, `DELETE /allowlist HTTP/1.1`},
	{"netcat_space_separated", MutationChannelControlPort, `printf 'DELETE /allowlist HTTP/1.1\r\n\r\n' | nc 127.0.0.1 8787`},
	// Class 3 — genuine writes to the listed file.
	{"redirect_data_dir_path", MutationChannelFileWrite, `echo '{}' > /home/u/.local/share/tokenhush/allowlist.json`},
	{"append_basename", MutationChannelFileWrite, `printf '{}' >> allowlist.json`},
	{"tee_path", MutationChannelFileWrite, `tee /home/u/.local/share/tokenhush/allowlist.json`},
	{"cp_path", MutationChannelFileWrite, `cp /tmp/evil.json /home/u/.local/share/tokenhush/allowlist.json`},
	{"python_open_for_write", MutationChannelFileWrite, `python3 -c "open('/home/u/.local/share/tokenhush/allowlist.json','w').write('{}')"`},
	{"heredoc_into_a_shell_is_code", MutationChannelFileWrite, "bash <<'EOF'\necho '{}' > /home/u/.local/share/tokenhush/allowlist.json\nEOF\n"},
	{"heredoc_redirect_target", MutationChannelFileWrite, "cat > /home/u/.local/share/tokenhush/allowlist.json <<'EOF'\n{}\nEOF\n"},
}

// TestMentionVsInvocationBothDirections is the acceptance test with the literal
// present in every argument text: daily operations pass, real invocations are
// still refused with their channel class.
func TestMentionVsInvocationBothDirections(t *testing.T) {
	ctx := w62Context()
	for _, tc := range mentionStartCases {
		t.Run("pass/"+tc.name, func(t *testing.T) {
			if class, matched := ClassifyMutationChannel(tc.text, ctx); matched {
				t.Fatalf("daily op matched class %q, want no match: %q", class, tc.text)
			}
		})
	}
	for _, tc := range mentionRefuseCases {
		t.Run("refuse/"+tc.name, func(t *testing.T) {
			class, matched := ClassifyMutationChannel(tc.text, ctx)
			if !matched {
				t.Fatalf("invocation was not refused: %q", tc.text)
			}
			if class != tc.class {
				t.Fatalf("invocation matched class %q, want %q: %q", class, tc.class, tc.text)
			}
		})
	}
}

// TestMentionLiveGrepCaseIsNamed is the regression for the exact live case: the
// `grep` that searches for the documented CLI form must pass, and its
// command-substitution counter-case must still be refused. The literals are
// assembled here on purpose so the report names the exact case.
func TestMentionLiveGrepCaseIsNamed(t *testing.T) {
	ctx := w62Context()
	cliForm := "tokenhush" + " allowlist add entry-value"
	search := `grep -rn "` + cliForm + `" docs/`
	if class, matched := ClassifyMutationChannel(search, ctx); matched {
		t.Fatalf("the live grep false positive is back (class %q): %q", class, search)
	}
	invocation := `sh -c "` + cliForm + `"`
	if class, matched := ClassifyMutationChannel(invocation, ctx); !matched || class != MutationChannelCLI {
		t.Fatalf("sh -c invocation = (%q, %v), want (%q, true): %q", class, matched, MutationChannelCLI, invocation)
	}
}

// TestMentionCarrierListIsExplicitAndStructural pins the frozen list and proves
// every enumerated name actually suppresses a mention (so the list cannot drift
// from the behaviour it claims).
func TestMentionCarrierListIsExplicitAndStructural(t *testing.T) {
	want := []string{
		"grep", "rg", "ag", "ack", "sed", "awk", "echo", "printf",
		"cat", "head", "tail", "less", "more", "man", "ls", "find", "locate",
		"wc", "sort", "uniq", "cut", "tr", "xargs",
		"git log", "git show", "git commit", "git grep", "git diff", "git blame",
	}
	got := MutationChannelMentionCarrierCommands()
	if !slices.Equal(got, want) {
		t.Fatalf("mention-carrier list = %q, want the frozen %q", got, want)
	}
	got[0] = "tampered"
	if MutationChannelMentionCarrierCommands()[0] != "grep" {
		t.Fatal("MutationChannelMentionCarrierCommands returned an aliased slice")
	}

	ctx := w62Context()
	cliForm := "tokenhush allowlist add entry-value"
	for _, name := range want {
		var text string
		if strings.ContainsAny(name, " ") {
			command, subcommand := name[:strings.IndexByte(name, ' ')], name[strings.IndexByte(name, ' ')+1:]
			text = command + " " + subcommand + ` -m '` + cliForm + `'`
		} else {
			text = name + ` '` + cliForm + `'`
		}
		if class, matched := ClassifyMutationChannel(text, ctx); matched {
			t.Fatalf("mention carrier %q did not suppress the mention (class %q): %q", name, class, text)
		}
	}
}

// TestContentToolClassesAreMentionOnly pins the content-bearing file tool rule:
// its content is a mention for the CLI and control-port classes, while the
// file-write class stays strict on the tool's target path.
func TestContentToolClassesAreMentionOnly(t *testing.T) {
	ctx := w62Context()
	want := []string{"write", "edit", "multiedit", "apply_patch", "notebook_edit"}
	if got := MutationChannelContentTools(); !slices.Equal(got, want) {
		t.Fatalf("content tool list = %q, want %q", got, want)
	}

	mention := `Run tokenhush allowlist add x; ` +
		`curl -X POST http://127.0.0.1:8787/allowlist -d '{"entry":"x"}'; ` +
		`echo '{}' > allowlist.json`
	if class, matched := ClassifyMutationChannelContentTool(mention, ctx); matched {
		t.Fatalf("content-tool content matched class %q, want no match: %q", class, mention)
	}
	target := `/home/u/.local/share/tokenhush/allowlist.json`
	if class, matched := ClassifyMutationChannelContentTool(target, ctx); !matched || class != MutationChannelFileWrite {
		t.Fatalf("content-tool target path = (%q, %v), want (%q, true)", class, matched, MutationChannelFileWrite)
	}
	if class, matched := ClassifyMutationChannelContentTool("allowlist.json", ctx); !matched || class != MutationChannelFileWrite {
		t.Fatalf("content-tool basename target = (%q, %v), want (%q, true)", class, matched, MutationChannelFileWrite)
	}
}

// TestContentToolGuardIsPerToolCall is the end-to-end buffered check: a content
// file tool may quote the guarded shapes, an acting tool may not, and a write to
// the listed file is refused with the file-write class.
func TestContentToolGuardIsPerToolCall(t *testing.T) {
	pipe := w7Pipeline(t)
	docContent := `{"path":"docs/guard.md","content":"The guard refuses tokenhush allowlist add and POSTs to http://127.0.0.1:8787/allowlist; the file is allowlist.json."}`
	writeToFile := `{"filePath":"/home/u/.local/share/tokenhush/allowlist.json","content":"{}"}`
	acting := `{"command":"tokenhush allowlist add evil.example"}`

	fixture := w63Fixture(docContent, writeToFile, acting)
	names := []string{"write", "edit", "bash"}
	for i, name := range names {
		fixture.Choices[0].Message.ToolCalls[i].Function.Name = name
	}
	body, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	out, err := pipe.transformResponse(body, pipe.tool)
	if err != nil {
		t.Fatalf("transformResponse = %v, want nil", err)
	}
	t.Logf("CONTENT_TOOL_ORIGINAL=%s", body)
	t.Logf("CONTENT_TOOL_GUARDED=%s", out)
	w63WantArgs(t, out, docContent, w63Refusal(MutationChannelFileWrite), w63Refusal(MutationChannelCLI))
}

// TestContentToolGuardSSE is the streaming counterpart: a streamed content-
// bearing file tool whose content mentions the shapes passes byte-identically,
// while a streamed write to the listed file is still refused.
func TestContentToolGuardSSE(t *testing.T) {
	t.Run("content_write_document_passes", func(t *testing.T) {
		pipe := w7Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)
		whole := w7NamedEvent(t, "write", `{"path":"docs/guard.md","content":"The guard refuses tokenhush allowlist add and http://127.0.0.1:8787/allowlist; the file is allowlist.json."}`)
		input := append(append([]byte{}, whole...), w64FinishEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if out := rec.Body.Bytes(); !bytes.Equal(out, input) {
			t.Fatalf("streamed content write was rewritten:\n got %q\nwant %q", out, input)
		}
		if got := pipe.StreamGuardRefusals(); got != 0 {
			t.Fatalf("StreamGuardRefusals = %d, want 0", got)
		}
	})

	t.Run("content_write_to_the_listed_file_refused", func(t *testing.T) {
		pipe := w7Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)
		whole := w7NamedEvent(t, "write", `{"filePath":"/home/u/.local/share/tokenhush/allowlist.json","content":"{}"}`)
		input := append(append([]byte{}, whole...), w64FinishEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got, _ := w64Arguments(t, rec.Body.Bytes()); got != w63Refusal(MutationChannelFileWrite) {
			t.Fatalf("assembled arguments = %q, want the file-write refusal envelope", got)
		}
		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
	})
}

// TestMentionBareProseIsAMention pins the allow side of the execution-boundary
// rule: a guarded token that is not the command word of its shell segment is an
// argument of another command, hence a mention, even when the owning word is not
// one of the enumerated mention carriers. Prose cannot execute the guarded
// shape; a real invocation needs a segment start (`;`, a newline, a wrapper),
// which the refuse cases cover. This supersedes the earlier fail-closed
// direction for bare prose (the user's goal is that daily operations succeed).
func TestMentionBareProseIsAMention(t *testing.T) {
	ctx := w62Context()
	prose := `The CLI form tokenhush allowlist add is what the guard refuses.`
	if class, matched := ClassifyMutationChannel(prose, ctx); matched {
		t.Fatalf("bare prose matched class %q, want a mention: %q", class, prose)
	}
	invocation := `then; tokenhush allowlist add entry-value`
	if class, matched := ClassifyMutationChannel(invocation, ctx); !matched || class != MutationChannelCLI {
		t.Fatalf("a real invocation after `;` = (%q, %v), want (%q, true): %q", class, matched, MutationChannelCLI, invocation)
	}
}

// TestMentionRuleIsNotLengthOrProseBased is a guard against the decision being
// re-implemented as a heuristic: the same string is a mention in one position
// and an invocation in another, so only a positional rule can tell them apart.
func TestMentionRuleIsNotLengthOrProseBased(t *testing.T) {
	ctx := w62Context()
	cliForm := "tokenhush allowlist add entry-value"
	mentionText := `grep -rn "` + cliForm + `" docs/`
	invocation := cliForm
	if _, matched := ClassifyMutationChannel(mentionText, ctx); matched {
		t.Fatal("the mention position matched")
	}
	if _, matched := ClassifyMutationChannel(invocation, ctx); !matched {
		t.Fatal("the invocation position did not match")
	}
	if len(mentionText) <= len(invocation) {
		t.Fatalf("test is vacuous: the mention (%d bytes) must be longer than the invocation (%d bytes)", len(mentionText), len(invocation))
	}
}

// TestMentionEncodedArgumentsAreMentionOnly proves the encoded (valid-JSON)
// arguments shape is analysed per leaf, so a JSON wrapper around a mention no
// longer defeats the rule (the raw whole-document scan was the live leak).
func TestMentionEncodedArgumentsAreMentionOnly(t *testing.T) {
	pipe := w7Pipeline(t)
	mentionArgs := `{"command":"grep -rn \"tokenhush allowlist\" docs/"}`
	invocationArgs := `{"command":"tokenhush allowlist add evil.example"}`
	body := w7Body(t, "bash", mentionArgs, invocationArgs)

	out, err := pipe.transformResponse(body, pipe.tool)
	if err != nil {
		t.Fatalf("transformResponse = %v", err)
	}
	t.Logf("ENCODED_MENTION_ORIGINAL=%s", body)
	t.Logf("ENCODED_MENTION_GUARDED=%s", out)
	if bytes.Contains(out, []byte("tokenhush allowlist add evil.example")) {
		t.Fatalf("the invocation survived: %s", out)
	}
	w63WantArgs(t, out, mentionArgs, w63Refusal(MutationChannelCLI))
}

// mentionBisectProbe is one entry of the execution-boundary bisect table the
// fix was validated against: the live daily-ops call's commands, plus the real
// invocations that must stay refused.
type mentionBisectProbe struct {
	name    string
	text    string
	want    bool // true = must be refused (an invocation)
	channel string
}

// mentionBisectProbes substitutes the live probe's placeholders with the
// concrete binary, subcommand and checkout path.
func mentionBisectProbes() []mentionBisectProbe {
	const bin = "tokenhush-pro"
	const sub = "allowlist"
	const path = "/home/fregie/software/tokenhush-pro"
	return []mentionBisectProbe{
		{"grep_pattern", fmt.Sprintf(`grep -rn "%s %s" %s/docs/`, bin, sub, path), false, ""},
		{"git_log_grep", fmt.Sprintf(`git -C %s log --oneline --grep="%s %s"`, path, bin, sub), false, ""},
		{"printf_write", fmt.Sprintf("printf 'note: %s %s add x\\n' > /tmp/probe.md", bin, sub), false, ""},
		{"sed_prints", `sed -n '1p' /tmp/probe.md`, false, ""},
		{"cat_reads", `cat /tmp/probe.md`, false, ""},
		{"echo_quotes", fmt.Sprintf(`echo "%s %s add x"`, bin, sub), false, ""},
		{"cli_line_start", fmt.Sprintf(`%s %s add x`, bin, sub), true, MutationChannelCLI},
		{"cli_after_semicolon", fmt.Sprintf(`true; %s %s add x`, bin, sub), true, MutationChannelCLI},
		{"cli_sh_c", fmt.Sprintf(`sh -c "%s %s add x"`, bin, sub), true, MutationChannelCLI},
		{"argument_of_another_command", fmt.Sprintf(`frobnicate %s %s add x`, bin, sub), false, ""},
		{"separator_inside_a_quoted_pattern", fmt.Sprintf(`grep -rn "x; %s %s" docs/`, bin, sub), false, ""},
		// The wrapper prefixes are recorded residuals: the simple
		// execution-position boundary set does not model them.
		{"sudo_wrapper_is_a_residual", fmt.Sprintf(`sudo %s %s add x`, bin, sub), false, ""},
		{"env_assignment_wrapper_is_a_residual", fmt.Sprintf(`env FOO=bar %s %s add x`, bin, sub), false, ""},
		{"absolute_path", fmt.Sprintf(`/usr/local/bin/%s %s add x`, bin, sub), true, MutationChannelCLI},
	}
}

// TestMentionExecutionBoundaryBisect is the two-directional acceptance test for
// the execution-boundary + command-word rule on the exact live probe shapes.
func TestMentionExecutionBoundaryBisect(t *testing.T) {
	ctx := w62Context()
	for _, p := range mentionBisectProbes() {
		t.Run(p.name, func(t *testing.T) {
			class, matched := ClassifyMutationChannel(p.text, ctx)
			if matched != p.want {
				t.Fatalf("ClassifyMutationChannel(%q) = (%q, %v), want matched=%v", p.text, class, matched, p.want)
			}
			if p.want && class != p.channel {
				t.Fatalf("ClassifyMutationChannel(%q) class = %q, want %q", p.text, class, p.channel)
			}
		})
	}
}

// mentionDailyOpsCommand is the exact literal the orchestrator's daily-ops
// `bash` call carried: a grep, a git log --grep, a printf write and a sed read
// of the same documented CLI form.
func mentionDailyOpsCommand() string {
	const bin = "tokenhush-pro"
	const sub = "allowlist"
	const path = "/home/fregie/software/tokenhush-pro"
	return fmt.Sprintf("grep -rn \"%s %s\" %s/docs/\n"+
		"git -C %s log --oneline --grep=\"%s %s\"\n"+
		"printf 'note: %s %s add x\\n' > /tmp/probe.md\n"+
		"sed -n '1p' /tmp/probe.md", bin, sub, path, path, bin, sub, bin, sub)
}

// TestMentionDailyOpsCallStreamsUnrefused is the exact live regression: the
// daily-ops call arrives as the last streamed event (no trailing finish event),
// so the guard must decide on the complete accumulation and release it
// byte-identically. On the pre-fix code this path refused it with an empty
// channel (reason undecided), which is what the live gateway reported.
func TestMentionDailyOpsCallStreamsUnrefused(t *testing.T) {
	pipe := w7Pipeline(t)
	t.Run("daily_ops", func(t *testing.T) {
		w, rec := w14SSEWriter(t, pipe)
		arguments := fmt.Sprintf(`{"command":%s,"description":"daily ops"}`, strconv.Quote(mentionDailyOpsCommand()))
		input := w64ArgumentsEvent(t, arguments)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got := rec.Body.Bytes(); !bytes.Equal(got, input) {
			t.Fatalf("the daily-ops call was rewritten:\n got %q\nwant %q", got, input)
		}
		if got := pipe.StreamGuardRefusals(); got != 0 {
			t.Fatalf("StreamGuardRefusals = %d, want 0", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 0 {
			t.Fatalf("StreamGuardFailClosed = %d, want 0", got)
		}
	})

	t.Run("real_invocation_still_refused", func(t *testing.T) {
		pipe := w7Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)
		arguments := `{"command":"tokenhush-pro allowlist add evil.example"}`
		input := w64ArgumentsEvent(t, arguments)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got, _ := w64Arguments(t, rec.Body.Bytes()); got != w63Refusal(MutationChannelCLI) {
			t.Fatalf("assembled arguments = %q, want the cli-command refusal envelope", got)
		}
		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
	})
}

// TestFileWriteMentionVsInvocation pins the file-write class's positional rule:
// a listed-path mention inside another command's quoted argument is a mention,
// while a top-level redirect or a write command at a segment start is a write.
func TestFileWriteMentionVsInvocation(t *testing.T) {
	ctx := w62Context()
	for _, text := range []string{
		`grep -rn 'a > allowlist.json' docs/`,
		`grep -rn 'allowlist.json' docs/`,
		`sed -n '/allowlist.json/p' docs/security.md`,
		`git commit -m "docs: mention allowlist.json"`,
		`git log --grep='allowlist.json'`,
		`rg 'allowlist.json' .`,
		`echo 'allowlist.json is documented'`,
	} {
		if class, matched := ClassifyMutationChannel(text, ctx); matched {
			t.Fatalf("file-write mention matched class %q: %q", class, text)
		}
	}
	for _, text := range []string{
		`echo '{}' > allowlist.json`,
		`printf '{}' >> allowlist.json`,
		`echo '{}' | tee allowlist.json`,
		`sh -c "echo '{}' > /home/u/.local/share/tokenhush/allowlist.json"`,
	} {
		if class, matched := ClassifyMutationChannel(text, ctx); !matched || class != MutationChannelFileWrite {
			t.Fatalf("file-write invocation = (%q, %v), want (%q, true): %q", class, matched, MutationChannelFileWrite, text)
		}
	}
}

// TestControlPortMentionVsInvocation pins the control-port class's positional
// rule: a control path or a request verb inside another command's quoted
// argument is a mention, while an HTTP client at a segment start with a write
// verb or data flag is the control channel.
func TestControlPortMentionVsInvocation(t *testing.T) {
	ctx := w62Context()
	for _, text := range []string{
		`grep -rn 'curl -X POST http://127.0.0.1:8787/allowlist -d' docs/`,
		`echo 'DELETE /allowlist HTTP/1.1'`,
		`git log --grep='POST http://127.0.0.1:8787/allowlist'`,
		`printf 'GET http://127.0.0.1:8787/status\n'`,
	} {
		if class, matched := ClassifyMutationChannel(text, ctx); matched {
			t.Fatalf("control-port mention matched class %q: %q", class, text)
		}
	}
	for _, text := range []string{
		`curl -X POST http://127.0.0.1:8787/allowlist -d '{"entry":"evil"}'`,
		`curl -X DELETE http://127.0.0.1:8787/allowlist`,
		`wget -qO- http://[::1]:8787/allowlist`,
		`DELETE /allowlist HTTP/1.1`,
	} {
		if class, matched := ClassifyMutationChannel(text, ctx); !matched || class != MutationChannelControlPort {
			t.Fatalf("control-port invocation = (%q, %v), want (%q, true): %q", class, matched, MutationChannelControlPort, text)
		}
	}
}
