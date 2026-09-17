package proxy

// C8 carrier-tool exemption regressions.
//
// Live testing exposed a false positive: the mutation-channel guard matched on
// text alone, so a delegation tool call (the orchestrator's own `task` tool)
// whose arguments were a long prose brief that merely MENTIONED a guarded shape
// — the CLI form, the control port with a control path, or the persisted
// allowlist file name — was refused and its arguments replaced by the refusal
// envelope, which broke the client's tool-call schema. The guard now
// discriminates on the TOOL, not on the text: an enumerated set of non-action
// carrier tools (see mutationChannelCarrierTools and MutationChannelCarrierTools)
// is not inspected, because its arguments are content destined for a human or
// another agent and cannot execute a command, make an HTTP request or write a
// file.
//
// Every other tool name keeps today's text inspection, and an unknown tool name
// still fails toward inspecting: a tool call with no sibling `name` leaf at all
// is refused exactly as before. The residual boundary — a harness that names an
// acting tool like a carrier — is documented in docs/security.md; the
// control-token force-redaction and the outbound re-check are independent and
// unaffected.
//
// See carriertools.go, responseguard.go (buffered) and sseguard.go (streamed).

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// w7Context installs the W6.2 runtime facts (the bound control port and the
// allowlist path), so the control-port and file-write classes are live in these
// tests.
func w7Context() MutationChannelContext { return w62Context() }

// w7Pipeline builds the W6.3 full-mode pipeline and installs the runtime
// channel context on it.
func w7Pipeline(t *testing.T) *Pipeline {
	t.Helper()
	pipe := w63Pipeline(t)
	pipe.SetSelfProtectionChannel(w7Context())
	return pipe
}

// w7Body builds an OpenAI-shaped response whose tool calls all carry tool as
// their function name and the given decoded arguments strings.
func w7Body(t *testing.T, tool string, args ...string) []byte {
	t.Helper()
	fixture := w63Fixture(args...)
	for i := range fixture.Choices[0].Message.ToolCalls {
		fixture.Choices[0].Message.ToolCalls[i].Function.Name = tool
	}
	body, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal response fixture: %v", err)
	}
	return body
}

// w7DelegationBrief is the prose payload that reproduces the live refusal: it
// quotes the guard's own notice, the CLI command form (plain, sh -c, backtick
// and $() wrappings), the control path with a data flag and the persisted list
// file name — all as prose, in one delegation prompt.
const w7DelegationBrief = "Delegation brief: hand this to the sub-agent and let it decide. " +
	"Context: the C8 self-protection guard refuses a tool call whose arguments match the allowlist change channel. " +
	"Examples of refused acting shapes: `tokenhush allowlist add delegated-entry`, " +
	"sh -c \"tokenhush allowlist add delegated-entry\", `tokenhush allowlist list`, " +
	"$(tokenhush allowlist remove delegated-entry), " +
	"curl -X POST http://127.0.0.1:8787/allowlist -d '{\"entry\":\"delegated-entry\"}', " +
	"DELETE /allowlist HTTP/1.1, echo '{}' > allowlist.json, " +
	"tee /home/u/.local/share/tokenhush/allowlist.json. " +
	"Task: summarise why those shapes are refused and what the human operator does instead. "

// w7DelegationProse returns the brief repeated past 4 KiB, so the regression
// covers the multi-KB prompt of the live case rather than a toy string.
func w7DelegationProse() string {
	var prose strings.Builder
	prose.WriteString(w7DelegationBrief)
	for i := 0; prose.Len() < 4<<10; i++ {
		prose.WriteString("Section ")
		prose.WriteString(strconv.Itoa(i))
		prose.WriteString(". ")
		prose.WriteString(w7DelegationBrief)
	}
	return prose.String()
}

// w7NamedEvent renders one streamed tool-call delta carrying the function name
// and one arguments fragment, so the SSE guard sees the carrier name and the
// arguments under the same tool call.
func w7NamedEvent(t *testing.T, name, fragment string) []byte {
	t.Helper()
	quotedName, err := json.Marshal(name)
	if err != nil {
		t.Fatalf("marshal function name: %v", err)
	}
	quotedArgs, err := json.Marshal(fragment)
	if err != nil {
		t.Fatalf("marshal arguments fragment: %v", err)
	}
	return []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":` +
		string(quotedName) + `,"arguments":` + string(quotedArgs) + `}}]}}]}` + "\n\n")
}

// TestToolCallCarrierExemptionAllowsContent is the live false-positive
// regression: a carrier tool whose arguments are prose that mentions every
// guarded shape must pass through byte-identically, for both argument shapes
// (a valid-JSON arguments document and a terminal non-JSON string), and no
// interference event may be reported.
func TestToolCallCarrierExemptionAllowsContent(t *testing.T) {
	prose := w7DelegationProse()

	t.Run("delegation_prose_by_carrier_tool_is_untouched", func(t *testing.T) {
		for _, tool := range []string{"task", "todowrite", "plan", "read", "grep"} {
			pipe := w7Pipeline(t)
			reporter, events := w14Reporter()
			pipe.SetRedactionReporter(reporter)

			// Valid-JSON arguments (the Encoded parent shape): the whole
			// arguments document quotes the guarded shapes.
			jsonArgs := `{"prompt":` + strconv.Quote(prose) + `,"deliverable":"summary"}`
			body := w7Body(t, tool, jsonArgs)
			out, err := pipe.transformResponse(body, pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse(%s) = %v, want nil", tool, err)
			}
			if !bytes.Equal(out, body) {
				t.Fatalf("carrier tool %q was rewritten (len %d -> %d):\n got %s\nwant %s",
					tool, len(body), len(out), out, body)
			}
			// Terminal non-JSON arguments shape.
			body = w7Body(t, tool, prose)
			out, err = pipe.transformResponse(body, pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse(%s, terminal) = %v, want nil", tool, err)
			}
			if !bytes.Equal(out, body) {
				t.Fatalf("carrier tool %q terminal arguments were rewritten:\n got %s\nwant %s", tool, out, body)
			}
			if len(*events) != 0 {
				t.Fatalf("carrier tool %q reported %d interference event(s): %+v", tool, len(*events), *events)
			}
		}
	})

	t.Run("read_only_inspection_shapes_are_untouched", func(t *testing.T) {
		// read/glob/grep cannot write, request or execute; their arguments are
		// a path or a pattern, and a pattern that matches a guarded shape is a
		// search, not an action.
		cases := []struct{ tool, args string }{
			{"read", `{"path":"/home/u/.local/share/tokenhush/allowlist.json"}`},
			{"read_file", `{"file_path":"/home/u/.local/share/tokenhush/allowlist.json"}`},
			{"glob", `{"pattern":"**/allowlist.json"}`},
			{"grep", `{"pattern":"tokenhush allowlist add","path":"/home/u/.local/share/tokenhush"}`},
			{"grep", `{"pattern":"curl -X POST http://127.0.0.1:8787/allowlist -d"}`},
		}
		for _, tc := range cases {
			pipe := w7Pipeline(t)
			body := w7Body(t, tc.tool, tc.args)
			out, err := pipe.transformResponse(body, pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse(%s) = %v, want nil", tc.tool, err)
			}
			if !bytes.Equal(out, body) {
				t.Fatalf("carrier tool %q was rewritten:\n got %s\nwant %s", tc.tool, out, body)
			}
		}
	})
}

// TestToolCallCarrierExemptionActingToolsStillRefused is the other direction:
// the same guarded shapes in an ACTING tool call are refused exactly as before,
// per call, with the observed channel class.
func TestToolCallCarrierExemptionActingToolsStillRefused(t *testing.T) {
	pipe := w7Pipeline(t)
	cases := []struct {
		name        string
		tool        string
		args        string
		wantChannel string
	}{
		{"cli_plain", "bash", `{"command":"tokenhush allowlist add evil.example"}`, MutationChannelCLI},
		{"cli_sh_c", "shell", `{"command":"sh -c \"tokenhush allowlist add evil.example\""}`, MutationChannelCLI},
		{"cli_backticks", "exec", "{\"command\":\"`tokenhush allowlist add evil.example`\"}", MutationChannelCLI},
		{"cli_substitution", "terminal", `{"command":"echo done && $(tokenhush allowlist remove evil.example)"}`, MutationChannelCLI},
		{"control_post_with_data", "bash", `{"command":"curl -X POST http://127.0.0.1:8787/allowlist -d '{\"entry\":\"evil\"}'"}`, MutationChannelControlPort},
		{"control_request_line", "powershell", `{"command":"DELETE /allowlist HTTP/1.1\r\nHost: 127.0.0.1:8787"}`, MutationChannelControlPort},
		{"file_write_redirect", "shell", `{"command":"echo '{}' > /home/u/.local/share/tokenhush/allowlist.json"}`, MutationChannelFileWrite},
		{"file_target_path", "write", `{"path":"/home/u/.local/share/tokenhush/allowlist.json"}`, MutationChannelFileWrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := w7Body(t, tc.tool, tc.args)
			out, err := pipe.transformResponse(body, pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse = %v, want nil (only the tool call is refused)", err)
			}
			args := w63Arguments(t, out)
			w63AssertRefusal(t, args[0], tc.wantChannel)
			t.Logf("acting tool %q: channel=%s args=%s", tc.tool, tc.wantChannel, args[0])
		})
	}
}

// TestToolCallCarrierExemptionKeepsFailClosed pins the two shapes that must NOT
// gain the exemption: an unknown tool name and a tool call with no sibling
// function-name leaf at all keep today's inspection and refusal.
func TestToolCallCarrierExemptionKeepsFailClosed(t *testing.T) {
	pipe := w7Pipeline(t)

	t.Run("unknown_tool_name_is_still_inspected", func(t *testing.T) {
		// apply_patch is deliberately NOT here: it is a content-bearing file
		// tool (see mutationChannelContentTools), so its content is a mention
		// for the CLI/control-port classes while the file-write class stays
		// strict. A name on neither list keeps the full inspection.
		for _, tool := range []string{"mystery_tool", "run_command", "str_replace_editor"} {
			body := w7Body(t, tool, `{"cmd":"tokenhush allowlist add evil.example"}`)
			out, err := pipe.transformResponse(body, pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse(%s) = %v, want nil", tool, err)
			}
			args := w63Arguments(t, out)
			w63AssertRefusal(t, args[0], MutationChannelCLI)
			t.Logf("unknown tool %q refused: channel=%s", tool, MutationChannelCLI)
		}
	})

	t.Run("absent_function_name_leaf_is_still_inspected", func(t *testing.T) {
		// No function.name sibling exists, so the tool is unknown and the guard
		// keeps its pre-exemption behaviour.
		raw := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[` +
			`{"id":"call_1","type":"function","function":{"arguments":"{\"cmd\":\"tokenhush allowlist add evil.example\"}"}}]}}]}`)
		out, err := pipe.transformResponse(raw, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		args := w63Arguments(t, out)
		w63AssertRefusal(t, args[0], MutationChannelCLI)
	})

	t.Run("carrier_like_leaf_outside_the_tool_call_does_not_exempt", func(t *testing.T) {
		// The name value "task" sits on the message, not as the function-name
		// sibling of the arguments leaf: the decision is structural (same tool
		// call), never a text search for a carrier word.
		raw := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","tool":"task","tool_calls":[` +
			`{"id":"call_1","type":"function","function":{"arguments":"{\"cmd\":\"tokenhush allowlist add evil.example\"}"}}]}}]}`)
		out, err := pipe.transformResponse(raw, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		args := w63Arguments(t, out)
		w63AssertRefusal(t, args[0], MutationChannelCLI)
	})

	t.Run("carrier_name_with_other_case_is_still_inspected", func(t *testing.T) {
		// The list comparison is exact: a differently-spelled name is unknown
		// and keeps the text inspection (the fail-closed direction).
		for _, tool := range []string{"Task", "TASK", "task "} {
			body := w7Body(t, tool, `{"cmd":"tokenhush allowlist add evil.example"}`)
			out, err := pipe.transformResponse(body, pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse(%q) = %v, want nil", tool, err)
			}
			args := w63Arguments(t, out)
			w63AssertRefusal(t, args[0], MutationChannelCLI)
		}
	})

	t.Run("last_duplicate_function_name_wins", func(t *testing.T) {
		// JSON keeps the last duplicate object member (encoding/json semantics),
		// and the carrier map is filled in document order, so the effective name
		// decides: task last exempts, bash last keeps the refusal.
		allowed := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[` +
			`{"id":"call_1","type":"function","function":{"name":"bash","name":"task","arguments":"{\"cmd\":\"tokenhush allowlist add evil.example\"}"}}]}}]}`)
		out, err := pipe.transformResponse(allowed, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		if !bytes.Equal(out, allowed) {
			t.Fatalf("effective carrier name (last duplicate) did not exempt:\n got %s\nwant %s", out, allowed)
		}
		refused := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[` +
			`{"id":"call_1","type":"function","function":{"name":"task","name":"bash","arguments":"{\"cmd\":\"tokenhush allowlist add evil.example\"}"}}]}}]}`)
		out, err = pipe.transformResponse(refused, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		args := w63Arguments(t, out)
		w63AssertRefusal(t, args[0], MutationChannelCLI)
	})
}

// TestMutationChannelCarrierToolsFrozen pins the enumerated carrier list: the
// exact set, its invariants, the acting names it must not contain, that the
// exported accessor returns a defensive copy, and that every name on the list
// actually exempts a matching payload (the list cannot silently drift from the
// behaviour it describes).
func TestMutationChannelCarrierToolsFrozen(t *testing.T) {
	want := []string{
		"task", "spawn_agent", "subagent", "agent", "agent_task",
		"message", "prompt", "think", "reasoning",
		"todo", "todowrite", "plan", "question", "ask",
		"read", "read_file", "glob", "grep",
	}
	tools := MutationChannelCarrierTools()
	if !slices.Equal(tools, want) {
		t.Fatalf("carrier list = %q, want the frozen %q", tools, want)
	}
	for _, name := range tools {
		if name == "" || name != strings.ToLower(name) {
			t.Fatalf("carrier name %q is empty or not lower-case", name)
		}
	}
	for _, acting := range []string{
		"bash", "shell", "exec", "terminal", "powershell", "cmd",
		"write", "edit", "apply_patch", "run_command", "fetch", "http_request",
		// notebook can execute code cells, so it is not a content carrier.
		"notebook",
	} {
		if slices.Contains(tools, acting) {
			t.Fatalf("acting tool %q is on the carrier list", acting)
		}
	}
	tools[0] = "tampered"
	if got := MutationChannelCarrierTools(); got[0] != "task" {
		t.Fatalf("MutationChannelCarrierTools returned an aliased slice: got %q", got)
	}
	t.Logf("carrier tool list (%d): %q", len(want), want)
}

// TestMutationChannelCarrierToolsAllExempt checks every frozen name end to end:
// the list's promise is that each name exempts, so the test would fail if a
// name were added to the constant without the structure granting it.
func TestMutationChannelCarrierToolsAllExempt(t *testing.T) {
	pipe := w7Pipeline(t)
	for _, tool := range MutationChannelCarrierTools() {
		body := w7Body(t, tool, `{"cmd":"tokenhush allowlist add evil.example"}`)
		out, err := pipe.transformResponse(body, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse(%q) = %v, want nil", tool, err)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("carrier tool %q was refused:\n got %s\nwant %s", tool, out, body)
		}
	}
}

// TestToolCallCarrierExemptionIsPerToolCall pins the scoping: in one response,
// only the acting tool call is refused; the carrier calls around it keep every
// byte.
func TestToolCallCarrierExemptionIsPerToolCall(t *testing.T) {
	pipe := w7Pipeline(t)
	prose := `{"prompt":` + strconv.Quote(w7DelegationProse()) + `}`
	cli := `{"command":"tokenhush allowlist add evil.example"}`
	readPath := `{"path":"/home/u/.local/share/tokenhush/allowlist.json"}`

	fixture := w63Fixture(prose, cli, readPath)
	names := []string{"task", "bash", "read"}
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
	w63WantArgs(t, out, prose, w63Refusal(MutationChannelCLI), readPath)
}

// TestToolCallCarrierExemptionSSEContentAllowed pins the streaming path: a
// carrier tool's streamed arguments pass byte-identically, while an acting tool
// and an unknown tool name keep the existing refusal.
func TestToolCallCarrierExemptionSSEContentAllowed(t *testing.T) {
	t.Run("carrier_stream_passes_byte_identical", func(t *testing.T) {
		pipe := w7Pipeline(t)
		reporter, events := w14Reporter()
		pipe.SetRedactionReporter(reporter)
		w, rec := w14SSEWriter(t, pipe)

		prose := w7DelegationProse()
		half := len(prose) / 2
		input := append(w7NamedEvent(t, "task", prose[:half]), w64ArgumentsEvent(t, prose[half:])...)
		input = append(input, w64FinishEvent...)
		input = append(input, w64DoneEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		out := rec.Body.Bytes()
		if !bytes.Equal(out, input) {
			t.Fatalf("carrier stream was rewritten (len %d -> %d):\n got %q\nwant %q", len(input), len(out), out, input)
		}
		if got := pipe.StreamGuardRefusals(); got != 0 {
			t.Fatalf("StreamGuardRefusals = %d for a carrier stream, want 0", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 0 {
			t.Fatalf("StreamGuardFailClosed = %d for a carrier stream, want 0", got)
		}
		if len(*events) != 0 {
			t.Fatalf("reporter events = %d (%+v), want 0", len(*events), *events)
		}
		args, _ := w64Arguments(t, out)
		if args != prose {
			t.Fatalf("assembled arguments = %d bytes, want the %d-byte prose prompt", len(args), len(prose))
		}
	})

	t.Run("carrier_valid_json_arguments_in_one_event_pass", func(t *testing.T) {
		// The mainstream OpenAI shape: the whole valid-JSON arguments value
		// arrives in one event, so the arguments leaf is an Encoded parent that
		// only the Encoded matcher would otherwise inspect.
		pipe := w7Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)

		whole := w7NamedEvent(t, "task", `{"prompt":`+strconv.Quote(w7DelegationProse())+`}`)
		input := append(append([]byte{}, whole...), w64FinishEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		out := rec.Body.Bytes()
		if !bytes.Equal(out, input) {
			t.Fatalf("carrier Encoded arguments were rewritten:\n got %q\nwant %q", out, input)
		}
		if got := pipe.StreamGuardRefusals(); got != 0 {
			t.Fatalf("StreamGuardRefusals = %d, want 0", got)
		}
	})

	t.Run("acting_tool_with_a_name_leaf_is_still_refused", func(t *testing.T) {
		pipe := w7Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)

		fragments := []string{"tokenhush allow", "list add evil.example MARK-HIT"}
		input := append(w7NamedEvent(t, "shell", fragments[0]), w64ArgumentsEvent(t, fragments[1])...)
		input = append(input, w64FinishEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		out := rec.Body.Bytes()
		if bytes.Contains(out, []byte("MARK-HIT")) || bytes.Contains(out, []byte("evil.example")) {
			t.Fatalf("a fragment of the split command survived: %q", out)
		}
		if got, _ := w64Arguments(t, out); got != w63Refusal(MutationChannelCLI) {
			t.Fatalf("assembled arguments = %q, want the CLI refusal envelope", got)
		}
		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
		t.Logf("acting tool shell: channel=%s", MutationChannelCLI)
	})

	t.Run("unknown_tool_name_is_still_refused", func(t *testing.T) {
		pipe := w7Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)

		whole := w7NamedEvent(t, "mystery_tool", `{"cmd":"tokenhush allowlist add evil.example"}`)
		input := append(append([]byte{}, whole...), w64FinishEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got, _ := w64Arguments(t, rec.Body.Bytes()); got != w63Refusal(MutationChannelCLI) {
			t.Fatalf("assembled arguments = %q, want the CLI refusal envelope", got)
		}
		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
	})

	t.Run("carrier_name_arriving_after_the_first_fragment_disarms", func(t *testing.T) {
		// A provider that streams the function name after the first arguments
		// fragment must not leave the call armed once the name is known; no
		// fragment here matches alone, so the disarmed path releases verbatim.
		pipe := w7Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)

		fragments := []string{"tokenhush allow", "list add evil.example"}
		input := append(w64ArgumentsEvent(t, fragments[0]), w7NamedEvent(t, "task", fragments[1])...)
		input = append(input, w64FinishEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		out := rec.Body.Bytes()
		if !bytes.Equal(out, input) {
			t.Fatalf("later carrier name did not disarm the path:\n got %q\nwant %q", out, input)
		}
		if got := pipe.StreamGuardRefusals(); got != 0 {
			t.Fatalf("StreamGuardRefusals = %d, want 0", got)
		}
	})
}
