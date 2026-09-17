package proxy

// Rule-rewrite regressions: the C8 guard now intercepts only specific
// high-risk commands (mutationrules.go), requires the command at an execution
// position, and scans object-form arguments and Anthropic tool_use input as
// well as the OpenAI arguments string. These tests pin both directions: a
// genuine invocation is refused with its class on the buffered and streamed
// paths, and every daily-operation mention is byte-identical.

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// ruleContainsEnvelope reports whether any string value in the JSON body is the
// structured refusal envelope for class.
func ruleContainsEnvelope(t *testing.T, body []byte, class string) bool {
	t.Helper()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("unmarshal guarded body %s: %v", body, err)
	}
	want := `"refused":true`
	wantChannel := `"channel":` + strconv.Quote(class)
	var found bool
	var walk func(any)
	walk = func(x any) {
		switch y := x.(type) {
		case string:
			if strings.Contains(y, want) && strings.Contains(y, wantChannel) {
				found = true
			}
		case []any:
			for _, e := range y {
				walk(e)
			}
		case map[string]any:
			for _, e := range y {
				walk(e)
			}
		}
	}
	walk(v)
	return found
}

// ruleOpenAIObjectBody is an OpenAI-shaped response whose `arguments` is a JSON
// OBJECT (the reproduced false-negative shape: its child leaves end in their own
// field name, never "arguments").
func ruleOpenAIObjectBody() []byte {
	return []byte(`{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"bash","arguments":{"command":"tokenhush allowlist add x"}}}]}}]}`)
}

// ruleAnthropicInputBody is an Anthropic Messages response whose content[N] is a
// tool_use block carrying an `input` object (the second reproduced
// false-negative shape: no `arguments` leaf at all).
func ruleAnthropicInputBody() []byte {
	return []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"bash","input":{"command":"tokenhush allowlist add x"}}]}`)
}

// TestRuleRewriteBufferedMustRefuse is the buffered must-refuse matrix: each
// specific high-risk command is refused with its class, for the string-form
// arguments, the object-form arguments and the Anthropic input shape.
func TestRuleRewriteBufferedMustRefuse(t *testing.T) {
	cases := []struct {
		name  string
		class string
		body  []byte
	}{
		{"cli_sh_c_string", MutationChannelCLI, w7Body(t, "bash", `sh -c "tokenhush allowlist add x"`)},
		{"cli_line_start_string", MutationChannelCLI, w7Body(t, "bash", `tokenhush allowlist add x`)},
		{"cli_object_form", MutationChannelCLI, ruleOpenAIObjectBody()},
		{"cli_anthropic_input", MutationChannelCLI, ruleAnthropicInputBody()},
		{"control_post", MutationChannelControlPort, w7Body(t, "bash", `curl -X POST http://127.0.0.1:8787/allowlist -d '{"entry":"x"}'`)},
		{"file_write", MutationChannelFileWrite, w7Body(t, "bash", `echo '{}' > /home/u/.local/share/tokenhush/allowlist.json`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipe := w7Pipeline(t)
			out, err := pipe.transformResponse(append([]byte{}, tc.body...), pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse = %v, want nil", err)
			}
			if bytes.Contains(out, []byte("tokenhush allowlist add x")) {
				t.Fatalf("the invocation survived:\n%s", out)
			}
			if !ruleContainsEnvelope(t, out, tc.class) {
				t.Fatalf("no %q refusal envelope in:\n%s", tc.class, out)
			}
			if got := pipe.SelfProtectionInterceptions(); got != 1 {
				t.Fatalf("SelfProtectionInterceptions = %d, want 1", got)
			}
			t.Logf("MUST_REFUSE %s class=%s out=%s", tc.name, tc.class, out)
		})
	}
}

// TestRuleRewriteBufferedMustAllow is the false-positive guard: the literal is
// present in every payload, and none may be refused (the output must stay
// byte-identical).
func TestRuleRewriteBufferedMustAllow(t *testing.T) {
	const literal = "tokenhush allowlist add x"
	daily := []string{
		`grep -rn "` + literal + `" docs/`,
		`git log --grep="` + literal + `"`,
		`printf '%s\n' '` + literal + `'`,
		`cat docs/notes.md`,
		`sed -n '/tokenhush allowlist/p' docs/security.md`,
		`echo '` + literal + `'`,
		`git commit -m "docs: explain ` + literal + `"`,
		`Please run ` + literal + ` to register the host.`,
		`tokenhush allowlist list`,
	}
	for i, args := range daily {
		t.Run("daily_"+strconv.Itoa(i), func(t *testing.T) {
			pipe := w7Pipeline(t)
			body := w7Body(t, "bash", args)
			out, err := pipe.transformResponse(append([]byte{}, body...), pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse = %v, want nil", err)
			}
			if !bytes.Equal(out, body) {
				t.Fatalf("daily op was rewritten:\n got %s\nwant %s", out, body)
			}
			if got := pipe.SelfProtectionInterceptions(); got != 0 {
				t.Fatalf("SelfProtectionInterceptions = %d, want 0", got)
			}
		})
	}

	t.Run("content_tools_may_reference_the_literal", func(t *testing.T) {
		for _, tool := range []string{"write", "edit"} {
			pipe := w7Pipeline(t)
			body := w7Body(t, tool, `{"path":"docs/guard.md","content":"`+literal+`"}`)
			out, err := pipe.transformResponse(append([]byte{}, body...), pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse(%s) = %v", tool, err)
			}
			if !bytes.Equal(out, body) {
				t.Fatalf("content tool %q was rewritten:\n got %s\nwant %s", tool, out, body)
			}
		}
	})
}

// ruleSSEData frames one data payload as an SSE event.
func ruleSSEData(payload string) []byte {
	return []byte("data: " + payload + "\n\n")
}

// ruleSSEArguments extracts the concatenated `arguments` value of the SSE
// stream, whatever its leaf shape.
func ruleSSEArguments(t *testing.T, out []byte) string {
	t.Helper()
	args, _ := w64Arguments(t, out)
	return args
}

// TestRuleRewriteSSEMustRefuse is the streamed must-refuse matrix: the OpenAI
// string form split across events, the object form delivered whole, and the
// Anthropic input form.
func TestRuleRewriteSSEMustRefuse(t *testing.T) {
	t.Run("openai_string_split", func(t *testing.T) {
		pipe := w7Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)
		input := append(w64ArgumentsStream(t, []string{`sh -c "tokenhush allow`, `list add x"`}), w64FinishEvent...)
		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got := ruleSSEArguments(t, rec.Body.Bytes()); got != w63Refusal(MutationChannelCLI) {
			t.Fatalf("assembled arguments = %q, want the cli-command refusal envelope", got)
		}
		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
	})

	objectPayload := `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"bash","arguments":{"command":"tokenhush allowlist add x"}}}]}}]}`
	anthropicPayload := `{"type":"message","content":[{"type":"tool_use","id":"toolu_1","name":"bash","input":{"command":"tokenhush allowlist add x"}}]}`
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"openai_object_form", objectPayload},
		{"anthropic_input_form", anthropicPayload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pipe := w7Pipeline(t)
			w, rec := w14SSEWriter(t, pipe)
			input := append(ruleSSEData(tc.payload), w64FinishEvent...)
			if _, err := w.backfill.Write(input); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := w.backfill.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			out := rec.Body.Bytes()
			if bytes.Contains(out, []byte("tokenhush allowlist add x")) {
				t.Fatalf("the invocation survived:\n%s", out)
			}
			if !bytes.Contains(out, []byte("cli-command")) {
				t.Fatalf("no cli-command refusal in:\n%s", out)
			}
			if got := pipe.StreamGuardRefusals(); got != 1 {
				t.Fatalf("StreamGuardRefusals = %d, want 1", got)
			}
			t.Logf("MUST_REFUSE %s out=%s", tc.name, out)
		})
	}
}

// TestRuleRewriteSSEMustAllow pins the streamed false-positive guard for the
// object form: a command that only quotes/documents the form is not refused.
func TestRuleRewriteSSEMustAllow(t *testing.T) {
	pipe := w7Pipeline(t)
	w, rec := w14SSEWriter(t, pipe)
	payload := `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"bash","arguments":{"command":"grep -rn \"tokenhush allowlist add x\" docs/"}}}]}}]}`
	input := append(ruleSSEData(payload), w64FinishEvent...)
	if _, err := w.backfill.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.backfill.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !bytes.Equal(rec.Body.Bytes(), input) {
		t.Fatalf("the mention stream was rewritten:\n got %s\nwant %s", rec.Body.Bytes(), input)
	}
	if got := pipe.StreamGuardRefusals(); got != 0 {
		t.Fatalf("StreamGuardRefusals = %d, want 0", got)
	}
}

// TestMutationChannelBuiltinRulesAreSpecific pins the built-in rule model: it
// is exactly the three documented rules, and no rule names a generic shell,
// wrapper, redirection or wildcard.
func TestMutationChannelBuiltinRulesAreSpecific(t *testing.T) {
	ids := MutationChannelRuleIDs()
	want := []string{
		"cli-command/allowlist-mutation",
		"control-port/mutating-control-request",
		"file-write/allowlist-file",
	}
	if len(ids) != len(want) {
		t.Fatalf("built-in rules = %q, want exactly %q", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("built-in rule %d = %q, want %q", i, ids[i], want[i])
		}
	}
	for _, commands := range MutationChannelRuleCommands() {
		if len(commands) == 0 {
			t.Fatal("a built-in rule names no command")
		}
		for _, cmd := range commands {
			if mutationChannelCommandIsGeneric(cmd) {
				t.Fatalf("built-in rule names the generic command %q", cmd)
			}
		}
	}
}

// TestMutationChannelCommandRulesRejectGeneric pins the proxy-side load gate: a
// rule naming a generic command (or omitting the command) is rejected, so a
// blanket rule over generic shell surface can never be installed.
func TestMutationChannelCommandRulesRejectGeneric(t *testing.T) {
	generic := []string{"sh", "bash", "zsh", "python3", "sudo", "env", "*", ">", ">>", "/bin/bash"}
	for _, cmd := range generic {
		if err := ValidateMutationChannelCommandRules([]MutationChannelCommandRule{{ID: "custom.x", Command: cmd}}); err == nil {
			t.Fatalf("generic command %q was accepted", cmd)
		}
	}
	if err := ValidateMutationChannelCommandRules([]MutationChannelCommandRule{{ID: "custom.x"}}); err == nil {
		t.Fatal("a rule with no command was accepted")
	}
	if err := ValidateMutationChannelCommandRules([]MutationChannelCommandRule{{ID: "custom.x", Command: "dangerctl"}}); err != nil {
		t.Fatalf("a specific command was rejected: %v", err)
	}

	pipe := w7Pipeline(t)
	pipe.SetMutationChannelCommandRules([]MutationChannelCommandRule{{ID: "custom.sh", Command: "sh"}})
	if got := pipe.MutationChannelCommandRules(); len(got) != 0 {
		t.Fatalf("a generic rule was installed: %+v", got)
	}
	if _, matched := pipe.DetectMutationChannel("sh -c 'ls'"); matched {
		t.Fatal("the generic rule refused a shell command")
	}
}

// TestMutationChannelCommandRulesExtendGuard proves rule-pack extensibility at
// the proxy seam: an installed specific command rule becomes refused, with no
// binary change.
func TestMutationChannelCommandRulesExtendGuard(t *testing.T) {
	pipe := w7Pipeline(t)
	if _, matched := pipe.DetectMutationChannel("dangerctl admin nuke --force"); matched {
		t.Fatal("dangerctl matched before the rule was installed")
	}
	pipe.SetMutationChannelCommandRules([]MutationChannelCommandRule{{
		ID: "custom.dangerctl", Command: "dangerctl", Subcommand: "admin", Verbs: []string{"nuke"},
	}})
	if class, matched := pipe.DetectMutationChannel("dangerctl admin nuke --force"); !matched || class != MutationChannelCLI {
		t.Fatalf("dangerctl = (%q, %v), want (%q, true)", class, matched, MutationChannelCLI)
	}
	if _, matched := pipe.DetectMutationChannel("dangerctl admin status"); matched {
		t.Fatal("a non-mutating dangerctl subcommand matched")
	}
	if _, matched := pipe.DetectMutationChannel("grep dangerctl admin nuke docs/"); matched {
		t.Fatal("a mention of dangerctl matched")
	}
}
