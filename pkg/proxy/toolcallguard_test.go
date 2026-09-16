package proxy

// W6.3 regressions: on the buffered response path the C8 guard rewrites only
// the offending tool call's `arguments`, replacing the whole arguments string
// with the documented refusal notice, and leaves every other byte of the
// response alone. See guardResponseToolCalls, mutationChannelRefusalNotice and
// the W6.2 classifier in mutationchannel.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// w63ToolCall is one tool call in the OpenAI-shaped response fixture below.
type w63ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// w63Message is the assistant message carrying the tool calls.
type w63Message struct {
	Role      string        `json:"role"`
	Content   string        `json:"content"`
	ToolCalls []w63ToolCall `json:"tool_calls"`
}

// w63Choice is one completion choice.
type w63Choice struct {
	Index   int        `json:"index"`
	Message w63Message `json:"message"`
}

// w63Response is an OpenAI-shaped chat-completion response carrying tool calls
// under /choices/0/message/tool_calls/N/function/arguments.
type w63Response struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Choices []w63Choice `json:"choices"`
}

// w63Pipeline builds a response-path pipeline with the full C8 mode set and an
// empty registry (no detectors), so only the mutation-channel guard can change
// the bytes.
func w63Pipeline(t *testing.T) *Pipeline {
	t.Helper()
	return w45Pipeline(t, PipelineConfig{
		Registry:              w45Registry(t),
		Engine:                w45Engine(t),
		Tool:                  "w6.3",
		SelfProtectionEnabled: true,
		SelfProtectionModes:   []string{MutationChannelCLI, MutationChannelControlPort, MutationChannelFileWrite},
	})
}

// w63Fixture returns an OpenAI-shaped response whose tool calls carry the given
// decoded argument strings, so a test can also tweak one field (for example the
// message prose or the function name) before marshalling.
func w63Fixture(args ...string) *w63Response {
	resp := &w63Response{ID: "chatcmpl-w63", Object: "chat.completion"}
	choice := w63Choice{Index: 0}
	choice.Message.Role = "assistant"
	for i, arg := range args {
		var call w63ToolCall
		call.ID = fmt.Sprintf("call_%d", i+1)
		call.Type = "function"
		call.Function.Name = "shell"
		call.Function.Arguments = arg
		choice.Message.ToolCalls = append(choice.Message.ToolCalls, call)
	}
	resp.Choices = append(resp.Choices, choice)
	return resp
}

// w63Body marshals the fixture built from args.
func w63Body(t *testing.T, args ...string) []byte {
	t.Helper()
	body, err := json.Marshal(w63Fixture(args...))
	if err != nil {
		t.Fatalf("marshal response fixture: %v", err)
	}
	return body
}

// w63Arguments extracts the arguments of every tool call, in order, so a test
// can compare per-item goldens.
func w63Arguments(t *testing.T, body []byte) []string {
	t.Helper()
	var resp w63Response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal guarded response %q: %v", body, err)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(resp.Choices))
	}
	calls := resp.Choices[0].Message.ToolCalls
	out := make([]string, len(calls))
	for i, call := range calls {
		out[i] = call.Function.Arguments
	}
	return out
}

// w63WantArgs compares the per-item arguments of got against want and logs each
// item, so the golden diff is visible in the -v output (the per-item evidence
// the plan asks for).
func w63WantArgs(t *testing.T, got []byte, want ...string) {
	t.Helper()
	items := w63Arguments(t, got)
	if len(items) != len(want) {
		t.Fatalf("tool calls = %d, want %d (body %s)", len(items), len(want), got)
	}
	for i := range want {
		status := "ok"
		if items[i] != want[i] {
			status = "CHANGED"
		}
		t.Logf("tool_call[%d] %s: got=%q want=%q", i, status, items[i], want[i])
		if items[i] != want[i] {
			t.Fatalf("tool_call[%d] arguments = %q, want %q", i, items[i], want[i])
		}
	}
}

// TestToolCallBlockedWithNotice is the W6.3 acceptance test: a mutation-channel
// tool call is rewritten to the refusal notice per tool call, for both argument
// shapes, while the response itself is still delivered and every other byte is
// untouched.
func TestToolCallBlockedWithNotice(t *testing.T) {
	t.Run("valid_json_arguments_replaces_the_whole_parent", func(t *testing.T) {
		pipe := w63Pipeline(t)
		arguments := `{"cmd":"tokenhush allowlist add evil.example","note":"ok"}`
		body := w63Body(t, arguments)

		out, err := pipe.transformResponse(body, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil (the whole response must not be blocked)", err)
		}
		if bytes.Contains(out, []byte("tokenhush allowlist add evil.example")) {
			t.Fatalf("the offending command survived: %s", out)
		}
		w63WantArgs(t, out, mutationChannelRefusalNotice)
	})

	t.Run("non_json_arguments_terminal_leaf_replaced", func(t *testing.T) {
		pipe := w63Pipeline(t)
		arguments := "tokenhush allowlist add evil.example"
		body := w63Body(t, arguments)

		out, err := pipe.transformResponse(body, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		if bytes.Contains(out, []byte(arguments)) {
			t.Fatalf("the non-JSON command survived: %s", out)
		}
		w63WantArgs(t, out, mutationChannelRefusalNotice)
	})

	t.Run("multi_tool_call_only_the_offending_item_changes", func(t *testing.T) {
		pipe := w63Pipeline(t)
		offending := `{"cmd":"tokenhush allowlist add evil.example"}`
		safeList := `{"cmd":"ls -la /tmp"}`
		safeRead := `{"path":"/tmp/report.txt","content":"hello"}`
		body := w63Body(t, offending, safeList, safeRead)

		out, err := pipe.transformResponse(body, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		t.Logf("W63_ORIGINAL=%s", body)
		t.Logf("W63_GUARDED=%s", out)
		// Per-item golden: only item 0 changed; items 1 and 2 are unchanged.
		w63WantArgs(t, out, mutationChannelRefusalNotice, safeList, safeRead)
		for _, safe := range []string{safeList, safeRead} {
			quoted, qerr := json.Marshal(safe)
			if qerr != nil {
				t.Fatalf("marshal safe argument: %v", qerr)
			}
			if !bytes.Contains(out, quoted) {
				t.Fatalf("safe tool call %q was not preserved byte-for-byte: %s", safe, out)
			}
		}
	})

	t.Run("hash_key_sibling_leaf_survives", func(t *testing.T) {
		pipe := w63Pipeline(t)
		// The sibling key is literally "arguments#y": escapePointer does not
		// escape '#', so its path shares the parent's '/arguments' prefix. The
		// run length must come from len(protocol.Walk(parentContent)), never a
		// path+"#" prefix scan, or this sibling would be swallowed.
		raw := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[` +
			`{"id":"call_1","type":"function","function":{"arguments":"{\"cmd\":\"tokenhush allowlist add evil.example\"}","arguments#y":"SIBLING"}}]}}]}`)

		out, err := pipe.transformResponse(raw, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		t.Logf("W63_HASH_ORIGINAL=%s", raw)
		t.Logf("W63_HASH_GUARDED=%s", out)
		if !bytes.Contains(out, []byte(`"SIBLING"`)) {
			t.Fatalf("the '#'-named sibling leaf was swallowed: %s", out)
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("guarded body is not valid JSON: %v (%s)", err, out)
		}
		got := w63Arguments(t, out)
		if len(got) != 1 || got[0] != mutationChannelRefusalNotice {
			t.Fatalf("arguments = %q, want the notice", got)
		}
	})

	t.Run("command_split_across_nested_leaves_is_caught", func(t *testing.T) {
		pipe := w63Pipeline(t)
		// Neither nested leaf matches alone, and the raw parent text does not
		// either (JSON punctuation separates the halves), so only matching the
		// whole arguments string catches this. Rewriting just a matched nested
		// leaf would miss it entirely.
		splitMidToken := `{"a":"tokenhush allow","b":"list add evil.example"}`
		splitAtToken := `{"a":"tokenhush","b":"allowlist add evil.example"}`
		body := w63Body(t, splitMidToken, splitAtToken)

		out, err := pipe.transformResponse(body, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		t.Logf("W63_SPLIT_ORIGINAL=%s", body)
		t.Logf("W63_SPLIT_GUARDED=%s", out)
		w63WantArgs(t, out, mutationChannelRefusalNotice, mutationChannelRefusalNotice)
		if bytes.Contains(out, []byte("evil.example")) {
			t.Fatalf("a fragment of the split command survived: %s", out)
		}
	})

	t.Run("safe_prose_and_status_calls_pass_through_byte_identical", func(t *testing.T) {
		pipe := w63Pipeline(t)
		for _, arguments := range []string{
			`{"command":"echo hello","note":"see the allowlist documentation"}`,
			`{"command":"grep -n allowlist README.md"}`,
			"tokenhush status --json",
			`{"cmd":"tokenhush status"}`,
		} {
			body := w63Body(t, arguments)
			out, err := pipe.transformResponse(body, pipe.tool)
			if err != nil {
				t.Fatalf("transformResponse(%q) = %v", arguments, err)
			}
			if !bytes.Equal(out, body) {
				t.Fatalf("safe call %q was rewritten:\n got %s\nwant %s", arguments, out, body)
			}
		}
	})

	t.Run("only_the_arguments_field_is_guarded", func(t *testing.T) {
		pipe := w63Pipeline(t)
		fixture := w63Fixture(`{"cmd":"ls"}`)
		fixture.Choices[0].Message.Content = "tokenhush allowlist add evil.example"
		fixture.Choices[0].Message.ToolCalls[0].Function.Name = "tokenhush allowlist add evil.example"
		body, err := json.Marshal(fixture)
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}

		out, err := pipe.transformResponse(body, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("a matching leaf outside the arguments field was rewritten:\n got %s\nwant %s", out, body)
		}
	})

	t.Run("gating_disabled_and_mode_off_is_a_noop", func(t *testing.T) {
		body := w63Body(t, `{"cmd":"tokenhush allowlist add evil.example"}`)

		disabled := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: w45Engine(t), Tool: "w6.3-off"})
		out, err := disabled.transformResponse(body, disabled.tool)
		if err != nil {
			t.Fatalf("transformResponse(disabled) = %v", err)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("disabled self-protection rewrote the response: %s", out)
		}

		modeOff := w45Pipeline(t, PipelineConfig{
			Registry:              w45Registry(t),
			Engine:                w45Engine(t),
			Tool:                  "w6.3-mode-off",
			SelfProtectionEnabled: true,
			SelfProtectionModes:   []string{MutationChannelControlPort},
		})
		out, err = modeOff.transformResponse(body, modeOff.tool)
		if err != nil {
			t.Fatalf("transformResponse(mode off) = %v", err)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("a disabled class was still enforced: %s", out)
		}
	})

	t.Run("response_is_still_delivered_without_a_whole_response_403", func(t *testing.T) {
		pipe := w63Pipeline(t)
		upstreamBody := w63Body(t, `{"cmd":"tokenhush allowlist add evil.example"}`, `{"cmd":"ls"}`)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(upstreamBody)
		}))
		t.Cleanup(upstream.Close)
		srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
		t.Cleanup(srv.Close)

		resp, err := srv.Client().Post(srv.URL+"/v1/chat/completions", "application/json",
			bytes.NewReader([]byte(`{"model":"claude-test"}`)))
		if err != nil {
			t.Fatalf("through proxy: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		clientBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read client body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (the response must not be blocked as a whole): %s", resp.StatusCode, clientBody)
		}
		w63WantArgs(t, clientBody, mutationChannelRefusalNotice, `{"cmd":"ls"}`)
	})

	t.Run("reporter_hook_emits_one_metadata_only_event", func(t *testing.T) {
		pipe := w63Pipeline(t)
		reporter, events := w14Reporter()
		pipe.SetRedactionReporter(reporter)
		body := w63Body(t, `{"cmd":"tokenhush allowlist add evil.example"}`)

		if _, err := pipe.transformResponse(body, pipe.tool); err != nil {
			t.Fatalf("transformResponse = %v", err)
		}
		if len(*events) != 1 {
			t.Fatalf("events = %d (%+v), want 1", len(*events), *events)
		}
		got := (*events)[0]
		want := RedactionEvent{
			Action:    RedactionActionMutationChannelBlocked,
			Direction: RedactionDirectionResponse,
			Phase:     extension.ResponseContent.String(),
			Type:      MutationChannelCLI,
		}
		if got != want {
			t.Fatalf("event = %+v, want %+v", got, want)
		}
	})
}
