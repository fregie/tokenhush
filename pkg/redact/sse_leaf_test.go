package redact

import (
	"bytes"
	"encoding/json"
	"testing"
)

// ossKeySecret stands in for the incident's Aliyun OSS AccessKeyId. It is
// deliberately a synthetic ASCII byte string with no JSON metacharacter, so
// restoring it into an `arguments` JSON string needs no escaping. The literal
// matches the repo's gitleaks allowlist (SECRET-LEAF-*); never replace it with
// a provider-shaped credential such as LTAI... or AKIA....
var ossKeySecret = []byte("SECRET-LEAF-OSSKEY-0001")

// sseToolCallEnvelope renders one SSE record whose data value is a real JSON
// document carrying arguments inside
// choices[0].delta.tool_calls[0].function.arguments. It mirrors sseJSONEnvelope
// (sse_spelling_test.go:11) but targets the tool-call shape of the incident, and
// marshals with encoding/json so the arguments string is correctly escaped.
func sseToolCallEnvelope(t *testing.T, arguments string) string {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"choices": []any{
			map[string]any{
				"delta": map[string]any{
					"tool_calls": []any{
						map[string]any{
							"index": 0,
							"type":  "function",
							"function": map[string]any{
								"name":      "bash",
								"arguments": arguments,
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal tool-call envelope: %v", err)
	}
	return "data: " + string(doc) + "\n\n"
}

// envelopeArguments decodes one SSE data value and returns the
// choices[0].delta.tool_calls[0].function.arguments string, the leaf the
// incident's split placeholder lives in.
func envelopeArguments(t *testing.T, data []byte) string {
	t.Helper()
	var doc struct {
		Choices []struct {
			Delta struct {
				ToolCalls []struct {
					Function struct {
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal tool-call envelope: %v", err)
	}
	if len(doc.Choices) == 0 || len(doc.Choices[0].Delta.ToolCalls) == 0 {
		t.Fatalf("tool-call envelope is missing choices[0].delta.tool_calls[0]: %q", data)
	}
	return doc.Choices[0].Delta.ToolCalls[0].Function.Arguments
}

// TestSSEBackfillEnvelopeContentSplitRestored locks the Aliyun OSS incident: a
// session-minted __PII_<type>_<digest>__ placeholder is content-split across TWO
// consecutive SSE `data:` events, where EACH event is a complete, independently
// valid JSON envelope and the placeholder fragments live inside
// choices[0].delta.tool_calls[0].function.arguments.
//
// Byte counterexample: with real placeholder p and split point k=8,
//
//	event 1 arguments = `{"Bucket":"mybucket","Object":"data.csv","AccessKeyId":"` + p[:8]
//	event 2 arguments = p[8:] + `","Secret":"x"}`
//
// The placeholder never spans the two events as a single byte span the writer
// holds: each event's data value ends in `"}}]}}`, so today both fragments are
// emitted literally and the local client/tool receives the placeholder as if it
// were the real credential (observed: OSS `403 InvalidAccessKeyId`). The fix must
// splice the completing leaf back to the secret and delete the contributing
// fragment span while keeping every emitted envelope independently valid JSON.
func TestSSEBackfillEnvelopeContentSplitRestored(t *testing.T) {
	back, p := mintRestorable(t, ossKeySecret, "api_key")
	if len(p) <= 12 {
		t.Fatalf("placeholder %q is too short to content-split", p)
	}

	const k = 8
	const (
		pre    = `{"Bucket":"mybucket","Object":"data.csv","AccessKeyId":"`
		suffix = `","Secret":"x"}`
	)

	// The foreign-placeholder split is the todo-1 failure-scenario assertion and
	// it must pass both before and after the fix. It runs FIRST so it actually
	// executes under the red baseline: the t.Fatalf happy assertions below would
	// otherwise Goexit before this subtest starts.
	t.Run("foreign-placeholder-split-stays-byte-identical", func(t *testing.T) {
		const foreign = "__PII_api_key_deadbeefcafe__"
		back2, _ := mintRestorable(t, ossKeySecret, "api_key")
		in := sseToolCallEnvelope(t, pre+foreign[:k]) +
			sseToolCallEnvelope(t, foreign[k:]+suffix)

		out := NewSSEBackfiller(back2, nil).process([]byte(in))
		if !bytes.Equal(out, []byte(in)) {
			t.Fatalf("foreign placeholder split changed:\n got %q\nwant byte-identical %q", out, in)
		}
	})

	env1 := sseToolCallEnvelope(t, pre+p[:k])
	env2 := sseToolCallEnvelope(t, p[k:]+suffix)
	out := NewSSEBackfiller(back, nil).process([]byte(env1 + env2))

	events := decodeStream(t, out)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want exactly 2", len(events))
	}

	if got := bytes.Count(out, ossKeySecret); got != 1 {
		t.Fatalf("restored secret occurrences = %d, want exactly 1 in %q", got, out)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder prefix %q survived the restore: %q", placeholderPrefix, out)
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not independently valid JSON: %q", i, ev.Data)
		}
	}

	arg1 := envelopeArguments(t, events[0].Data)
	arg2 := envelopeArguments(t, events[1].Data)
	if got, want := arg1+arg2, pre+string(ossKeySecret)+suffix; got != want {
		t.Fatalf("concatenated arguments = %q, want %q", got, want)
	}
	if got := arg1; got != pre {
		t.Fatalf("event 1 arguments = %q, want the untouched pre-fragment %q", got, pre)
	}
	if got, want := arg2, string(ossKeySecret)+suffix; got != want {
		t.Fatalf("event 2 arguments = %q, want %q", got, want)
	}
}
