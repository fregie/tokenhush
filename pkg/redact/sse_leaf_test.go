package redact

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
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

// ---------------------------------------------------------------------------
// Wave-1 counterexample and held-bound regressions (todo 3).
//
// Every assertion below is derived from the frozen decisions D1-D13 in
// .omo/plans/r6-sse-envelope-restore.md, NOT from the current implementation:
// these tests are the arbiter Wave 3 (todos 8-10) must satisfy. A test that is
// RED now pins behavior the current SSEBackfiller does not yet have; a test
// that is GREEN now is a no-reflow / no-fabrication pin that must stay green.
// ---------------------------------------------------------------------------

// chunkEnvelope is an ordered, OpenAI-shaped streaming chunk. Field order is
// the declaration order, so its id/object/model string leaves are byte-present
// BEFORE choices and the target `arguments` leaf. encoding/json marshals struct
// fields in order but map keys sorted, so the F1 sibling-before-target layout
// needs this ordered shape rather than a map.
type chunkEnvelope struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Model   string        `json:"model"`
	Choices []chunkChoice `json:"choices"`
}

// chunkChoice is one ordered choices[] element.
type chunkChoice struct {
	Index int        `json:"index"`
	Delta chunkDelta `json:"delta"`
}

// chunkDelta is one ordered delta object.
type chunkDelta struct {
	ToolCalls []chunkToolCall `json:"tool_calls"`
}

// chunkToolCall is one ordered tool_calls[] element; Index is the logical-call
// discriminator real providers use.
type chunkToolCall struct {
	Index    int           `json:"index"`
	Type     string        `json:"type"`
	Function chunkFunction `json:"function"`
}

// chunkFunction carries the ordered function.name sibling and the target
// arguments leaf.
type chunkFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// sseChunkEnvelope renders one SSE record whose data value is an ordered
// tool-call chunk carrying callIndex and arguments.
func sseChunkEnvelope(t *testing.T, id, object, model string, callIndex int, arguments string) string {
	t.Helper()
	doc := chunkEnvelope{
		ID: id, Object: object, Model: model,
		Choices: []chunkChoice{{
			Index: 0,
			Delta: chunkDelta{ToolCalls: []chunkToolCall{{
				Index:    callIndex,
				Type:     "function",
				Function: chunkFunction{Name: "bash", Arguments: arguments},
			}}},
		}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal ordered tool-call envelope: %v", err)
	}
	return "data: " + string(b) + "\n\n"
}

// sseRawArgumentsEnvelope renders one SSE record whose
// choices[0].delta.tool_calls[0].function.arguments JSON source is argumentsJSON
// verbatim. It bypasses encoding/json so a test can pin the exact WIRE escape
// spelling (F4/F8): encoding/json would re-escape a hand-written `\uXXXX` into
// `\\uXXXX` and hide the normalize-other-escapes bug. argumentsJSON must be
// valid inside a JSON string (no bare quote, no backslash except the intended
// escape).
func sseRawArgumentsEnvelope(argumentsJSON string) string {
	return "data: " +
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"type":"function","function":{"name":"bash","arguments":"` +
		argumentsJSON + `"}}]}}]}` + "\n\n"
}

// sseRawDataEnvelope renders one SSE record whose data value is dataJSON
// verbatim, so a test can build duplicate object keys a Go map or struct cannot
// express (F7).
func sseRawDataEnvelope(dataJSON string) string {
	return "data: " + dataJSON + "\n\n"
}

// sseJSONEnvelopeWithPad renders one valid-JSON content envelope whose root
// carries a large, inert sibling string leaf. The pad inflates the segment's
// retained bytes without changing the target content leaf's channel identity
// (D1 captures preceding non-string scalars only), so the held-bound test can
// drive the joint budget to its cap.
func sseJSONEnvelopeWithPad(t *testing.T, pad, content string) string {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"pad": pad,
		"choices": []any{
			map[string]any{"delta": map[string]string{"content": content}},
		},
	})
	if err != nil {
		t.Fatalf("marshal padded envelope: %v", err)
	}
	return "data: " + string(doc) + "\n\n"
}

// TestSSEBackfillSiblingBeforeTargetF1 pins D1 / scope item 1: a content-split
// placeholder must survive sibling STRING leaves that PRECEDE the target leaf
// inside the SAME JSON envelope (id, object, model, function.name). Real
// provider chunks carry those siblings, so a guard that releases the carry on
// the first leaf whose path differs would kill it before the target arrives.
//
// Byte counterexample: two ordered envelopes whose arguments are
// `pre+p[:8]` and `p[8:]+suffix`. Today each envelope's data value is emitted
// verbatim, so the client receives the fragment and the secret is never
// restored. Contract: secret exactly once, no prefix, every envelope valid
// JSON, the sibling leaves byte-preserved, and the concatenated arguments equal
// `pre+secret+suffix` with each event's own fragment removed.
func TestSSEBackfillSiblingBeforeTargetF1(t *testing.T) {
	back, p := mintRestorable(t, ossKeySecret, "api_key")
	if len(p) <= 8 {
		t.Fatalf("placeholder %q is too short to content-split", p)
	}

	const (
		id     = "chatcmpl-1"
		object = "chat.completion.chunk"
		model  = "gpt-x"
		k      = 8
		pre    = `{"Bucket":"mybucket","Object":"data.csv","AccessKeyId":"`
		suffix = `","Secret":"x"}`
	)

	env1 := sseChunkEnvelope(t, id, object, model, 0, pre+p[:k])
	env2 := sseChunkEnvelope(t, id, object, model, 0, p[k:]+suffix)
	out := NewSSEBackfiller(back, nil).process([]byte(env1 + env2))

	if got := bytes.Count(out, ossKeySecret); got != 1 {
		t.Fatalf("restored secret occurrences = %d, want exactly 1 in %q", got, out)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder prefix %q survived the restore: %q", placeholderPrefix, out)
	}

	events := decodeStream(t, out)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want exactly 2", len(events))
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not independently valid JSON: %q", i, ev.Data)
		}
	}
	for _, sibling := range []string{id, object, model, "bash"} {
		if !bytes.Contains(out, []byte(sibling)) {
			t.Fatalf("sibling string leaf %q vanished from %q", sibling, out)
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

// TestSSEBackfillToolIndexNoCrossInjectF2 pins D1/D7: Path alone is not a
// channel identity. Two OpenAI tool calls both live at tool_calls[0]; only the
// non-string scalar `index` tells them apart, so a fragment in call 0 must
// never be stitched into call 1.
//
// cross-index (GREEN today): call 0 carries `pre+p[:8]`, call 1 carries
// `p[8:]+suffix` -> no match, both released byte-identically, no fabrication.
// same-index (RED today): both carry index 0 -> the split restores exactly
// once. The test is RED overall because of same-index; cross-index runs first
// so it actually executes under the red baseline.
func TestSSEBackfillToolIndexNoCrossInjectF2(t *testing.T) {
	const (
		k      = 8
		pre    = `{"Bucket":"b","Object":"o","AccessKeyId":"`
		suffix = `","Secret":"x"}`
	)

	t.Run("cross-index-does-not-stitch", func(t *testing.T) {
		back, p := mintRestorable(t, ossKeySecret, "api_key")
		if len(p) <= k {
			t.Fatalf("placeholder %q is too short to content-split", p)
		}
		in := sseChunkEnvelope(t, "id", "obj", "m", 0, pre+p[:k]) +
			sseChunkEnvelope(t, "id", "obj", "m", 1, p[k:]+suffix)
		out := NewSSEBackfiller(back, nil).process([]byte(in))
		if !bytes.Equal(out, []byte(in)) {
			t.Fatalf("cross-index split was stitched:\n got %q\nwant byte-identical %q", out, in)
		}
		if bytes.Contains(out, ossKeySecret) {
			t.Fatalf("cross-index split fabricated the secret: %q", out)
		}
		for i, ev := range decodeStream(t, out) {
			if !json.Valid(ev.Data) {
				t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
			}
		}
	})

	t.Run("same-index-restores", func(t *testing.T) {
		back, p := mintRestorable(t, ossKeySecret, "api_key")
		if len(p) <= k {
			t.Fatalf("placeholder %q is too short to content-split", p)
		}
		in := sseChunkEnvelope(t, "id", "obj", "m", 0, pre+p[:k]) +
			sseChunkEnvelope(t, "id", "obj", "m", 0, p[k:]+suffix)
		out := NewSSEBackfiller(back, nil).process([]byte(in))
		if got := bytes.Count(out, ossKeySecret); got != 1 {
			t.Fatalf("restored secret occurrences = %d, want exactly 1 in %q", got, out)
		}
		if bytes.Contains(out, []byte(placeholderPrefix)) {
			t.Fatalf("placeholder prefix survived: %q", out)
		}
		for i, ev := range decodeStream(t, out) {
			if !json.Valid(ev.Data) {
				t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
			}
		}
	})
}

// TestSSEBackfillReleaseKeepsValidJSONF3 pins D2's raw->JSON handoff. A raw
// (non-JSON) event whose value ends in a partial placeholder prefix leaves the
// single writer holding that tail; when the NEXT event is a valid-JSON
// envelope, the writer must be flushed onto the RAW segment's side, never
// prefixed into the JSON envelope's data value. Today the tail is fed together
// with the JSON value, so the envelope ships as `__PII_api_{...}` and is no
// longer valid JSON.
//
// The raw data value is intentionally not JSON; the invariant is that every
// event whose own input was a complete JSON document stays independently valid
// JSON, and the raw fragment leaves literally, exactly once, in order.
func TestSSEBackfillReleaseKeepsValidJSONF3(t *testing.T) {
	back, _ := mintRestorable(t, ossKeySecret, "api_key")

	in := sseRecord("delta", "__PII_api_") + sseToolCallEnvelope(t, `{"a":"b"}`)
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	events := decodeStream(t, out)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	if got, want := string(events[0].Data), "__PII_api_"; got != want {
		t.Fatalf("raw event data = %q, want the literal held prefix %q", got, want)
	}
	if !json.Valid(events[1].Data) {
		t.Fatalf("JSON envelope data is not independently valid JSON: %q", events[1].Data)
	}
	if bytes.Contains(events[1].Data, []byte("__PII_")) {
		t.Fatalf("raw held prefix leaked into the JSON envelope: %q", events[1].Data)
	}
	if got, want := envelopeArguments(t, events[1].Data), `{"a":"b"}`; got != want {
		t.Fatalf("JSON envelope arguments = %q, want %q", got, want)
	}
	concat := string(events[0].Data) + string(events[1].Data)
	if got := strings.Count(concat, "__PII_api_"); got != 1 {
		t.Fatalf("raw fragment occurrences = %d, want exactly 1 in %q", got, concat)
	}
}

// TestSSEBackfillRawJsonRawInterleavingPreservesBytes pins D2's raw->JSON
// handoff across a raw -> JSON -> raw interleaving: a raw event whose value
// ends in a partial placeholder prefix leaves the raw writer holding that tail,
// the next event is a valid-JSON envelope, and the third is raw again and never
// completes the prefix. The writer's held tail must be handed off onto the
// newest raw segment BEFORE the JSON envelope is processed, so the prefix can
// never leak into a JSON data value; every input byte must leave literally,
// exactly once, in order.
func TestSSEBackfillRawJsonRawInterleavingPreservesBytes(t *testing.T) {
	back, _ := mintRestorable(t, ossKeySecret, "api_key")

	env1 := sseRecord("delta", "PREFIX-__PII_api_")
	env2 := sseToolCallEnvelope(t, `{"a":"b"}`)
	env3 := sseRecord("delta", "suffix-X")
	in := env1 + env2 + env3

	out := NewSSEBackfiller(back, nil).process([]byte(in))
	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("raw->JSON->raw interleaving reordered or lost bytes:\n got %q\nwant byte-identical %q", out, in)
	}

	events := decodeStream(t, out)
	if len(events) != 3 {
		t.Fatalf("event count = %d, want exactly 3", len(events))
	}
	if !json.Valid(events[1].Data) {
		t.Fatalf("JSON envelope data is not independently valid JSON: %q", events[1].Data)
	}
	if bytes.Contains(events[1].Data, []byte("__PII_")) {
		t.Fatalf("raw held prefix leaked into the JSON envelope: %q", events[1].Data)
	}
	concat := string(events[0].Data) + string(events[1].Data) + string(events[2].Data)
	if got := strings.Count(concat, "__PII_api_"); got != 1 {
		t.Fatalf("raw fragment occurrences = %d, want exactly 1 in %q", got, concat)
	}
}

// TestSSEBackfillEscapedSiblingUnchangedF4 pins D4's "only the restored token's
// bytes change". The origin arguments carry a sibling rune spelled on the WIRE
// as the six bytes `\u00e9`; a whole-leaf re-encode would normalize it to the
// raw UTF-8 `é` bytes. Assert after the restore that `\u00e9` is still present,
// the `é` bytes are not, the secret is restored exactly once, and the decoded
// concatenation is `café ` + secret + suffix.
func TestSSEBackfillEscapedSiblingUnchangedF4(t *testing.T) {
	back, p := mintRestorable(t, ossKeySecret, "api_key")
	if len(p) <= 8 {
		t.Fatalf("placeholder %q is too short to content-split", p)
	}

	const (
		k      = 8
		pre    = `caf\u00e9 ` // the JSON source spelling, not the decoded rune
		suffix = " END"
	)
	in := sseRawArgumentsEnvelope(pre+p[:k]) + sseRawArgumentsEnvelope(p[k:]+suffix)
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	if got := bytes.Count(out, ossKeySecret); got != 1 {
		t.Fatalf("restored secret occurrences = %d, want exactly 1 in %q", got, out)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder prefix survived: %q", out)
	}
	if !bytes.Contains(out, []byte(`\u00e9`)) {
		t.Fatalf("the wire escape \\u00e9 was normalized away: %q", out)
	}
	if bytes.Contains(out, []byte("é")) {
		t.Fatalf("the escaped rune was rewritten to raw UTF-8 bytes: %q", out)
	}

	events := decodeStream(t, out)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
	}
	arg1 := envelopeArguments(t, events[0].Data)
	arg2 := envelopeArguments(t, events[1].Data)
	if got, want := arg1+arg2, "café "+string(ossKeySecret)+suffix; got != want {
		t.Fatalf("concatenated decoded arguments = %q, want %q", got, want)
	}
}

// TestSSEBackfillTornInnerKeepsPlaceholderF5 pins D5 on the ORIGIN leaf.
//
// torn-inner-keeps-placeholder (GREEN today): the origin arguments start with
// `{"cmd":"echo ` -> not Encoded, not valid JSON, first non-space byte `{`, and
// the secret is a PEM that needs `\n` escaping, so KeepPlaceholder is true and
// the placeholder must be kept with the stream byte-identical.
// plain-content-restores (RED today): the origin is plain text, so the PEM
// split restores exactly once even though the secret needs escaping.
func TestSSEBackfillTornInnerKeepsPlaceholderF5(t *testing.T) {
	t.Run("torn-inner-keeps-placeholder", func(t *testing.T) {
		back, p := mintRestorable(t, pemSecret, "private_key")
		if len(p) <= 8 {
			t.Fatalf("placeholder %q is too short to content-split", p)
		}
		const (
			k      = 8
			pre    = `{"cmd":"echo `
			suffix = `"}`
		)
		in := sseToolCallEnvelope(t, pre+p[:k]) + sseToolCallEnvelope(t, p[k:]+suffix)
		out := NewSSEBackfiller(back, nil).process([]byte(in))
		if !bytes.Equal(out, []byte(in)) {
			t.Fatalf("torn inner-JSON origin changed:\n got %q\nwant byte-identical %q", out, in)
		}
		if bytes.Contains(out, pemSecret) {
			t.Fatalf("escape-needing secret was restored into a torn inner JSON fragment: %q", out)
		}
		for i, ev := range decodeStream(t, out) {
			if !json.Valid(ev.Data) {
				t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
			}
		}
	})

	t.Run("plain-content-restores", func(t *testing.T) {
		back, p := mintRestorable(t, pemSecret, "private_key")
		if len(p) <= 8 {
			t.Fatalf("placeholder %q is too short to content-split", p)
		}
		const (
			k      = 8
			pre    = "echo hello "
			suffix = " END"
		)
		in := sseToolCallEnvelope(t, pre+p[:k]) + sseToolCallEnvelope(t, p[k:]+suffix)
		out := NewSSEBackfiller(back, nil).process([]byte(in))

		events := decodeStream(t, out)
		if len(events) != 2 {
			t.Fatalf("event count = %d, want 2", len(events))
		}
		for i, ev := range events {
			if !json.Valid(ev.Data) {
				t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
			}
		}
		arg1 := envelopeArguments(t, events[0].Data)
		arg2 := envelopeArguments(t, events[1].Data)
		if got, want := arg1+arg2, pre+string(pemSecret)+suffix; got != want {
			t.Fatalf("concatenated decoded arguments = %q, want %q", got, want)
		}
		// The PEM secret carries a trailing newline, so it is counted in the
		// DECODED domain; the wire spelling escapes `\n`.
		if got := strings.Count(arg1+arg2, string(pemSecret)); got != 1 {
			t.Fatalf("restored secret occurrences = %d, want exactly 1 in %q", got, arg1+arg2)
		}
		if strings.Contains(arg1+arg2, p) {
			t.Fatalf("minted placeholder %q survived in %q", p, arg1+arg2)
		}
	})
}

// TestSSEBackfillNoMatchPartialPrefixByteIdenticalF6 pins D6: a valid-JSON
// stream carrying ordinary text and ending a leaf in a partial `__PII_` prefix
// (no minted token completes) must round-trip byte-for-byte. GREEN today.
func TestSSEBackfillNoMatchPartialPrefixByteIdenticalF6(t *testing.T) {
	back, _ := mintRestorable(t, ossKeySecret, "api_key")

	in := sseJSONEnvelope(t, "first line") +
		sseJSONEnvelope(t, "trailing __PII_") +
		sseJSONEnvelope(t, "after")
	out := NewSSEBackfiller(back, nil).process([]byte(in))
	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("no-match partial prefix was reflowed:\n got %q\nwant byte-identical %q", out, in)
	}
	for i, ev := range decodeStream(t, out) {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
	}
}

// TestSSEBackfillDuplicateKeyNoStitchF7 pins D7's duplicate-key hazard: two
// `arguments` string leaves at the SAME JSON path in one event. The origin
// fragment sits in the SECOND occurrence while the completing event has only
// the FIRST occurrence, so the carry key cannot uniquely resolve and the held
// bytes must be released unchanged. GREEN today; the test reports whether the
// fix keeps it green (it must not cross-stitch).
func TestSSEBackfillDuplicateKeyNoStitchF7(t *testing.T) {
	back, p := mintRestorable(t, ossKeySecret, "api_key")
	if len(p) <= 8 {
		t.Fatalf("placeholder %q is too short to content-split", p)
	}

	const pre = "BUCKET-"
	env1 := sseRawDataEnvelope(`{"arguments":"decoy","arguments":"` + pre + p[:8] + `"}`)
	env2 := sseRawDataEnvelope(`{"arguments":"` + p[8:] + `"}`)
	in := env1 + env2
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("duplicate-key ambiguity was stitched:\n got %q\nwant byte-identical %q", out, in)
	}
	if bytes.Contains(out, ossKeySecret) {
		t.Fatalf("duplicate-key ambiguity fabricated the secret: %q", out)
	}
	for i, ev := range decodeStream(t, out) {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
	}
}

// TestSSEBackfillEscapedSpellingRestoresF8 pins D8: the placeholder is split in
// the DECODED domain while the wire spells one byte with a `\u` escape. The `a`
// of the minted type is written `\u0061`, so the two decoded halves join to the
// real token and the secret restores exactly once with every envelope valid.
func TestSSEBackfillEscapedSpellingRestoresF8(t *testing.T) {
	back, p := mintRestorable(t, ossKeySecret, "api_key")
	if len(p) <= 8 {
		t.Fatalf("placeholder %q is too short to content-split", p)
	}

	const (
		k      = 8
		pre    = "BUCKET-"
		suffix = " END"
	)
	in := sseRawArgumentsEnvelope(pre+`__PII_\u0061p`) +
		sseRawArgumentsEnvelope(p[k:]+suffix)
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	if got := bytes.Count(out, ossKeySecret); got != 1 {
		t.Fatalf("restored secret occurrences = %d, want exactly 1 in %q", got, out)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder prefix survived: %q", out)
	}

	events := decodeStream(t, out)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
	}
	arg1 := envelopeArguments(t, events[0].Data)
	arg2 := envelopeArguments(t, events[1].Data)
	if got, want := arg1+arg2, pre+string(ossKeySecret)+suffix; got != want {
		t.Fatalf("concatenated decoded arguments = %q, want %q", got, want)
	}
}

// TestSSEBackfillForeignPlaceholderSplitUnchanged pins D6's foreign-token
// contract: a never-minted placeholder split across two complete-JSON
// envelopes is released byte-identically and never fabricated into a secret.
// GREEN today.
func TestSSEBackfillForeignPlaceholderSplitUnchanged(t *testing.T) {
	back, _ := mintRestorable(t, ossKeySecret, "api_key")
	const (
		k       = 8
		foreign = "__PII_api_key_deadbeefcafe__"
		pre     = "FOREIGN-"
		suffix  = "-END"
	)

	in := sseToolCallEnvelope(t, pre+foreign[:k]) + sseToolCallEnvelope(t, foreign[k:]+suffix)
	out := NewSSEBackfiller(back, nil).process([]byte(in))
	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("foreign placeholder split changed:\n got %q\nwant byte-identical %q", out, in)
	}
	if bytes.Contains(out, ossKeySecret) {
		t.Fatalf("foreign placeholder was fabricated into a secret: %q", out)
	}
}

// TestSSEBackfillOriginCoLocatedCompleteAndFragment pins D2's heldBytes and
// D3's origin carryPart: ONE target leaf carries a COMPLETE mapped placeholder
// (pA) followed by the start of a SECOND (pB). Both secrets must restore
// exactly once, `pre` and the `|` separator must be preserved, no `__PII_` may
// remain, and every envelope must stay valid JSON.
func TestSSEBackfillOriginCoLocatedCompleteAndFragment(t *testing.T) {
	secretA := ossKeySecret
	secretB := []byte("SECRET-LEAF-OSSKEY-0002")
	back, pA := mintRestorable(t, secretA, "api_key")
	pB, err := back.Mint(NewForwardWriter(newEngine()), secretB, "api_key")
	if err != nil {
		t.Fatalf("Mint(secretB): %v", err)
	}
	if len(pB) <= 8 {
		t.Fatalf("placeholder %q is too short to content-split", pB)
	}

	const (
		k      = 8
		pre    = "CO-LOCATED-"
		sep    = "|"
		suffix = "-END"
	)
	in := sseToolCallEnvelope(t, pre+pA+sep+pB[:k]) +
		sseToolCallEnvelope(t, pB[k:]+suffix)
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	if got := bytes.Count(out, secretA); got != 1 {
		t.Fatalf("pA restored %d times, want exactly 1 in %q", got, out)
	}
	if got := bytes.Count(out, secretB); got != 1 {
		t.Fatalf("pB restored %d times, want exactly 1 in %q", got, out)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder prefix survived: %q", out)
	}

	events := decodeStream(t, out)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
	}
	arg1 := envelopeArguments(t, events[0].Data)
	arg2 := envelopeArguments(t, events[1].Data)
	if got, want := arg1+arg2, pre+string(secretA)+sep+string(secretB)+suffix; got != want {
		t.Fatalf("concatenated arguments = %q, want %q", got, want)
	}
	if !strings.Contains(arg1, sep) {
		t.Fatalf("the %q separator was not preserved: %q", sep, arg1)
	}
}

// TestSSEBackfillBackToBackCarry pins D3's "then maybe start a NEW carry": the
// event that COMPLETES one split also starts the next. Envelope 1 carries
// pA[:8]; envelope 2 carries pA[8:] + "mid" + pB[:8]; envelope 3 carries
// pB[8:] + suffix. Both secrets must restore exactly once, no `__PII_` may
// remain, and every envelope must stay valid JSON.
func TestSSEBackfillBackToBackCarry(t *testing.T) {
	secretA := ossKeySecret
	secretB := []byte("SECRET-LEAF-OSSKEY-0002")
	back, pA := mintRestorable(t, secretA, "api_key")
	pB, err := back.Mint(NewForwardWriter(newEngine()), secretB, "api_key")
	if err != nil {
		t.Fatalf("Mint(secretB): %v", err)
	}
	if len(pA) <= 8 || len(pB) <= 8 {
		t.Fatalf("placeholders %q/%q are too short to content-split", pA, pB)
	}

	const (
		k      = 8
		pre    = "BACK-TO-BACK-"
		mid    = "-MID-"
		suffix = "-END"
	)
	in := sseToolCallEnvelope(t, pre+pA[:k]) +
		sseToolCallEnvelope(t, pA[k:]+mid+pB[:k]) +
		sseToolCallEnvelope(t, pB[k:]+suffix)
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	if got := bytes.Count(out, secretA); got != 1 {
		t.Fatalf("pA restored %d times, want exactly 1 in %q", got, out)
	}
	if got := bytes.Count(out, secretB); got != 1 {
		t.Fatalf("pB restored %d times, want exactly 1 in %q", got, out)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder prefix survived: %q", out)
	}

	events := decodeStream(t, out)
	if len(events) != 3 {
		t.Fatalf("event count = %d, want 3", len(events))
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
	}
	arg1 := envelopeArguments(t, events[0].Data)
	arg2 := envelopeArguments(t, events[1].Data)
	arg3 := envelopeArguments(t, events[2].Data)
	if got, want := arg1+arg2+arg3, pre+string(secretA)+mid+string(secretB)+suffix; got != want {
		t.Fatalf("concatenated arguments = %q, want %q", got, want)
	}
}

// TestSSEBackfillerHoldsAreBounded pins D9. A JSON envelope establishes an
// unresolved carry (`__PII_ap`); every continuation is a valid GRAMMAR
// extension of that carry (`i`,`_`,`k`,`e`,`y` -> `__PII_api`, `__PII_api_`,
// ...), so the ONLY legal reason to release one is the joint budget
// `writer.Held()+len(carry)+heldBytes`. Each continuation carries a large inert
// sibling whose size is derived from protocol.SSEBackfillHoldbackBytes, so
// several holds accumulate before the cap trips. Held() must never exceed the
// production constant, the first two continuations must strictly increase it
// (proving they were held rather than no-match released), and after the trip
// Held() must fall back to zero. Flush then releases every byte literally and
// in order: nothing dropped, nothing fabricated, no secret.
func TestSSEBackfillerHoldsAreBounded(t *testing.T) {
	back, _ := mintRestorable(t, ossKeySecret, "api_key")
	b := NewSSEBackfiller(back, nil)

	origin := sseJSONEnvelope(t, "hold __PII_ap")
	out := b.Write([]byte(origin))
	h0 := b.Held()
	if h0 <= 0 {
		t.Fatalf("Held() = %d after a JSON carry, want > 0 (held segments must be counted)", h0)
	}
	if h0 > protocol.SSEBackfillHoldbackBytes {
		t.Fatalf("Held() = %d, want <= %d", h0, protocol.SSEBackfillHoldbackBytes)
	}

	// limit/8 per inert pad means each continuation retains about limit/4
	// (raw+content), so at least two continuations fit before the joint cap
	// trips. The contents keep the carry a valid prefix with TokenLen == 0, so
	// no continuation can release for a reason other than the budget.
	pad := strings.Repeat("x", protocol.SSEBackfillHoldbackBytes/8)
	contents := []string{"i", "_", "k", "e", "y"}
	in := append([]byte(nil), origin...)
	trace := []int{h0}
	for i, c := range contents {
		seg := sseJSONEnvelopeWithPad(t, pad, c)
		in = append(in, seg...)
		out = append(out, b.Write([]byte(seg))...)
		h := b.Held()
		trace = append(trace, h)
		if h > protocol.SSEBackfillHoldbackBytes {
			t.Fatalf("Held() = %d after continuation %d (%q), want <= %d; trace=%v",
				h, i, c, protocol.SSEBackfillHoldbackBytes, trace)
		}
	}
	if trace[1] <= trace[0] || trace[2] <= trace[1] {
		t.Fatalf("Held() did not strictly increase across the first two held continuations: trace=%v", trace)
	}
	tripped := false
	for i := 1; i < len(trace); i++ {
		if trace[i-1] > 0 && trace[i] == 0 {
			tripped = true
			break
		}
	}
	if !tripped {
		t.Fatalf("joint budget never tripped during the loop: Held() trace = %v", trace)
	}
	if last := trace[len(trace)-1]; last != 0 {
		t.Fatalf("Held() = %d after the trip, want 0 (held segments must be released); trace=%v", last, trace)
	}

	out = append(out, b.Flush()...)
	if !bytes.Equal(out, in) {
		t.Fatalf("bounded hold did not release literally in order:\n got %q\nwant %q", out, in)
	}
	if bytes.Contains(out, ossKeySecret) {
		t.Fatalf("bounded hold fabricated a secret: %q", out)
	}
}

// TestSSEBackfillerOriginHoldStaysWithinBound pins D9 at the branch that
// ESTABLISHES a carry: the budget check must count the prefix the branch is
// about to install, because Held() counts both the held segment's content
// (which already contains that prefix) and len(carry) again. The inert pad is
// sized from the production constant so len(env)+len(value) lands just under
// the cap yet within len(p) of it: the pre-fix check admits a hold whose Held()
// overshoots the cap by len(p). After the fix the hold is rejected, every byte
// is released literally in order, and no secret is fabricated.
func TestSSEBackfillerOriginHoldStaysWithinBound(t *testing.T) {
	back, _ := mintRestorable(t, ossKeySecret, "api_key")
	b := NewSSEBackfiller(back, nil)

	const content = "hold __PII_ap"
	p := content[strings.Index(content, placeholderPrefix):]

	// len(env)+len(value) must equal cap-max(1,len(p)/2): <= cap, yet within
	// len(p) of it. Each pad byte lengthens env and value by exactly one, so
	// solve the pad length from an empty-pad baseline.
	target := protocol.SSEBackfillHoldbackBytes - max(1, len(p)/2)
	base := sseJSONEnvelopeWithPad(t, "", content)
	baseValue := base[len("data: ") : len(base)-len("\n\n")]
	pad := strings.Repeat("x", (target-(len(base)+len(baseValue)))/2)
	env := sseJSONEnvelopeWithPad(t, pad, content)
	value := env[len("data: ") : len(env)-len("\n\n")]
	if got := len(env) + len(value); got != target {
		t.Fatalf("envelope sizing: len(env)+len(value) = %d, want %d", got, target)
	}
	if target <= protocol.SSEBackfillHoldbackBytes-len(p) {
		t.Fatalf("sizing is not inside the overshoot window: %d <= %d", target, protocol.SSEBackfillHoldbackBytes-len(p))
	}

	out := b.Write([]byte(env))
	h := b.Held()
	t.Logf("Held() = %d, cap = %d, len(p) = %d", h, protocol.SSEBackfillHoldbackBytes, len(p))
	if h > protocol.SSEBackfillHoldbackBytes {
		t.Fatalf("Held() = %d, want <= %d", h, protocol.SSEBackfillHoldbackBytes)
	}
	out = append(out, b.Flush()...)
	if !bytes.Equal(out, []byte(env)) {
		t.Fatalf("rejected hold did not release literally:\n got %q\nwant %q", out, env)
	}
	if bytes.Contains(out, ossKeySecret) {
		t.Fatalf("rejected hold fabricated a secret: %q", out)
	}
}

// sseEncodedContentEnvelope renders one SSE record whose data value carries a
// `content` string that is ITSELF a JSON document with a `content` string.
// Walk therefore yields the inner `content` leaf with Encoded=true, so a
// restore into it must re-spell the secret through BOTH enclosing JSON string
// wrappers (D4).
func sseEncodedContentEnvelope(t *testing.T, inner string) string {
	t.Helper()
	nested, err := json.Marshal(map[string]any{"content": inner})
	if err != nil {
		t.Fatalf("marshal nested content: %v", err)
	}
	doc, err := json.Marshal(map[string]any{
		"choices": []any{
			map[string]any{"delta": map[string]string{"content": string(nested)}},
		},
	})
	if err != nil {
		t.Fatalf("marshal encoded envelope: %v", err)
	}
	return "data: " + string(doc) + "\n\n"
}

// encodedEnvelopeContent decodes one SSE data value two levels: the outer
// choices[0].delta.content string, then the `content` string inside it.
func encodedEnvelopeContent(t *testing.T, data []byte) string {
	t.Helper()
	var outer struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &outer); err != nil {
		t.Fatalf("unmarshal outer envelope: %v", err)
	}
	if len(outer.Choices) == 0 {
		t.Fatalf("outer envelope has no choices: %q", data)
	}
	nested := []byte(outer.Choices[0].Delta.Content)
	var inner struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(nested, &inner); err != nil {
		t.Fatalf("unmarshal nested content %q: %v", nested, err)
	}
	return inner.Content
}

// TestSSEBackfillEncodedCrossLeafSplitRestores pins D4: a placeholder is split
// across TWO complete JSON envelopes whose target leaf is reached via an
// Encoded=true nested JSON string, so RawSpelling must escape the PEM secret
// through both enclosing wrappers. The secret restores exactly once, no
// `__PII_` remains, every emitted envelope is valid JSON, and the concatenated
// decoded inner content equals the original text.
func TestSSEBackfillEncodedCrossLeafSplitRestores(t *testing.T) {
	back, p := mintRestorable(t, pemSecret, "private_key")
	if len(p) <= 8 {
		t.Fatalf("placeholder %q is too short to content-split", p)
	}

	const (
		k      = 8
		pre    = "BUCKET-"
		suffix = " END"
	)
	in := sseEncodedContentEnvelope(t, pre+p[:k]) +
		sseEncodedContentEnvelope(t, p[k:]+suffix)
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder prefix survived: %q", out)
	}

	events := decodeStream(t, out)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
	}
	c1 := encodedEnvelopeContent(t, events[0].Data)
	c2 := encodedEnvelopeContent(t, events[1].Data)
	if got, want := c1+c2, pre+string(pemSecret)+suffix; got != want {
		t.Fatalf("concatenated decoded content = %q, want %q", got, want)
	}
	if got := strings.Count(c1+c2, string(pemSecret)); got != 1 {
		t.Fatalf("restored secret occurrences = %d, want exactly 1 in %q", got, c1+c2)
	}
}

// TestSSEBackfillAbortResetsCarry pins D11's abort row: an SSEObserver abort
// while a carry is unresolved must drop the carry, its held segments and the
// joint accounting, so Held() returns to zero and the stream is closed. The
// first Write establishes a real carry (Held() > 0); the observer aborts on the
// next event, whose bytes become the sole output.
func TestSSEBackfillAbortResetsCarry(t *testing.T) {
	back, _ := mintRestorable(t, ossKeySecret, "api_key")
	abortRecord := []byte("data: {\"aborted\":true}\n\n")
	seen := 0
	obs := func(ev protocol.Event) []byte {
		seen++
		if seen == 2 {
			return abortRecord
		}
		return nil
	}
	b := NewSSEBackfiller(back, obs)

	if out := b.Write([]byte(sseJSONEnvelope(t, "hold __PII_ap"))); len(out) != 0 {
		t.Fatalf("first Write released %q, want a held carry", out)
	}
	if h := b.Held(); h <= 0 {
		t.Fatalf("Held() = %d after establishing a carry, want > 0", h)
	}

	out := b.Write([]byte(sseJSONEnvelopeWithPad(t, "", "i")))
	if !bytes.Equal(out, abortRecord) {
		t.Fatalf("abort output = %q, want %q", out, abortRecord)
	}
	if h := b.Held(); h != 0 {
		t.Fatalf("Held() = %d after abort, want 0", h)
	}
	if !b.Closed() {
		t.Fatalf("Closed() = false after abort, want true")
	}
	if out := b.Flush(); len(out) != 0 {
		t.Fatalf("Flush() after abort = %q, want empty", out)
	}
}

// TestSSEBackfillRawPrefixDoesNotLeakIntoLeafLessJSON pins D2's writer handoff
// for a VALID-JSON event that falls back to the raw path because it carries NO
// identifiable string leaf (`{"a":1,"b":true,"c":null}`). The preceding raw
// event leaves the single writer holding a partial placeholder tail; that
// handoff must happen BEFORE the JSON event is processed, even though the event
// is then handled by the raw writer. Otherwise the held tail is fed together
// with the JSON value and the event ships as `__PII_api_{"a":1}`: invalid JSON
// and a leaked fragment. Every input byte must leave literally, exactly once,
// in order.
func TestSSEBackfillRawPrefixDoesNotLeakIntoLeafLessJSON(t *testing.T) {
	back, _ := mintRestorable(t, ossKeySecret, "api_key")

	in := sseRecord("delta", "PREFIX-__PII_api_") +
		sseRecord("delta", `{"a":1,"b":true,"c":null}`)
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("raw prefix leaked into a leaf-less JSON event:\n got %q\nwant byte-identical %q", out, in)
	}

	events := decodeStream(t, out)
	if len(events) != 2 {
		t.Fatalf("event count = %d, want exactly 2", len(events))
	}
	if !json.Valid(events[1].Data) {
		t.Fatalf("event 2 data is not valid JSON: %q", events[1].Data)
	}
	if bytes.Contains(events[1].Data, []byte("__PII_")) {
		t.Fatalf("raw held prefix leaked into the JSON event: %q", events[1].Data)
	}
	concat := string(events[0].Data) + string(events[1].Data)
	if got := strings.Count(concat, "__PII_api_"); got != 1 {
		t.Fatalf("raw fragment occurrences = %d, want exactly 1 in %q", got, concat)
	}
}
