package proxy

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// mutationChannelRefusalNotice is the fixed, model-visible refusal text. It is
// deliberately plain prose: the model must be able to read that the call was
// refused and why, and the client can show it to the user. It carries no secret,
// no internal path and no data-directory detail beyond the channel names that are
// already public.
//
// W6.4 (the SSE path) reuses this exact string, so a refusal looks the same
// whether the tool call arrived buffered or streamed.
//
// The notice is no longer delivered as the raw arguments value: clients parse
// `arguments` as JSON and hard-fail on bare prose, which loses the tool call.
// It is delivered verbatim as the `error` field of mutationChannelRefusalArguments
// (see that function), so JSON.parse succeeds and the model sees a structured
// refusal it can adapt to. The text below is byte-frozen as the field value.
const mutationChannelRefusalNotice = "tokenhush refused this tool call: its arguments matched the self-protection guard for the allowlist change channel (the tokenhush allowlist CLI, the loopback control port, or the allowlist file). The allowlist can only be changed by the human operator through the authenticated control plane, so this call was not executed."

// mutationChannelRefusalArguments builds the JSON object literal the guard
// delivers in place of a refused tool call's whole arguments value:
//
//	{"error":"<verbatim notice>","refused":true,"channel":"<class>"}
//
// The shape is a deliberate, user-authorized change to the frozen refusal
// delivery: the notice text itself stays byte-identical, but it now travels as a
// valid JSON object string so a client that does `JSON.parse(arguments)` — as
// OpenAI-shaped clients do — succeeds and can present the refusal instead of
// losing the tool call to a parse error. class is the matched channel class (the
// empty string for the two fail-closed paths, which match no pattern).
func mutationChannelRefusalArguments(class string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"error":`)
	buf.Write(jsonQuote(mutationChannelRefusalNotice))
	buf.WriteString(`,"refused":true,"channel":`)
	buf.Write(jsonQuote(class))
	buf.WriteByte('}')
	return buf.Bytes()
}

// mutationChannelArgumentsField is the JSON object member whose string value
// carries a tool call's arguments (OpenAI: .../tool_calls/N/function/arguments).
// The guard scopes itself to this field so it never rewrites unrelated leaves
// (the assistant prose, a tool name, a note), and so one offending tool call in
// a batch never touches its siblings.
const mutationChannelArgumentsField = "arguments"

// isMutationChannelArgumentsPath reports whether a decoded-leaf JSON Pointer
// names a tool call's arguments field. It compares the final '/' reference token
// exactly: the nested leaves of an arguments parent end in their own field name
// (…/arguments#/cmd ends in "cmd"), and a sibling key that merely contains '#'
// (…/arguments#y) is one token, not "arguments", so neither is treated as the
// arguments field itself.
func isMutationChannelArgumentsPath(path string) bool {
	return path[strings.LastIndexByte(path, '/')+1:] == mutationChannelArgumentsField
}

// mutationChannelGuardTargets locates the tool-call arguments leaves the guard
// may rewrite: the leaf ordinals the leafRewriter will report for the arguments
// field, for the terminal (non-JSON arguments) and the Encoded (valid-JSON
// arguments) shapes. The map value records whether the tool call is a
// content-bearing file tool (see mutationChannelContentTools), so the caller can
// classify it with the reduced content-tool table.
//
// Only top-level leaves are eligible: a leaf nested inside an Encoded parent is
// owned by that parent's whole-string replacement, never edited on its own —
// that is the frozen rule that stops a command split across leaves from evading
// a per-leaf match. The nested-run lengths come from re-walking each Encoded
// parent's decoded content (protocol.Walk), exactly the rule consumeEncoded
// uses, so the ordinals stay aligned with the rewriter even when a sibling key
// contains '#' (escapePointer does not escape '#').
//
// The carrier-tool exemption is applied here, per tool call: an arguments leaf
// whose sibling function-name leaf (same tool call, …/function/name) carries a
// name on the frozen non-action carrier list (see carriertools.go) is not a
// target at all, so the tool call whose arguments are content — a delegation
// prompt, a plan, a read-only pattern — cannot reach the refusal. Every other
// name, an unknown name, and a call with no name leaf keep the text inspection;
// a content-bearing file tool keeps only the file-write class.
func mutationChannelGuardTargets(walked []protocol.Leaf) (terminalTargets, encodedTargets map[int]bool, err error) {
	terminalTargets = make(map[int]bool)
	encodedTargets = make(map[int]bool)
	carrierArguments := mutationChannelCarrierArgumentsPaths(walked)
	contentArguments := mutationChannelContentArgumentsPaths(walked)
	terminalIdx, encodedIdx := 0, 0
	for i := 0; i < len(walked); {
		leaf := walked[i]
		if leaf.Encoded {
			if _, carrier := carrierArguments[leaf.Path]; isMutationChannelArgumentsPath(leaf.Path) && !carrier {
				_, content := contentArguments[leaf.Path]
				encodedTargets[encodedIdx] = content
			}
			nested, nerr := protocol.Walk([]byte(leaf.Content))
			if nerr != nil {
				return nil, nil, fmt.Errorf("proxy: re-walk encoded leaf %q: %w", leaf.Path, nerr)
			}
			encodedIdx++
			for _, inner := range nested {
				if inner.Encoded {
					encodedIdx++
					continue
				}
				terminalIdx++
			}
			i += 1 + len(nested)
			continue
		}
		if _, carrier := carrierArguments[leaf.Path]; isMutationChannelArgumentsPath(leaf.Path) && !carrier {
			_, content := contentArguments[leaf.Path]
			terminalTargets[terminalIdx] = content
		}
		terminalIdx++
		i++
	}
	return terminalTargets, encodedTargets, nil
}

// detectMutationChannelForTool classifies an arguments value with the table the
// owning tool call deserves: the reduced content-tool table for a content-bearing
// file tool, the full table otherwise.
func (p *Pipeline) detectMutationChannelForTool(text string, contentTool bool) (string, bool) {
	if contentTool {
		return p.DetectMutationChannelContentTool(text)
	}
	return p.DetectMutationChannel(text)
}

// matchEncodedArguments reports whether a valid-JSON arguments document reaches
// the mutation channel, and which class matched.
//
// Each nested terminal leaf is tested (a command written into a single nested
// leaf keeps its shape there). Because JSON punctuation separates two leaves,
// the same command split across leaves is invisible to a raw-text scan and to a
// per-leaf scan, so the concatenation of the nested terminal-leaf contents is
// tested too — both with no separator (a command split mid-token) and with a
// single space (a command split at a token boundary). This is what makes the
// parent replacement load-bearing: the variant that rewrites only a matched
// nested leaf cannot see a split and would let it through.
//
// The raw arguments document is deliberately NOT tested as a whole: JSON
// punctuation and escaping put the owning command's name behind a `":"` prefix,
// which would defeat the mention/position analysis and refuse a tool call whose
// text merely mentions a guarded shape (the live `grep` false positive).
func (p *Pipeline) matchEncodedArguments(content []byte) (string, bool) {
	return p.matchEncodedArgumentsForTool(content, false)
}

// matchEncodedArgumentsForTool is matchEncodedArguments with a selectable
// classifier, so a content-bearing file tool's arguments are matched with the
// reduced content-tool table.
func (p *Pipeline) matchEncodedArgumentsForTool(content []byte, contentTool bool) (string, bool) {
	detect := func(text string) (string, bool) {
		return p.detectMutationChannelForTool(text, contentTool)
	}
	nested, err := protocol.Walk(content)
	if err != nil {
		return "", false
	}
	var concatenated, spaced strings.Builder
	first := true
	for _, leaf := range nested {
		if leaf.Encoded {
			continue
		}
		if class, matched := detect(leaf.Content); matched {
			return class, true
		}
		concatenated.WriteString(leaf.Content)
		if !first {
			spaced.WriteByte(' ')
		}
		first = false
		spaced.WriteString(leaf.Content)
	}
	if class, matched := detect(concatenated.String()); matched {
		return class, true
	}
	if class, matched := detect(spaced.String()); matched {
		return class, true
	}
	return "", false
}

// guardResponseToolCalls is the W6.3 response-path step: for every tool call
// whose arguments reach the mutation channel it replaces the whole arguments
// string with mutationChannelRefusalNotice, and returns the rewritten body
// together with its fresh walk. A response with no match is returned unchanged
// (same bytes, same walk).
//
// It runs inside transformResponse, after protocol.Walk and before the value
// policy; the policy, ResponseContent transformers and backfill then continue
// on its output, so the frozen transformers -> backfill order is untouched. A
// match is never a whole-response error: the response is still delivered, with
// only the offending tool call(-s) rewritten.
func (p *Pipeline) guardResponseToolCalls(body []byte, walked []protocol.Leaf) ([]byte, []protocol.Leaf, error) {
	if p == nil || !p.selfProtectionEnabled || len(body) == 0 {
		return body, walked, nil
	}
	terminalTargets, encodedTargets, err := mutationChannelGuardTargets(walked)
	if err != nil {
		return nil, nil, err
	}
	if len(terminalTargets) == 0 && len(encodedTargets) == 0 {
		return body, walked, nil
	}
	rewriter := &leafRewriter{
		walked: walked,
		edit: func(terminalIdx int, _ string, content []byte) ([]byte, bool) {
			contentTool, ok := terminalTargets[terminalIdx]
			if !ok {
				return content, false
			}
			class, matched := p.detectMutationChannelForTool(string(content), contentTool)
			if !matched {
				return content, false
			}
			p.noteBufferedGuardRefusal(class)
			return mutationChannelRefusalArguments(class), true
		},
		parentEdit: func(encodedIdx int, _ string, content []byte) ([]byte, bool) {
			contentTool, ok := encodedTargets[encodedIdx]
			if !ok {
				return nil, false
			}
			class, matched := p.matchEncodedArgumentsForTool(content, contentTool)
			if !matched {
				return nil, false
			}
			p.noteBufferedGuardRefusal(class)
			return mutationChannelRefusalArguments(class), true
		},
	}
	out, changed, err := rewriter.rewrite(body, "")
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: guard response tool calls: %w", err)
	}
	if !changed {
		return body, walked, nil
	}
	rewalked, err := protocol.Walk(out)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: re-walk guarded response: %w", err)
	}
	return out, rewalked, nil
}
