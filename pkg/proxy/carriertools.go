package proxy

import (
	"strings"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// This file is the C8 carrier-tool exemption: the mutation-channel guard's
// target is an ACTING tool call — one that can execute a command, make an HTTP
// request or write a file. A tool whose arguments are CONTENT destined for a
// human or another agent (a delegation prompt, a plan, a document body, a todo
// item, a question) cannot reach the mutation channel by construction, so the
// guard must discriminate on the TOOL, not on the text the arguments happen to
// mention. Live testing exposed exactly that false positive: the orchestrator's
// own `task` delegation calls were refused because the delegation prompt
// described the guard and, in doing so, quoted the CLI form, the control path
// and the allowlist file name.
//
// The list below is frozen and explicitly enumerated (no user-facing config
// key, matching the pattern-inventory policy: an auditable constant cited by
// docs/security.md). The exemption is structural: it keys on the tool call's
// own `function.name` value — the sibling JSON leaf of the `arguments` leaf the
// guard inspects (…/tool_calls/N/function/name) — never on a heuristic over the
// argument text.
//
// Boundary (documented in docs/security.md): the guard cannot know whether a
// harness's tool really is what its name says, so an ACTING tool deliberately
// named like a carrier would evade this exemption. That residual is bounded:
// the control-token force-redaction and the outbound re-check are independent
// of this guard and still protect the token and the allowlist-file content. A
// tool name not on the list keeps today's text inspection, including an unknown
// name and a tool call with no sibling `name` leaf at all.

// mutationChannelCarrierTools is the frozen, enumerated list of non-action
// carrier tool names. Every entry receives or returns text and cannot execute a
// command, make an HTTP request or write a file, so its arguments are out of
// the mutation channel's scope:
//
//   - task, spawn_agent, subagent, agent, agent_task: delegation — the
//     arguments are a prompt handed to another agent; the tool call itself acts
//     on nothing. Any tool call the delegated agent then makes is inspected on
//     its own.
//   - message, prompt: conversation text addressed to a human or a model.
//   - think, reasoning: model scratchpad text, never executed.
//   - todo, todowrite, plan: plan/todo/document bodies.
//   - question, ask: a question to the user; the reply arrives as content.
//   - read, read_file: read-only file inspection; it cannot write. A read of
//     the allowlist file is therefore also exempt: reading cannot change the
//     channel, and the file's bytes stay protected by the C8 exclusion set
//     (force-redacted outbound, never restored inbound).
//   - glob, grep: read-only search patterns; a pattern that spells a guarded
//     shape is a search, not an action.
//
// `notebook` was REMOVED from this list: a notebook tool can execute code
// cells, so its arguments are not guaranteed to be content. It now keeps the
// full inspection (the fail-closed direction).
//
// The list is deliberately closed: adding a name widens the exemption (and the
// carrier-named acting-tool boundary above), so it is a security-relevant edit,
// not a convenience knob.
var mutationChannelCarrierTools = []string{
	"task",
	"spawn_agent",
	"subagent",
	"agent",
	"agent_task",
	"message",
	"prompt",
	"think",
	"reasoning",
	"todo",
	"todowrite",
	"plan",
	"question",
	"ask",
	"read",
	"read_file",
	"glob",
	"grep",
}

// MutationChannelCarrierTools returns a copy of the frozen non-action carrier
// tool-name list. It exists so the set is auditable from outside the package
// (tests, the security documentation) without exporting the mutable slice; the
// returned slice belongs to the caller.
func MutationChannelCarrierTools() []string {
	out := make([]string, len(mutationChannelCarrierTools))
	copy(out, mutationChannelCarrierTools)
	return out
}

// mutationChannelCarrierToolName reports whether name is on the frozen carrier
// list. The comparison is exact: a differently-spelled name is unknown and
// keeps today's text inspection, so a harness whose carrier tool is not
// enumerated here fails toward refusing rather than toward exempting.
func mutationChannelCarrierToolName(name string) bool {
	for _, carrier := range mutationChannelCarrierTools {
		if name == carrier {
			return true
		}
	}
	return false
}

// mutationChannelFunctionNameField is the JSON object member carrying a tool
// call's function name: the sibling leaf of the arguments leaf the guard
// inspects, on the same tool call (…/tool_calls/N/function/name).
const mutationChannelFunctionNameField = "name"

// mutationChannelInputField is the Anthropic Messages tool_use input field. It
// is the object (or JSON string) carrying a tool call's arguments in that
// shape, so the guard scopes it exactly like the OpenAI `arguments` field.
const mutationChannelInputField = "input"

// isMutationChannelFunctionNamePath reports whether a decoded-leaf JSON Pointer
// names a tool call's function-name field. It uses the same final-'/'-token rule
// as isMutationChannelArgumentsPath, so a sibling key that merely contains
// "name" is not treated as the field itself.
func isMutationChannelFunctionNamePath(path string) bool {
	return path[strings.LastIndexByte(path, '/')+1:] == mutationChannelFunctionNameField
}

// mutationChannelGuardRootKey returns the canonical root key of a decoded-leaf
// path: the leaf's own path when it is a root, or the enclosing
// arguments-or-input root when the leaf is nested under object-form arguments.
// The key is what the carrier/content-tool exemption maps are built from, so a
// nested leaf must resolve to exactly the key the sibling name leaf produces.
func mutationChannelGuardRootKey(path string) (string, bool) {
	for _, field := range [...]string{mutationChannelArgumentsField, mutationChannelInputField} {
		suffix := "/" + field
		if strings.HasSuffix(path, suffix) {
			return path, true
		}
		if i := strings.LastIndex(path, suffix+"/"); i >= 0 {
			return path[:i+len(suffix)], true
		}
	}
	return "", false
}

// mutationChannelGuardToolPrefix returns the tool-call path prefix a name leaf
// and its arguments/input root share (the path up to and including the '/'
// opening the root's field). It is derived from the root key, so an
// object-form child leaf resolves to the same prefix as its sibling name leaf.
func mutationChannelGuardToolPrefix(path string) (string, bool) {
	root, ok := mutationChannelGuardRootKey(path)
	if !ok {
		return "", false
	}
	i := strings.LastIndexByte(root, '/')
	if i < 0 {
		return "", false
	}
	return root[:i+1], true
}

// mutationChannelToolRootKeys returns the two candidate root keys of a tool
// call identified by its function-name leaf: the OpenAI `arguments` root and
// the Anthropic `input` root. A name leaf registers both, so whichever shape
// the arguments arrive in resolves to an exempt root.
func mutationChannelToolRootKeys(namePath string) [2]string {
	base := namePath[:len(namePath)-len(mutationChannelFunctionNameField)]
	return [2]string{base + mutationChannelArgumentsField, base + mutationChannelInputField}
}

// mutationChannelFunctionNamePrefix returns the shared tool-call path prefix
// from a function-name leaf path. The caller guarantees namePath ends in
// mutationChannelFunctionNameField.
func mutationChannelFunctionNamePrefix(namePath string) string {
	return namePath[:len(namePath)-len(mutationChannelFunctionNameField)]
}

// mutationChannelCarrierArgumentsPaths returns the set of arguments/input root
// keys owned by a tool call whose function name is a carrier name. It is built
// from the sibling name leaves of the same walk, so the buffered guard can skip
// exactly those tool calls and nothing else. Duplicate keys follow the JSON
// convention (the later member wins, matching encoding/json), because a later
// name leaf sets or clears the entry in document order.
func mutationChannelCarrierArgumentsPaths(walked []protocol.Leaf) map[string]struct{} {
	var out map[string]struct{}
	for _, leaf := range walked {
		if !isMutationChannelFunctionNamePath(leaf.Path) {
			continue
		}
		roots := mutationChannelToolRootKeys(leaf.Path)
		if mutationChannelCarrierToolName(leaf.Content) {
			if out == nil {
				out = make(map[string]struct{}, 2)
			}
			for _, root := range roots {
				out[root] = struct{}{}
			}
			continue
		}
		for _, root := range roots {
			delete(out, root)
		}
	}
	return out
}
