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
//     on nothing.
//   - message, prompt: conversation text addressed to a human or a model.
//   - think, reasoning: model scratchpad text, never executed.
//   - todo, todowrite, notebook, plan: plan/todo/document bodies.
//   - question, ask: a question to the user; the reply arrives as content.
//   - read, read_file: read-only file inspection; it cannot write. A read of
//     the allowlist file is therefore also exempt: reading cannot change the
//     channel, and the file's bytes stay protected by the C8 exclusion set
//     (force-redacted outbound, never restored inbound).
//   - glob, grep: read-only search patterns; a pattern that spells a guarded
//     shape is a search, not an action.
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
	"notebook",
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

// isMutationChannelFunctionNamePath reports whether a decoded-leaf JSON Pointer
// names a tool call's function-name field. It uses the same final-'/'-token rule
// as isMutationChannelArgumentsPath, so a sibling key that merely contains
// "name" is not treated as the field itself.
func isMutationChannelFunctionNamePath(path string) bool {
	return path[strings.LastIndexByte(path, '/')+1:] == mutationChannelFunctionNameField
}

// mutationChannelCarrierArgumentsPath maps a function-name leaf path to the
// arguments leaf path of the same tool call (the sibling in the same parent
// object). The caller guarantees namePath ends in mutationChannelFunctionNameField
// (via isMutationChannelFunctionNamePath), so the prefix still ends with the
// '/' opening that field.
func mutationChannelCarrierArgumentsPath(namePath string) string {
	return namePath[:len(namePath)-len(mutationChannelFunctionNameField)] + mutationChannelArgumentsField
}

// mutationChannelArgumentsPrefix returns the tool-call path prefix that a
// function-name leaf and an arguments leaf share (the path up to and including
// the '/' opening the field). The caller guarantees argumentsPath ends in
// mutationChannelArgumentsField.
func mutationChannelArgumentsPrefix(argumentsPath string) string {
	return argumentsPath[:len(argumentsPath)-len(mutationChannelArgumentsField)]
}

// mutationChannelFunctionNamePrefix returns the same shared tool-call path
// prefix from a function-name leaf path. The caller guarantees namePath ends in
// mutationChannelFunctionNameField.
func mutationChannelFunctionNamePrefix(namePath string) string {
	return namePath[:len(namePath)-len(mutationChannelFunctionNameField)]
}

// mutationChannelCarrierArgumentsPaths returns the set of walked arguments-leaf
// paths owned by a tool call whose function name is a carrier name. It is built
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
		argumentsPath := mutationChannelCarrierArgumentsPath(leaf.Path)
		if mutationChannelCarrierToolName(leaf.Content) {
			if out == nil {
				out = make(map[string]struct{}, 2)
			}
			out[argumentsPath] = struct{}{}
			continue
		}
		delete(out, argumentsPath)
	}
	return out
}
