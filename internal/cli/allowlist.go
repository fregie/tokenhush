// The `allowlist` command group: list, add and remove C7 runtime allowlist
// entries. It is a thin client over the daemon's loopback control plane
// (pkg/proxy's guarded /allowlist route): the running gateway is the only
// writer, so a missing session is an explicit failure with a `tokenhush run`
// hint — never a fallback that writes <DataDir>/allowlist.json behind the
// running store's back (that would desynchronize the on-disk copy from the
// live redaction state).

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/fregie/tokenhush/pkg/platform"
)

// controlAllowlistPath mirrors the control plane's allowlist route
// (pkg/proxy's controlAllowlistPath and the gateway's registration).
const controlAllowlistPath = "/allowlist"

const allowlistUsage = `Usage of allowlist: tokenhush allowlist <list|add|remove>

  tokenhush allowlist list           print the effective allowlist entries
  tokenhush allowlist add <entry>    let one value leave unredacted
  tokenhush allowlist remove <entry> stop letting a value leave unredacted

Entries are matched byte-for-byte (case-sensitive substring), exactly like the
tokenhush.yaml allowlist: key, and the static entries stay in effect. Changes
apply to the running gateway immediately and persist to
<DataDir>/allowlist.json. The gateway is the only writer: this command talks to
its loopback control API, so the gateway must be running (start it with
` + "`tokenhush run`" + `), and the file is never edited directly.
`

// allowlistCommand dispatches `tokenhush allowlist <list|add|remove>`.
func allowlistCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, allowlistUsage)
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return allowlistListCommand(args[1:], stdout, stderr)
	case "add":
		return allowlistMutateCommand("add", args[1:], stdout, stderr)
	case "remove":
		return allowlistMutateCommand("remove", args[1:], stdout, stderr)
	case "-h", "--help":
		fmt.Fprint(stderr, allowlistUsage)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "tokenhush: allowlist: unknown subcommand %q\n", args[0])
		fmt.Fprint(stderr, allowlistUsage)
		return ExitUsage
	}
}

// allowlistListCommand is the CLI entry for `tokenhush allowlist list`. The
// entries are the whole output, one per line, in the store's deterministic
// order; an empty store prints nothing, so the output is usable as a data
// stream.
func allowlistListCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && isHelpArg(args[0]) {
		fmt.Fprint(stderr, allowlistUsage)
		return ExitOK
	}
	if len(args) > 0 {
		fmt.Fprintf(stderr, "tokenhush: allowlist: list: unexpected argument %q\n", args[0])
		fmt.Fprintln(stderr, "usage: tokenhush allowlist list")
		return ExitUsage
	}

	client, code := allowlistControlClient(stderr)
	if code != ExitOK {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlRequestTimeout)
	defer cancel()
	body, err := client.get(ctx, controlAllowlistPath, nil)
	if err != nil {
		return allowlistFail(stderr, err)
	}
	var entries []string
	if err := json.Unmarshal(body, &entries); err != nil {
		fmt.Fprintf(stderr, "tokenhush: allowlist: malformed control response: %v\n", err)
		return ExitFailure
	}
	for _, entry := range entries {
		fmt.Fprintln(stdout, entry)
	}
	return ExitOK
}

// allowlistMutateCommand is the CLI entry for `tokenhush allowlist add|remove
// <entry>`. The entry is arbitrary data taken verbatim from argv (it may begin
// with a dash), so the subcommand deliberately has no flag surface; -h/--help
// is honoured only when it is the sole argument.
func allowlistMutateCommand(action string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && isHelpArg(args[0]) {
		fmt.Fprint(stderr, allowlistUsage)
		return ExitOK
	}
	if len(args) == 0 {
		fmt.Fprintf(stderr, "tokenhush: allowlist: %s needs exactly one <entry> argument\n", action)
		fmt.Fprintf(stderr, "usage: tokenhush allowlist %s <entry>\n", action)
		return ExitUsage
	}
	if len(args) > 1 {
		fmt.Fprintf(stderr, "tokenhush: allowlist: %s: unexpected argument %q\n", action, args[1])
		fmt.Fprintf(stderr, "usage: tokenhush allowlist %s <entry>\n", action)
		return ExitUsage
	}
	entry := args[0]

	client, code := allowlistControlClient(stderr)
	if code != ExitOK {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlRequestTimeout)
	defer cancel()
	payload := controlAllowlistBody{Entry: entry}
	var err error
	switch action {
	case "add":
		_, err = client.post(ctx, controlAllowlistPath, payload)
	case "remove":
		_, err = client.delete(ctx, controlAllowlistPath, payload)
	}
	if err != nil {
		return allowlistFail(stderr, err)
	}
	fmt.Fprintf(stdout, "allowlist: %s %q\n", allowlistPastTense(action), entry)
	return ExitOK
}

// allowlistPastTense renders the human confirmation verb of a mutation.
func allowlistPastTense(action string) string {
	if action == "remove" {
		return "removed"
	}
	return "added"
}

// allowlistControlClient resolves the running gateway's control session (the
// <DataDir>/run.json pid/port file plus the <DataDir>/control.token bearer
// token) and returns an authenticated loopback client. A missing, unreadable
// or unreachable session is reported as a failure with a start-the-gateway
// hint; it is never a direct-file fallback.
func allowlistControlClient(stderr io.Writer) (controlClient, int) {
	dataDir, err := platform.DataDir()
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: allowlist: %v\n", err)
		return controlClient{}, ExitFailure
	}
	session, err := loadControlSession(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: allowlist: %v; start the gateway first with `tokenhush run`\n", err)
		return controlClient{}, ExitFailure
	}
	return newControlClient(session, defaultControlHTTPClient), ExitOK
}

// allowlistFail renders a failed control call: every message carries the
// `tokenhush: allowlist:` prefix and exits 1. A transport failure gets the
// same start-the-gateway hint as a missing session, because both mean there is
// no live gateway to mutate through; HTTP errors keep the control API's stable
// message verbatim.
func allowlistFail(stderr io.Writer, err error) int {
	if errors.Is(err, errControlUnreachable) {
		fmt.Fprintf(stderr, "tokenhush: allowlist: %v; start the gateway first with `tokenhush run`\n", err)
		return ExitFailure
	}
	fmt.Fprintf(stderr, "tokenhush: allowlist: %v\n", err)
	return ExitFailure
}

// controlAllowlistBody is the frozen W5.3 wire shape of POST/DELETE /allowlist:
// exactly one "entry" field, always in the body (the API rejects query
// strings).
type controlAllowlistBody struct {
	Entry string `json:"entry"`
}

// isHelpArg reports whether arg is an explicit help request.
func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help"
}
