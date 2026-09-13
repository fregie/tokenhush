package cli

// The `rules` command group: sync the signed rule pack, or roll back to the
// previous verified pack (or the built-in defaults). It mirrors the `update`
// command's shape: a thin CLI over a testable package, with every fallback
// surfaced as a warning.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/rules"
)

// EnvNoRuleSync disables rule sync egress. Rule sync is one of the two
// disclosed switchable vendor-bound categories (the other is update check); the
// disclosure in egress.yaml documents this switch, and `rules sync` honours it
// at the command boundary so no request leaves the machine when it is set.
const EnvNoRuleSync = "TOKENHUSH_NO_RULE_SYNC"

// ruleSyncDisabled reports whether the operator asked to switch rule sync off.
// Only an explicit truthy value disables it, so an empty or unrelated value
// leaves the command's default behaviour unchanged.
func ruleSyncDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvNoRuleSync))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// newRulesClient is the injectable seam of the rules commands. Production opens
// the cache and high-water store under the platform data root and trusts the
// embedded rule keys; tests inject a client backed by httptest and a temp dir.
var newRulesClient = func(warn func(string)) (*rules.Client, error) {
	dataDir, err := platform.DataDir()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(dataDir, "rules")
	cache, err := rules.OpenFileCache(root)
	if err != nil {
		return nil, err
	}
	highWater, err := rules.OpenFileHighWater(filepath.Join(root, "highwater.json"))
	if err != nil {
		return nil, err
	}
	return &rules.Client{
		BaseURL:   rules.DefaultBaseURL,
		Channel:   rules.DefaultChannel,
		Verifier:  &rules.Verifier{Keys: rules.DefaultKeys(), CurrentBinaryVersion: Version},
		Cache:     cache,
		HighWater: highWater,
		Warn:      warn,
	}, nil
}

// rulesCommand dispatches `tokenhush rules <sync|rollback>`.
func rulesCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rulesUsage)
		return ExitUsage
	}
	switch args[0] {
	case "sync":
		return rulesSyncCommand(args[1:], stdout, stderr)
	case "rollback":
		return rulesRollbackCommand(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "tokenhush: rules: unknown subcommand %q\n", args[0])
		fmt.Fprint(stderr, rulesUsage)
		return ExitUsage
	}
}

const rulesUsage = `Usage of rules: tokenhush rules <sync|rollback>

  tokenhush rules sync [--check]  fetch and verify signed detection rules
  tokenhush rules rollback        re-select the previous verified rule pack

Syncing is one of the two requests that leave your machine (see ` + "`tokenhush privacy`" + `).
Any failure falls back to the built-in defaults and is reported as a warning.
`

// rulesSyncCommand is the CLI entry for `tokenhush rules sync [--check]`.
func rulesSyncCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var check bool
	fs.BoolVar(&check, "check", false, "report whether a newer rule pack is available without writing anything")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage of rules sync: tokenhush rules sync [--check]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Fetch the signed rule manifest and bundle, verify the signature, freshness,")
		fmt.Fprintln(stderr, "serial and revocation list, then cache and activate the pack. --check reports")
		fmt.Fprintln(stderr, "without downloading the bundle or writing the cache. A failure falls back to")
		fmt.Fprintln(stderr, "the built-in defaults and warns.")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: rules sync: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}

	if ruleSyncDisabled() {
		fmt.Fprintf(stdout, "rules sync: disabled by %s; no request sent\n", EnvNoRuleSync)
		return ExitOK
	}

	client, err := newRulesClient(func(msg string) { fmt.Fprintln(stderr, msg) })
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: rules sync: %v\n", err)
		return ExitFailure
	}
	res, err := client.Sync(context.Background(), check)
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: rules sync: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintln(stdout, rulesSyncLine(res))
	return ExitOK
}

// rulesSyncLine renders the human status line for a sync result.
func rulesSyncLine(res rules.SyncResult) string {
	switch res.Status {
	case rules.SyncUpdated:
		return fmt.Sprintf("rules sync: updated to serial %d", res.Serial)
	case rules.SyncCurrent:
		return fmt.Sprintf("rules sync: already current (serial %d)", res.Serial)
	case rules.SyncAvailable:
		return fmt.Sprintf("rules sync: update available (serial %d); run `tokenhush rules sync` to apply", res.Serial)
	case rules.SyncCached:
		return fmt.Sprintf("rules sync: offline; using cached serial %d", res.Serial)
	default:
		return "rules sync: using built-in defaults"
	}
}

// rulesRollbackCommand is the CLI entry for `tokenhush rules rollback`.
func rulesRollbackCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage of rules rollback: tokenhush rules rollback")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Re-select the highest earlier verified rule pack, or the built-in defaults")
		fmt.Fprintln(stderr, "when none remains. A revoked pack is never restored.")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: rules rollback: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}

	client, err := newRulesClient(func(msg string) { fmt.Fprintln(stderr, msg) })
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: rules rollback: %v\n", err)
		return ExitFailure
	}
	res, err := client.Rollback()
	if err != nil {
		if errors.Is(err, rules.ErrNothingToRollback) {
			fmt.Fprintln(stdout, "rules rollback: already using built-in defaults")
			return ExitOK
		}
		fmt.Fprintf(stderr, "tokenhush: rules rollback: %v\n", err)
		return ExitFailure
	}
	if res.Config == nil {
		fmt.Fprintln(stdout, "rules rollback: reverted to built-in defaults")
		return ExitOK
	}
	fmt.Fprintf(stdout, "rules rollback: active serial %d\n", res.Serial)
	return ExitOK
}
