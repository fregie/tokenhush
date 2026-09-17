// rules.go owns `tokenhush rules <sync|rollback>`: the operator's view of the
// signed rule stream. `rules sync` runs supply's frozen sequence unchanged, and
// `rules sync --check` runs exactly the same sequence in a throwaway sandbox
// with the real anti-rollback mark exposed read-only, so it reports the verdict
// while writing no state at all. The env switch is consulted before the data
// dir is even resolved, so a disabled switch cannot reach the network.
// The rollback subcommand lives in rules_rollback.go.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/supply"
)

func init() { register("rules", rulesCommand) }

// noRuleSyncEnv is the disclosed switch of the rule-sync egress category. It is
// the same name pkg/supply consults; the CLI returns on it too so the command
// can report that no request was sent. Only the frozen "1" disables the sync.
const noRuleSyncEnv = "TOKENHUSH_NO_RULE_SYNC"

// rulesRequestTimeout bounds one rules fetch, matching the startup cache read's
// fetcher.
const rulesRequestTimeout = 30 * time.Second

// rulesSeams carries the injectable rules-command operations. Production uses
// defaultRulesSeams; tests interpose each seam to pin the no-write, no-network
// and verification behaviours without a socket or real state.
type rulesSeams struct {
	lookupEnv func(string) (string, bool)
	dataDir   func() (string, error)
	fetcher   func() supply.Fetcher
	verifier  supply.Verifier
	now       func() time.Time
}

// defaultRulesSeams is the production seam set. Every URL is composed from
// supply's frozen constants and no key or base URL is configurable.
func defaultRulesSeams() rulesSeams {
	return rulesSeams{
		lookupEnv: os.LookupEnv,
		dataDir:   platform.DataDir,
		fetcher: func() supply.Fetcher {
			return supply.NewBoundedHTTPFetcher(rulesRequestTimeout, supply.MaxRulesDocBytes)
		},
		verifier: supply.NewStaticVerifier(),
		now:      time.Now,
	}
}

// disabled reports whether an egress switch carries the frozen "1".
func disabled(lookup func(string) (string, bool), name string) bool {
	value, ok := lookup(name)
	return ok && value == "1"
}

// rulesCommand is the CLI entry for `tokenhush rules`.
func rulesCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		rulesUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "sync":
		return rulesSync(args[1:], stdout, stderr, defaultRulesSeams())
	case "rollback":
		return rulesRollback(args[1:], stdout, stderr, defaultRulesSeams())
	default:
		fmt.Fprintf(stderr, "tokenhush: rules: unknown subcommand %q\n", args[0])
		rulesUsage(stderr)
		return exitUsage
	}
}

// rulesUsage prints the subcommand help after a usage error.
func rulesUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: tokenhush rules <sync [--check]|rollback>")
}

// rulesSync runs `rules sync`, with or without --check.
func rulesSync(args []string, stdout, stderr io.Writer, seams rulesSeams) int {
	check := false
	flags := flag.NewFlagSet("rules sync", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&check, "check", false, "run every check and report the verdict without writing any state")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: rules sync: unexpected argument %q\n", flags.Arg(0))
		return exitUsage
	}
	if disabled(seams.lookupEnv, noRuleSyncEnv) {
		fmt.Fprintf(stdout, "rules sync: %s=1 is set; no request was sent.\n", noRuleSyncEnv)
		return exitOK
	}
	dataDir, err := seams.dataDir()
	if err != nil {
		return rulesFailure(stderr, "sync", err)
	}
	syncer, cleanup, err := newSync(dataDir, check, seams)
	if err != nil {
		return rulesFailure(stderr, "sync", err)
	}
	defer cleanup()
	if err := syncer.Sync(context.Background()); err != nil {
		return rulesFailure(stderr, "sync", err)
	}
	state := syncer.Active()
	for _, warning := range state.Warnings {
		fmt.Fprintf(stderr, "tokenhush: %s\n", warning)
	}
	if check {
		if state.Serial > 0 {
			fmt.Fprintf(stdout, "rules sync --check: serial %d is available and verified; no state was written (no cache write, no high-water advance, no activation).\n", state.Serial)
		} else {
			fmt.Fprintln(stdout, "rules sync --check: the active rules pack is already current; no state was written (no cache write, no high-water advance, no activation).")
		}
		return exitOK
	}
	if state.Serial > 0 {
		fmt.Fprintf(stdout, "rules sync: serial %d activated (source %s).\n", state.Serial, state.Source)
	} else {
		fmt.Fprintln(stdout, "rules sync: the active rules pack is already current; no new pack was activated.")
	}
	return exitOK
}

// newSync builds the sync layer for one run. A check builds the sandbox: the
// cache lives in a throwaway directory, and the REAL anti-rollback mark is
// exposed read-only so every check (including the replay rule) runs against the
// persisted state while Advance can never move it. The sandbox documents are
// discarded with the directory, so nothing the check does is observable.
func newSync(dataDir string, check bool, seams rulesSeams) (*supply.RulesSync, func(), error) {
	if !check {
		syncer, err := supply.NewRulesSync(supply.RulesSyncConfig{
			DataDir: dataDir, Fetcher: seams.fetcher(), Verifier: seams.verifier,
			LookupEnv: seams.lookupEnv, Now: seams.now,
		})
		return syncer, func() {}, err
	}
	scratch, err := os.MkdirTemp("", "tokenhush-rules-check-*")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	mark, err := supply.NewRulesHighWater(dataDir)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	syncer, err := supply.NewRulesSync(supply.RulesSyncConfig{
		DataDir: scratch, Fetcher: seams.fetcher(), Verifier: seams.verifier,
		HighWater: readOnlyHighWater{inner: mark}, LookupEnv: seams.lookupEnv, Now: seams.now,
	})
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return syncer, cleanup, nil
}

// readOnlyHighWater exposes the persisted anti-rollback mark for reading while
// making Advance a no-op, the one seam a --check run needs to perform every
// check without writing the mark.
type readOnlyHighWater struct{ inner supply.HighWater }

// Current implements supply.HighWater.
func (m readOnlyHighWater) Current() int64 { return m.inner.Current() }

// Advance implements supply.HighWater without writing anything.
func (m readOnlyHighWater) Advance(int64) error { return nil }

// rulesFailure reports one rules failure on stderr and returns exit 1.
func rulesFailure(stderr io.Writer, op string, err error) int {
	fmt.Fprintf(stderr, "tokenhush: rules %s: %v\n", op, err)
	return exitFailure
}
