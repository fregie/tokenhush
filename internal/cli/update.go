// update.go owns `tokenhush update [--check]`: the operator's view of the
// signed binary stream and of the D17 install-source routing. The env switch is
// consulted before the data dir is resolved and before any fetcher is
// constructed, so a disabled switch cannot reach the network. Nothing is
// configurable beyond --check: the origin, the paths and the trust roots are
// frozen in pkg/supply.
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

func init() { register("update", updateCommand) }

// noUpdateCheckEnv is the disclosed switch of the update-check egress category.
// The CLI owns it: pkg/supply performs no network request on its own, and the
// command returns on this switch before it constructs the updater at all.
const noUpdateCheckEnv = "TOKENHUSH_NO_UPDATE_CHECK"

// Update fetch bounds: documents are small and bounded, the artifact is large.
const (
	updateDocTimeout      = 30 * time.Second
	updateArtifactTimeout = 5 * time.Minute
)

// updateSeams carries the injectable update-command operations. Production uses
// defaultUpdateSeams; tests interpose the install source, the runner, the
// target and the fetchers to pin delegation, the no-write check and the
// no-network switch without touching a real install.
type updateSeams struct {
	lookupEnv func(string) (string, bool)
	dataDir   func() (string, error)
	docs      func() supply.Fetcher
	artifacts func() supply.Fetcher
	verifier  supply.Verifier
	now       func() time.Time
	source    supply.InstallSource
	runner    supply.CommandRunner
	target    string
}

// defaultUpdateSeams is the production seam set.
func defaultUpdateSeams() updateSeams {
	return updateSeams{
		lookupEnv: os.LookupEnv,
		dataDir:   platform.DataDir,
		docs:      func() supply.Fetcher { return supply.NewBoundedHTTPFetcher(updateDocTimeout, supply.MaxUpdateDocBytes) },
		artifacts: func() supply.Fetcher {
			return supply.NewBoundedHTTPFetcher(updateArtifactTimeout, supply.MaxArtifactBytes)
		},
		verifier: supply.NewStaticVerifier(),
		now:      time.Now,
		source:   supply.DefaultSource(),
	}
}

// updateCommand is the CLI entry for `tokenhush update`.
func updateCommand(args []string, stdout, stderr io.Writer) int {
	return updateWith(args, stdout, stderr, defaultUpdateSeams())
}

// updateWith runs the update command. The switch is checked FIRST, before the
// data dir is resolved and long before any fetcher exists, so a disabled switch
// cannot reach the network even by accident.
func updateWith(args []string, stdout, stderr io.Writer, seams updateSeams) int {
	check := false
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&check, "check", false, "report the verdict without installing, downloading or writing anything")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: update: unexpected argument %q\n", flags.Arg(0))
		return exitUsage
	}
	if disabled(seams.lookupEnv, noUpdateCheckEnv) {
		fmt.Fprintf(stdout, "update: %s=1 is set; no request was sent.\n", noUpdateCheckEnv)
		return exitOK
	}
	dataDir, err := seams.dataDir()
	if err != nil {
		return updateFailure(stderr, err)
	}
	updater, err := supply.NewUpdater(supply.UpdateConfig{
		DataDir: dataDir, Target: seams.target, Source: seams.source,
		Fetcher: seams.docs(), ArtifactFetcher: seams.artifacts(), Verifier: seams.verifier,
		Now: seams.now, Runner: seams.runner, LookupEnv: seams.lookupEnv, Out: stdout,
	})
	if err != nil {
		return updateFailure(stderr, err)
	}
	if _, err := updater.Update(context.Background(), check); err != nil {
		return updateFailure(stderr, err)
	}
	return exitOK
}

// updateFailure reports one update failure on stderr and returns exit 1.
func updateFailure(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "tokenhush: update: %v\n", err)
	return exitFailure
}
