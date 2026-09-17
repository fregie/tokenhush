// privacy.go owns `tokenhush privacy`: the human-readable and JSON disclosure
// of every vendor-bound egress category (invariant 6). The disclosure itself
// is generated from egress.yaml — the repository-root single source of truth —
// into egress_generated.go by the folded codegen step below; this file only
// renders it. There is no third category and no hand-maintained copy.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

//go:generate go run egress_gen.go

func init() { register("privacy", privacyCommand) }

// egressCategory is one vendor-bound egress category as rendered from
// egress.yaml: the environment switch that short-circuits it, the vendor host
// it would reach and the retention that applies to what the vendor records.
type egressCategory struct {
	Name      string `json:"name"`
	Switch    string `json:"switch"`
	Host      string `json:"host"`
	Retention string `json:"retention"`
}

// egressDisclosureDoc is the exact JSON shape `privacy --json` prints.
type egressDisclosureDoc struct {
	Categories []egressCategory `json:"categories"`
}

// privacyCommand is the CLI entry for `tokenhush privacy`.
func privacyCommand(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	flags := flag.NewFlagSet("privacy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&asJSON, "json", false, "print the disclosure document as JSON")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: privacy: unexpected argument %q\n", flags.Arg(0))
		return exitUsage
	}
	if asJSON {
		encoded, err := json.Marshal(egressDisclosureDoc{Categories: egressDisclosure})
		if err != nil {
			fmt.Fprintf(stderr, "tokenhush: privacy: %v\n", err)
			return exitFailure
		}
		fmt.Fprintln(stdout, string(encoded))
		return exitOK
	}
	fmt.Fprintf(stdout, "tokenhush egress disclosure: %d vendor-bound categories (source: egress.yaml)\n", len(egressDisclosure))
	for _, category := range egressDisclosure {
		fmt.Fprintf(stdout, "%s: host %s; switch %s=1 disables it; retention %s\n",
			category.Name, category.Host, category.Switch, category.Retention)
	}
	return exitOK
}
