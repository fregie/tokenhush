package cli

import (
	"flag"
	"fmt"
	"io"
)

func privacyCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("privacy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "print the disclosure as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage of privacy: tokenhush privacy [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Show which requests leave your machine for the vendor, what the")
		fmt.Fprintln(stderr, "server can observe, and how to switch each category off.")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: privacy: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}
	if asJSON {
		fmt.Fprint(stdout, egressGeneratedJSON)
		return ExitOK
	}
	fmt.Fprint(stdout, egressGeneratedText)
	return ExitOK
}
