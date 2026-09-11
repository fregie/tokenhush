// Command tokenhush is the CLI entry point of the local Tokenhush gateway.
package main

import (
	"os"

	"github.com/fregie/tokenhush/internal/cli"
)

// version is the build version injected by GoReleaser through
// -ldflags "-X main.version=...". Keep the symbol in package main: it is the
// release pipeline's ldflags target.
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
