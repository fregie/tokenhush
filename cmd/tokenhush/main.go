// Command tokenhush is the thin process entry point: it hands the arguments to
// the internal/cli dispatcher, which owns every command.
package main

import (
	"os"

	"github.com/fregie/tokenhush/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
