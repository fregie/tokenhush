// Command layering is the CLI half of the layering guard. It shares Load,
// Check, and the encoded graph with the Go test, so
// `bash scripts/check-layering.sh` and `go test ./internal/layering/` always
// agree.
//
// Exit codes:
//
//	0  green (or full-graph) guard passed
//	1  at least one layering violation
//	2  the graph could not be loaded
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fregie/tokenhush/internal/layering"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	graph, err := layering.Load(ctx, ".", layering.RunCommand)
	if err != nil {
		fmt.Fprintf(os.Stderr, "layering: %v\n", err)
		return 2
	}

	result := layering.Check(graph, layering.Options{FullGraph: layering.FullGraphEnabled()})

	for _, s := range result.Skips {
		fmt.Printf("skip: %s\n", s.Reason)
	}

	if !result.OK() {
		for _, v := range result.Violations {
			if v.Edge == (layering.Edge{}) {
				fmt.Fprintf(os.Stderr, "layering violation: %s\n", v.Reason)
				continue
			}
			fmt.Fprintf(os.Stderr, "layering violation: %s (%s)\n", v.Reason, v.Edge)
		}
		return 1
	}

	fmt.Printf("layering: OK (%d packages, %d internal edges, %d skipped)\n",
		len(graph.Present), len(graph.Edges), len(result.Skips))
	return 0
}
