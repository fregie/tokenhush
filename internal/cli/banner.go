package cli

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/supply"
)

// printStartupBanner reports what the gateway is about to do, once the listener
// is bound: the loopback endpoint, the effective upstream routing and the
// tool-setup helper. It is metadata only — no secret, placeholder or body — and
// is emitted on stderr alongside the running log.
func printStartupBanner(w io.Writer, cfg config.Config, addrs []string, port int) {
	if w == nil {
		return
	}
	for _, addr := range addrs {
		fmt.Fprintf(w, "tokenhush: v%s listening on http://%s\n", supply.Version, addr)
	}
	printConfiguredUpstreams(w, cfg)
	printBuiltinUpstreams(w)
	printToolHint(w, addrs, port)
}

// printConfiguredUpstreams lists the operator's routing overrides, if any.
func printConfiguredUpstreams(w io.Writer, cfg config.Config) {
	if len(cfg.Upstreams) == 0 {
		fmt.Fprintln(w, "tokenhush: upstreams: none configured; built-in routes apply")
		return
	}
	fmt.Fprintln(w, "tokenhush: upstreams (config):")
	for _, upstream := range cfg.Upstreams {
		fmt.Fprintf(w, "tokenhush:   %s -> %s\n", upstream.Match, upstream.Target)
	}
}

// printBuiltinUpstreams groups the built-in table by target so the startup
// report stays short and stays in sync with Resolve.
func printBuiltinUpstreams(w io.Writer) {
	var order []string
	paths := map[string][]string{}
	local := false
	for _, route := range proxy.BuiltinRoutes() {
		if route.Local {
			local = true
			continue
		}
		if _, seen := paths[route.BaseURL]; !seen {
			order = append(order, route.BaseURL)
		}
		paths[route.BaseURL] = append(paths[route.BaseURL], route.Path)
	}
	fmt.Fprintln(w, "tokenhush: built-in routes:")
	for _, target := range order {
		fmt.Fprintf(w, "tokenhush:   %d paths -> %s (e.g. %s)\n", len(paths[target]), target, representativePath(target, paths[target]))
	}
	if local {
		fmt.Fprintln(w, "tokenhush:   1 local route: GET /v1/models (no upstream)")
	}
}

// representativePath picks the best-known path of a target for the "e.g."
// clause, so the report names a path an operator recognises.
func representativePath(target string, paths []string) string {
	want := map[string]string{
		proxy.OpenAIBaseURL:    "/v1/chat/completions",
		proxy.AnthropicBaseURL: "/v1/messages",
	}
	for _, path := range paths {
		if path == want[target] {
			return path
		}
	}
	return paths[0]
}

// printToolHint reports the two base-URL forms a client needs and points at the
// env helper, whose snippet is the source of truth for each supported tool.
func printToolHint(w io.Writer, addrs []string, port int) {
	host := config.DefaultHost
	if len(addrs) > 0 {
		if bound, _, err := net.SplitHostPort(addrs[0]); err == nil && bound != "" {
			host = bound
		}
	}
	base := "http://" + net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Fprintf(w, "tokenhush: point your tool at %s (Anthropic-style) or %s/v1 (OpenAI-compatible)\n", base, base)
	fmt.Fprintf(w, "tokenhush: `tokenhush env <tool>` prints a setup snippet (%s)\n", strings.Join(envTools, ", "))
}
