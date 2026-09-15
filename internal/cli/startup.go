package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// writeStartupSummary prints the effective upstream routing table and the
// tool-onboarding hint. It is local only: no network request is made. w == nil
// is a no-op.
func writeStartupSummary(w io.Writer, cfg *config.Config) {
	if w == nil || cfg == nil {
		return
	}
	writeRouteTable(w)
	writeUpstreamOverrides(w, cfg)
	writeOnboarding(w, cfg)
}

// writeRouteTable renders the built-in routing table in the order
// proxy.BuiltinRoutes returns it. Padding is computed from the entries, so the
// columns stay aligned as the table changes.
func writeRouteTable(w io.Writer) {
	routes := proxy.BuiltinRoutes()
	pathWidth, nameWidth := 0, 0
	for _, r := range routes {
		if len(r.Path) > pathWidth {
			pathWidth = len(r.Path)
		}
		if len(r.Upstream.Name) > nameWidth {
			nameWidth = len(r.Upstream.Name)
		}
	}
	fmt.Fprintln(w, "tokenhush: upstream routes (a request path selects its upstream; config `upstreams:` overrides win):")
	for _, r := range routes {
		fmt.Fprintf(w, "tokenhush:   %-*s  -> %-*s  %s", pathWidth, r.Path, nameWidth, r.Upstream.Name, r.Upstream.BaseURL)
		if r.Exception {
			fmt.Fprint(w, "   (named exception: model discovery)")
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "tokenhush:   any other path is rejected, never misrouted")
}

// writeUpstreamOverrides lists the config `upstreams:` overrides that win over
// the built-in table. Keys are sorted lexically so the output is deterministic.
func writeUpstreamOverrides(w io.Writer, cfg *config.Config) {
	if len(cfg.Upstreams) == 0 {
		return
	}
	keys := make([]string, 0, len(cfg.Upstreams))
	for key := range cfg.Upstreams {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	keyWidth := 0
	for _, key := range keys {
		if len(key) > keyWidth {
			keyWidth = len(key)
		}
	}
	fmt.Fprintln(w, "tokenhush: your upstreams: overrides:")
	for _, key := range keys {
		label := "host"
		if strings.HasPrefix(key, "/") {
			label = "path prefix"
		}
		fmt.Fprintf(w, "tokenhush:   %-*s  -> %s   (%s)\n", keyWidth, key, cfg.Upstreams[key], label)
	}
}

// writeOnboarding shows how to point a client tool at the loopback gateway. It
// is skipped when no port is configured, since the hint would carry no URL.
func writeOnboarding(w io.Writer, cfg *config.Config) {
	port := int(cfg.Listen.Port)
	if port <= 0 {
		return
	}
	root := fmt.Sprintf("http://127.0.0.1:%d", port)
	commands := []string{
		"tokenhush env claude",
		"tokenhush env codex",
		"tokenhush env <tool>",
	}
	commandWidth := 0
	for _, command := range commands {
		if len(command) > commandWidth {
			commandWidth = len(command)
		}
	}
	fmt.Fprintln(w, "tokenhush: point a tool at the gateway, then run it:")
	fmt.Fprintf(w, "tokenhush:   %-*s   # ANTHROPIC_BASE_URL=%s\n", commandWidth, commands[0], root)
	fmt.Fprintf(w, "tokenhush:   %-*s   # base_url=%s/v1\n", commandWidth, commands[1], root)
	fmt.Fprintf(w, "tokenhush:   %-*s   # %s\n", commandWidth, commands[2], strings.Join(envTools, ", "))
}
