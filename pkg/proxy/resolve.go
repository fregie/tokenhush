package proxy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/fregie/tokenhush/pkg/config"
)

// Built-in vendor base URLs. A forwarder joins the request path onto the base
// URL, so these carry no trailing slash and no path part. Exported because the
// routing table is part of the frozen CLI-visible surface, asserted by
// pkg/proxy/resolve_test.go and internal/cli tests.
const (
	AnthropicBaseURL = "https://api.anthropic.com"
	OpenAIBaseURL    = "https://api.openai.com"
)

// ErrUnknownUpstream is returned when neither a configured upstream nor the
// built-in routing table recognises the request path. It is returned instead
// of guessing a vendor: a near-miss path must be a visible typed rejection,
// never a silent misroute to a provider that cannot serve it.
var ErrUnknownUpstream = errors.New("proxy: no upstream for request path")

// maxRoutePathRunes bounds the attacker-controlled path embedded in an
// ErrUnknownUpstream message.
const maxRoutePathRunes = 120

// Upstream is the resolved routing target for one request path.
type Upstream struct {
	// BaseURL is the vendor base URL the request is forwarded to. It is empty
	// exactly when Local is true.
	BaseURL string
	// Local marks the one named exception route: the request is served by the
	// gateway itself (GET /v1/models) and no upstream is ever dialled.
	Local bool
}

// builtinRoutes is the ONE explicit built-in routing table. Every entry is a
// data-bearing path that exactly one vendor serves, so assigning it cannot
// misroute content: the OpenAI-compatible surface (chat, completions,
// embeddings, responses, moderations, images, audio) and the Anthropic-style
// surface (the Messages API and its token counting / batch creation).
//
// /v1/models is the single named exception. It is deliberately NOT mapped to
// an upstream: both vendors serve it with the same meaning, so the gateway
// answers model discovery itself. Any path absent from this map is a typed
// ErrUnknownUpstream -- there is no default route.
var builtinRoutes = map[string]Upstream{
	"/v1/audio/speech":          {BaseURL: OpenAIBaseURL},
	"/v1/audio/transcriptions":  {BaseURL: OpenAIBaseURL},
	"/v1/audio/translations":    {BaseURL: OpenAIBaseURL},
	"/v1/chat/completions":      {BaseURL: OpenAIBaseURL},
	"/v1/completions":           {BaseURL: OpenAIBaseURL},
	"/v1/embeddings":            {BaseURL: OpenAIBaseURL},
	"/v1/images/edits":          {BaseURL: OpenAIBaseURL},
	"/v1/images/generations":    {BaseURL: OpenAIBaseURL},
	"/v1/moderations":           {BaseURL: OpenAIBaseURL},
	"/v1/responses":             {BaseURL: OpenAIBaseURL},
	"/v1/messages":              {BaseURL: AnthropicBaseURL},
	"/v1/messages/batches":      {BaseURL: AnthropicBaseURL},
	"/v1/messages/count_tokens": {BaseURL: AnthropicBaseURL},
	"/v1/models":                {Local: true},
}

// BuiltinRoute is one read-only projection of the built-in routing table. It
// exists so the CLI can report the effective routing at startup without a
// second copy of the table drifting from this one.
type BuiltinRoute struct {
	// Path is the exact request path the entry serves.
	Path string
	// BaseURL is the vendor base URL the path forwards to; empty when Local.
	BaseURL string
	// Local marks the one named exception route (GET /v1/models).
	Local bool
}

// BuiltinRoutes returns the built-in routing table as a fresh, path-sorted
// slice. Resolve remains the only behavioural owner of the table; this is a
// read-only view and carries no routing logic of its own.
func BuiltinRoutes() []BuiltinRoute {
	routes := make([]BuiltinRoute, 0, len(builtinRoutes))
	for path, upstream := range builtinRoutes {
		routes = append(routes, BuiltinRoute{Path: path, BaseURL: upstream.BaseURL, Local: upstream.Local})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Path < routes[j].Path })
	return routes
}

// Resolve maps an inbound request path to its upstream.
//
// Configured upstreams: entries win over the built-in table, and among them the
// longest match wins; a configured match applies to its exact path and to any
// path below it on a path-segment boundary. The query and fragment are ignored
// for route selection and one trailing slash is tolerated, and nothing else is
// normalised: case, "." and ".." and percent-escapes are never folded, so
// near-misses such as /v1/model, /v1/models/foo and /v1/chat/completionsX stay
// typed ErrUnknownUpstream errors instead of hitting a neighbouring route.
func Resolve(path string, cfg config.Config) (Upstream, error) {
	canonical, ok := canonicalRoutePath(path)
	if !ok {
		return Upstream{}, fmt.Errorf("%w: empty request path", ErrUnknownUpstream)
	}
	if upstream, ok := configuredUpstream(canonical, cfg.Upstreams); ok {
		return upstream, nil
	}
	if upstream, ok := builtinRoutes[canonical]; ok {
		return upstream, nil
	}
	return Upstream{}, fmt.Errorf("%w: %q", ErrUnknownUpstream, boundedRoutePath(canonical))
}

// configuredUpstream returns the upstream of the longest configured match that
// applies to path, or false when none does. Blank matches and blank targets are
// skipped defensively: pkg/config rejects both before a route is live, and a
// blank target must never become a live dial.
func configuredUpstream(path string, upstreams []config.Upstream) (Upstream, bool) {
	bestKey, bestTarget := "", ""
	for _, entry := range upstreams {
		key, ok := canonicalRoutePath(strings.TrimSpace(entry.Match))
		if !ok || !routeMatches(key, path) {
			continue
		}
		target := strings.TrimRight(strings.TrimSpace(entry.Target), "/")
		if target == "" {
			continue
		}
		if len(key) > len(bestKey) || (len(key) == len(bestKey) && key < bestKey) {
			bestKey, bestTarget = key, target
		}
	}
	if bestKey == "" {
		return Upstream{}, false
	}
	return Upstream{BaseURL: bestTarget}, true
}

// routeMatches reports whether a configured key routes path: the exact path,
// any path below it on a segment boundary (so "/v1/chat" matches
// "/v1/chat/completions" but not "/v1/chatX"), or the explicit "/" catch-all.
func routeMatches(key, path string) bool {
	return key == path || key == "/" || strings.HasPrefix(path, key+"/")
}

// canonicalRoutePath drops the query and fragment and trims trailing slashes.
// ok is false only for an empty or slash-only path.
func canonicalRoutePath(path string) (string, bool) {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path != "/" {
		path = strings.TrimRight(path, "/")
	}
	return path, path != ""
}

// boundedRoutePath bounds the path embedded in an error message so a client
// cannot inflate the message without bound, cutting on rune boundaries.
func boundedRoutePath(path string) string {
	if len(path) <= maxRoutePathRunes {
		return path
	}
	runes := []rune(path)
	if len(runes) > maxRoutePathRunes {
		runes = runes[:maxRoutePathRunes]
	}
	return string(runes) + "..."
}
