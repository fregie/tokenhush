package proxy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fregie/tokenhush/pkg/config"
)

// Built-in vendor base URLs. A forwarder joins the request path onto the base
// URL, so these carry no trailing slash and no path part.
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
