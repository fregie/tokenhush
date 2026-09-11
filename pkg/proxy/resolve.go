package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/extension"
)

// Provider names reported on every resolved extension.Upstream. ProviderCustom
// is used when a config upstreams: override routes a path the built-in table
// does not know (for example a custom OpenAI-compatible endpoint).
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
	ProviderCustom    = "custom"
)

// Built-in provider base URLs (docs/13 §4.1). The forwarder joins the request
// path onto the base URL, so these carry no trailing slash and no path part.
const (
	AnthropicBaseURL = "https://api.anthropic.com"
	OpenAIBaseURL    = "https://api.openai.com"
)

// ErrUnknownUpstream means no route matched the request: neither a config
// upstreams: override nor the built-in provider table recognises the path.
// It is returned instead of guessing a provider, so an unrecognised request
// is rejected rather than silently sent to the wrong one (docs/13 §4.1).
var ErrUnknownUpstream = errors.New("proxy: no upstream for request path")

// builtinUpstreams is the path → provider table for the V1 tools that speak
// the Anthropic Messages API or the OpenAI Chat Completions / Responses API
// (docs/12 §6.1). Only unambiguous, real request paths are listed:
// /v1/models is deliberately absent because both providers serve it, and
// guessing there would break the never-misroute rule.
var builtinUpstreams = map[string]extension.Upstream{
	"/v1/messages":              {Name: ProviderAnthropic, BaseURL: AnthropicBaseURL},
	"/v1/messages/count_tokens": {Name: ProviderAnthropic, BaseURL: AnthropicBaseURL},
	"/v1/chat/completions":      {Name: ProviderOpenAI, BaseURL: OpenAIBaseURL},
	"/v1/responses":             {Name: ProviderOpenAI, BaseURL: OpenAIBaseURL},
}

// DefaultRouterName is the extension.Router name of the built-in router.
const DefaultRouterName = "default"

// Resolver is the built-in default extension.Router: it maps a request path
// (and, for explicit config host keys, the request host) to the provider
// upstream. Precedence, first match wins:
//
//  1. exact path override from config `upstreams:`;
//  2. exact host override (case-insensitive, port-aware; a key without a port
//     matches any port);
//  3. longest path-prefix override (matched on path-segment boundaries, so
//     "/v1/chat" matches "/v1/chat/completions" but not "/v1/chatter");
//  4. the built-in provider table;
//  5. ErrUnknownUpstream.
//
// It never guesses: an unrecognised path yields a typed error with the zero
// Upstream, so the caller can answer 502 and record the rejection instead of
// silently misrouting the request to a provider that cannot serve it.
type Resolver struct {
	sink        audit.AuditSink
	exactPaths  map[string]string
	prefixPaths []upstreamPrefix
	hostPorts   map[string]string
	hostNames   map[string]string
}

// upstreamPrefix is one canonical path-prefix override.
type upstreamPrefix struct {
	key  string
	base string
}

// Resolver implements the public extension.Router seam; the assertion keeps
// the contract explicit at compile time.
var _ extension.Router = (*Resolver)(nil)

// NewResolver builds the default router. overrides is the config `upstreams:`
// map (host/path → base URL, already shape-validated by pkg/config); a nil map
// means the built-in table only. sink, when non-nil, receives a metadata-only
// audit row for every unknown-path rejection the resolver turns into an error;
// with a nil sink the rejection remains a typed error and recording is left to
// the caller (the request handler records served traffic).
//
// Override keys are canonicalised once, here: path keys lose their query,
// fragment and trailing slashes, host keys are lower-cased and split into
// port-aware and portless maps. Blank keys and values are ignored defensively;
// pkg/config rejects them before they reach the resolver.
func NewResolver(overrides map[string]string, sink audit.AuditSink) *Resolver {
	r := &Resolver{
		sink:       sink,
		exactPaths: make(map[string]string),
		hostPorts:  make(map[string]string),
		hostNames:  make(map[string]string),
	}
	// Iterate in lexical order so a duplicate canonical key (for example
	// "/v1" and "/v1/") resolves deterministically instead of by map order.
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	prefixes := make(map[string]string, len(keys))
	for _, key := range keys {
		base := overrides[key]
		if strings.TrimSpace(key) == "" || strings.TrimSpace(base) == "" {
			continue
		}
		if strings.HasPrefix(key, "/") {
			path := upstreamCanonicalPath(key)
			prefixes[path] = base
			r.exactPaths[path] = base
			continue
		}
		host, port := upstreamSplitHost(key)
		if host == "" {
			continue
		}
		if port == "" {
			r.hostNames[strings.ToLower(host)] = base
		} else {
			r.hostPorts[strings.ToLower(host)+":"+port] = base
		}
	}
	for path, base := range prefixes {
		r.prefixPaths = append(r.prefixPaths, upstreamPrefix{key: path, base: base})
	}
	// Longest key first; equal lengths fall back to lexical order so the
	// outcome never depends on map iteration.
	sort.SliceStable(r.prefixPaths, func(i, j int) bool {
		a, b := r.prefixPaths[i].key, r.prefixPaths[j].key
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		return a < b
	})
	return r
}

// Name implements extension.Router and identifies the built-in router in logs
// and audit metadata.
func (r *Resolver) Name() string { return DefaultRouterName }

// Pick implements extension.Router by delegating to Resolve. Unlike a plugin
// router it always has an opinion for a known route; a path that matches no
// route is a typed error, never a silent fallback to another provider.
func (r *Resolver) Pick(req *extension.Request) (extension.Upstream, error) {
	return r.Resolve(req)
}

// Resolve maps one request to its upstream using the precedence documented on
// Resolver. A nil request, an empty path and every path that matches no route
// yield an error wrapping ErrUnknownUpstream; when a sink was injected, an
// unknown-path rejection is also recorded as a metadata-only audit row.
func (r *Resolver) Resolve(req *extension.Request) (extension.Upstream, error) {
	if req == nil {
		return extension.Upstream{}, fmt.Errorf("%w: nil request", ErrUnknownUpstream)
	}
	path := upstreamCanonicalPath(req.Path)
	if base, ok := r.exactPaths[path]; ok {
		return extension.Upstream{Name: upstreamNameForPath(path), BaseURL: base}, nil
	}
	if base, ok := r.hostOverride(req.Host); ok {
		return extension.Upstream{Name: upstreamNameForPath(path), BaseURL: base}, nil
	}
	for _, prefix := range r.prefixPaths {
		if upstreamPathKeyMatches(prefix.key, path) {
			return extension.Upstream{Name: upstreamNameForPath(path), BaseURL: prefix.base}, nil
		}
	}
	if up, ok := builtinUpstreams[path]; ok {
		return up, nil
	}
	r.recordUnknownPath(req, path)
	return extension.Upstream{}, upstreamUnknownError(req.Method, path)
}

// upstreamNameForPath reports the provider name an override route should
// carry: the built-in provider name when the path is a known provider route
// (so audit still says anthropic/openai), ProviderCustom otherwise.
func upstreamNameForPath(path string) string {
	if up, ok := builtinUpstreams[path]; ok {
		return up.Name
	}
	return ProviderCustom
}

// upstreamCanonicalPath normalises a request path for matching: the query and
// fragment are dropped and trailing slashes are trimmed ("/" is kept). The
// result is matched case-sensitively and without resolving "." or "..", so
// /V1/MESSAGES and /v1/messages/../chat/completions are unknown paths rather
// than near-miss routes to a provider.
func upstreamCanonicalPath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p != "/" {
		p = strings.TrimRight(p, "/")
	}
	if p == "" {
		p = "/"
	}
	return p
}

// upstreamPathKeyMatches reports whether a canonical config path key applies
// to the canonical request path: exact, or a prefix ending on a path-segment
// boundary. The root key "/" is an explicit catch-all.
func upstreamPathKeyMatches(key, path string) bool {
	if key == path || key == "/" {
		return true
	}
	return strings.HasPrefix(path, key+"/")
}

// upstreamSplitHost splits an HTTP authority into hostname and port. It is
// tolerant by design: a value it cannot split is returned as the hostname
// with an empty port, because the resolver must never reject a request on
// authority shape alone. Bracketed IPv6 literals are unwrapped.
func upstreamSplitHost(authority string) (host, port string) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", ""
	}
	if strings.HasPrefix(authority, "[") {
		if end := strings.Index(authority, "]"); end > 0 {
			host = authority[1:end]
			if rest := authority[end+1:]; strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
		return authority, ""
	}
	// A single colon separates host and port; more colons mean a bare IPv6
	// literal, which is treated as a hostname.
	if host, port, ok := strings.Cut(authority, ":"); ok && !strings.Contains(port, ":") {
		return host, port
	}
	return authority, ""
}

// hostOverride matches the request host against config host keys. An explicit
// port key wins over a portless key; matching is case-insensitive.
func (r *Resolver) hostOverride(reqHost string) (string, bool) {
	host, port := upstreamSplitHost(reqHost)
	if host == "" {
		return "", false
	}
	host = strings.ToLower(host)
	if port != "" {
		if base, ok := r.hostPorts[host+":"+port]; ok {
			return base, true
		}
	}
	base, ok := r.hostNames[host]
	return base, ok
}

// recordUnknownPath writes the metadata-only audit row for a rejected unknown
// path when a sink is injected. The canonical path is recorded, so a query
// string (which can carry sensitive parameters) is never persisted. Audit
// failures are ignored: the typed rejection error is the resolver's contract,
// and a best-effort metadata sink must not replace it (the real store is
// wired in W5.3; docs/13 §6).
func (r *Resolver) recordUnknownPath(req *extension.Request, path string) {
	if r.sink == nil {
		return
	}
	_ = r.sink.Record(audit.Record{
		TS:     time.Now().UnixMilli(),
		Path:   path,
		Method: req.Method,
		Status: http.StatusBadGateway,
	})
}

// upstreamUnknownError builds the typed rejection error. Method and path are
// attacker-controlled, so both are truncated before they are embedded; a
// client must not be able to inflate an error message without bound.
func upstreamUnknownError(method, path string) error {
	if method == "" {
		return fmt.Errorf("%w: %q", ErrUnknownUpstream, upstreamTruncate(path, 120))
	}
	return fmt.Errorf("%w: %s %q", ErrUnknownUpstream, upstreamTruncate(method, 12), upstreamTruncate(path, 120))
}

// upstreamTruncate bounds attacker-controlled text embedded in an error
// message, cutting on rune boundaries and marking the cut.
func upstreamTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	runes := []rune(s)
	if len(runes) > max {
		runes = runes[:max]
	}
	return string(runes) + "..."
}
