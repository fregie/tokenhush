package gateway

import (
	"bytes"
	"context"
	"net/http"
	"sort"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// RequestStats is the per-request observation snapshot the gateway fills in and
// a WrapDataPlane hook may read through StatsFrom. It is never shared across
// requests. Only metadata is carried: detector ids and byte counts, never the
// matched content.
type RequestStats struct {
	Provider   string
	Path       string
	Method     string
	ReqBytes   int
	Redactions int
	Detectors  []string
	Proxied    bool
}

// requestStatsKey is the context key for the per-request stats. The unexported
// zero-size struct prevents collisions with other packages' keys.
type requestStatsKey struct{}

// StatsFrom returns the current request's RequestStats, or nil outside the
// gateway's stats middleware (for example a direct data-plane test).
func StatsFrom(ctx context.Context) *RequestStats {
	stats, _ := ctx.Value(requestStatsKey{}).(*RequestStats)
	return stats
}

// statsMiddleware allocates one RequestStats per request and puts it in the
// request context before the wrapped handler runs. It sits outside
// WrapDataPlane, so a caller's wrapper sees the stats through StatsFrom.
func statsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats := &RequestStats{Path: r.URL.Path, Method: r.Method}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestStatsKey{}, stats)))
	})
}

// newPlaceholderStats reports how many placeholders the outbound transform
// introduced and the detector types they encode. Only the token grammar is
// read, never the matched bytes, so the result stays metadata-only.
func newPlaceholderStats(in, out []byte) (int, []string) {
	delta := bytes.Count(out, []byte(protocol.PlaceholderPrefix)) -
		bytes.Count(in, []byte(protocol.PlaceholderPrefix))
	if delta < 0 {
		delta = 0
	}
	before := placeholderTypes(in)
	beforeSet := make(map[string]struct{}, len(before))
	for _, t := range before {
		beforeSet[t] = struct{}{}
	}
	var added []string
	for _, t := range placeholderTypes(out) {
		if _, ok := beforeSet[t]; !ok {
			added = append(added, t)
		}
	}
	return delta, added
}

// placeholderTypes returns the distinct detector types encoded in the
// __PII_<type>_<digest>__ tokens of body, sorted for determinism.
func placeholderTypes(body []byte) []string {
	seen := map[string]struct{}{}
	for len(body) > 0 {
		i := bytes.Index(body, []byte(protocol.PlaceholderPrefix))
		if i < 0 {
			break
		}
		rest := body[i+len(protocol.PlaceholderPrefix):]
		j := bytes.Index(rest, []byte("__"))
		if j < 0 {
			break
		}
		token := rest[:j]
		body = rest[j+2:]
		if t, ok := placeholderType(token); ok {
			seen[t] = struct{}{}
		}
	}
	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// placeholderType splits a placeholder body (<type>_<digest>) into its type,
// rejecting anything that does not match the redaction layer's grammar.
func placeholderType(token []byte) (string, bool) {
	i := bytes.LastIndexByte(token, '_')
	if i <= 0 || i == len(token)-1 {
		return "", false
	}
	typ, digest := token[:i], token[i+1:]
	if len(digest) < 8 || !isLowerHex(digest) {
		return "", false
	}
	if typ[0] < 'a' || typ[0] > 'z' {
		return "", false
	}
	for _, c := range typ {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return "", false
		}
	}
	return string(typ), true
}

// isLowerHex reports whether every byte is a lowercase hexadecimal digit.
func isLowerHex(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
