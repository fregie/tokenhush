package cli

// counters.go is the assembler's counter glue: the production increments of
// the two counters the status surface froze but nothing used to move. It lives
// beside run.go because run.go is at the 250-pure-LOC guard ceiling; run.go
// wires both functions.

import (
	"net/http"

	"github.com/fregie/tokenhush/pkg/proxy"
)

// countRequests wraps one data-plane handler with the request counter, taken
// before the gate: a local refusal (400, 403, 415, 502) is still a served
// request and must count exactly once. The control surface is registered under
// its own pattern, so a GET /status never traverses this wrapper.
func countRequests(counters *proxy.Counters, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counters.CountRequest()
		next.ServeHTTP(w, r)
	})
}

// redactionTransform adapts the reporting redaction transform to the
// forwarder's BodyTransform seam and counts exactly the substitutions it
// applied. The forwarder invokes it once per forwarded request, so each
// substitution is counted once; a request refused before the transform (a
// local 400/403/415) contributes no redaction.
func (g *gateway) redactionTransform(body []byte) ([]byte, error) {
	out, substitutions, err := g.redactRequest(body)
	if err != nil {
		return nil, err
	}
	g.counters.CountRedactions(substitutions)
	return out, nil
}
