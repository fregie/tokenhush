// Package extension defines the public extension points of Tokenhush.
//
// The open-source core ships no-op defaults only (direct upstream, no
// routing, no cost tracking, no audit export). A private build may register
// implementations; the interfaces are public, the implementations are not.
// The surface stays intentionally minimal until a later revision.
package extension

import (
	"context"
	"net/http"

	"github.com/fregie/tokenhush/pkg/audit"
)

// Request is the protocol-agnostic view of one client request handed to
// extensions. JSON holds the parsed body (nil when absent or not JSON).
type Request struct {
	Method  string
	Host    string
	Path    string
	Headers http.Header
	JSON    any
}

// Response is the protocol-agnostic view of one upstream response.
type Response struct {
	Status  int
	Headers http.Header
	JSON    any
}

// Upstream identifies where a request is forwarded. V1 passes the client's
// credentials through untouched, so no credential material is carried here.
type Upstream struct {
	Name    string
	BaseURL string
}

// Query and Record alias the audit domain types so the AuditExporter seam
// and the pkg/audit store agree on a single shape.
type (
	Query  = audit.Query
	Record = audit.Record
)

// Router decides which upstream a request takes (multi-provider /
// multi-account). Returning the zero Upstream with a nil error means "no
// opinion" and the core falls back to its default direct route.
type Router interface {
	Name() string
	Pick(req *Request) (Upstream, error)
}

// CostSink observes completed requests for token and cost accounting.
type CostSink interface {
	Name() string
	Record(req *Request, resp *Response)
}

// AuditExporter exports audit records (team audit / compliance reports).
type AuditExporter interface {
	Name() string
	Export(ctx context.Context, q Query) ([]Record, error)
}
