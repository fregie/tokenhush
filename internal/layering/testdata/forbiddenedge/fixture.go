// Package forbiddenedge is a layering fixture. It is never compiled: the Go
// tool ignores testdata directories, and the layering guard test parses this
// file instead.
//
// Canonical forbidden edge:
//
//	pkg/supply -> pkg/redact
//
// The blank import below spells the target in concrete Go syntax, so the test
// can prove the edge is a real import and not just prose.
package forbiddenedge

import _ "github.com/fregie/tokenhush/pkg/redact"
