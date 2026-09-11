// Package protocol provides protocol-agnostic JSON leaf traversal and SSE
// incremental parsing. It deliberately avoids per-provider intermediate
// representations: every JSON string leaf is inspected in place.
package protocol
