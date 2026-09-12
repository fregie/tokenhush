package redact

import (
	"io"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// BackfillFunc returns the inbound-only replacement function for this engine.
// It maps a complete placeholder token back to its original secret and returns
// any unknown token unchanged, so a stale or previous-session placeholder
// reaches the client verbatim instead of being dropped or mis-restored.
//
// Pass it to protocol.NewBackfillWriter; never use it on the outbound path.
// BackfillFunc and Secret are the only readers of the reverse mapping, and
// ApplyPlaceholders — the outbound writer — never consults it (docs/security.md).
func (e *PlaceholderEngine) BackfillFunc() protocol.ReplaceFunc {
	return func(token string) string {
		if secret, ok := e.Secret(token); ok {
			return secret
		}
		return token
	}
}

// NewBackfillWriter returns a protocol.BackfillWriter over dst that restores
// this engine's placeholders across arbitrary chunk boundaries, sizing the
// sliding window from MaxPlaceholderLen.
//
// It is the inbound half of the substitution seam: the proxy uses it only when
// streaming a response back to the client, never when forwarding toward the
// upstream.
func (e *PlaceholderEngine) NewBackfillWriter(dst io.Writer) *protocol.BackfillWriter {
	return protocol.NewBackfillWriter(dst, e.MaxPlaceholderLen(), e.BackfillFunc())
}
