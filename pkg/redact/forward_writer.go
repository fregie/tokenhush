package redact

import "bytes"

// ForwardWriter is the sole outbound substitute. It holds ONLY the session
// forward map (secret -> placeholder) inside its engine: it has NO reverse map
// and NO restore/backfill method, so an outbound body can never be expanded
// back into a secret.
type ForwardWriter struct {
	engine *engine
}

// NewForwardWriter returns the outbound writer bound to a session engine. A
// nil engine gets a fresh one so the writer is always usable.
func NewForwardWriter(e *engine) *ForwardWriter {
	if e == nil {
		e = newEngine()
	}
	return &ForwardWriter{engine: e}
}

// Placeholder mints (or reuses) the session-scoped placeholder for secret. It is
// the writer's only exported operation: pinned by
// TestInvariant1NeverBackfillOutbound ("shape: forward-only writer").
func (w *ForwardWriter) Placeholder(secret []byte, kind string) (string, error) {
	return w.engine.placeholder(secret, kind)
}

// redactBody replaces every occurrence of each secret in body with the
// placeholder the writer minted for it. Re-application is idempotent: a
// placeholder already in the body is left verbatim, and nothing in the writer
// can turn a placeholder back into a secret.
func redactBody(w *ForwardWriter, body []byte, secrets [][]byte, kind string) ([]byte, error) {
	out := body
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		p, err := w.Placeholder(secret, kind)
		if err != nil {
			return nil, err
		}
		out = bytes.ReplaceAll(out, secret, []byte(p))
	}
	return out, nil
}
