package cli

import (
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/redact"
)

// sessionBackfiller installs the W2.3 exclusion set on a fresh session
// backfiller: the control token and every config-file allowlist literal are
// session-local values a client-bound response must never carry, so a
// placeholder mapped to them is never restored.
func sessionBackfiller(cfg config.Config, token proxy.Token) *redact.Backfiller {
	backfiller := redact.NewBackfiller()
	backfiller.ExcludeFromBackfill([]byte(token.String()))
	for _, literal := range cfg.Allowlist {
		backfiller.ExcludeFromBackfill([]byte(literal))
	}
	return backfiller
}
