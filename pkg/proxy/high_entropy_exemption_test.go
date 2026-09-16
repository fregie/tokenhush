package proxy

// Finding-3 safety proof: the high_entropy structural-identifier exemption must
// not open an exfiltration path. A secret the engine already knows, presented
// inside an exempted run (call_<secret>), is not redacted by the detector, so it
// must still be refused by the C2 outbound re-check — 403, the upstream is never
// dialed and receives zero bytes.

import (
	"net/http"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/redact"
)

// TestHighEntropyStructuralExemptionEgressBypassBlocked is the bypass proof.
// The secret carries no key prefix, so high_entropy is the only detector that
// would flag it; the exemption skips that run, and only the egress re-check
// stands between the plaintext and the upstream.
func TestHighEntropyStructuralExemptionEgressBypassBlocked(t *testing.T) {
	secret := "kR8mQ2vZ9pL4wX7nT1bY6cH3jF5dS0aG"
	engine := w45Engine(t)
	engine.Placeholder(secret, "api_key")

	reg := w45Registry(t, redact.NewHighEntropyDetector())
	policy := extension.NewPolicy(reg, extension.PolicyConfig{})
	pipe := w45Pipeline(t, PipelineConfig{
		Registry: reg,
		Policy:   policy,
		Engine:   engine,
		Tool:     "high-entropy-exemption-egress",
	})

	payload := "call_" + secret
	if !redact.StructuralIdentifierContains([]byte(payload), []byte(secret)) {
		t.Fatalf("fixture error: %q is not inside an exempted structural-identifier run", payload)
	}

	before := pipe.EgressBlocks()
	status, upstream := egressE2E(t, pipe, egressEncodedBody(t, []byte(payload)))
	sent := upstream.received()

	t.Logf("bypass proof status=%d upstream_hits=%d upstream_bytes=%d egress_blocks=%d",
		status, upstream.hits.Load(), len(sent), pipe.EgressBlocks())
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (the exempted known secret must be blocked)", status, http.StatusForbidden)
	}
	if got := upstream.hits.Load(); got != 0 {
		t.Fatalf("upstream dialed %d time(s), want 0", got)
	}
	if len(sent) != 0 {
		t.Fatalf("upstream received %d bytes, want 0", len(sent))
	}
	if got := pipe.EgressBlocks(); got != before+1 {
		t.Fatalf("EgressBlocks = %d, want %d", got, before+1)
	}
}
