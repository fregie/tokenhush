package proxy

// Finding-3 safety proof: the high_entropy structural exemptions must not open
// an exfiltration path. A secret the engine already knows, presented inside an
// exempted run (a provider id, a data-URI payload, a payload-length base64 run
// or a hash-addressed artifact path), is not redacted by the detector, so it
// must still be refused by the C2 outbound re-check — 403, the upstream is
// never dialed and receives zero bytes.

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/redact"
)

// highEntropyExemptionFixtures lists one known-secret payload per exempted
// shape. loadBearing marks the fixtures where the closure is the only defense:
// the secret sits verbatim inside the exempted run, so the plaintext-visibility
// exemption in egressSecretsVisibleInBody would forward it were
// StructuralIdentifierContains not covering the new classes. The encoded
// fixtures carry the secret only in a covered encoded form, so the decode path
// blocks them independently of the closure.
func highEntropyExemptionFixtures(secret string) []struct {
	name        string
	payload     string
	loadBearing bool
} {
	hex40 := strings.Repeat("ab12", 10)
	filler := strings.Repeat("aB3dE5gH7jK9mN1pQ3sU5wY7", 8)
	return []struct {
		name        string
		payload     string
		loadBearing bool
	}{
		{name: "structural_identifier", payload: "call_" + secret, loadBearing: true},
		{name: "data_uri_raw_run", payload: "data:image/png;base64," + secret, loadBearing: true},
		{name: "payload_length_run", payload: filler + secret + filler, loadBearing: true},
		{name: "hashed_artifact_path_raw_run", payload: "/tmp/build/" + hex40 + "/" + secret + "/out", loadBearing: true},
		{name: "data_uri_base64_of_secret", payload: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(secret))},
		{name: "hashed_artifact_path_hex_of_secret", payload: "/tmp/build/" + hex.EncodeToString([]byte(secret)) + "/out.bin"},
	}
}

// TestHighEntropyStructuralExemptionEgressBypassBlocked is the bypass proof.
// The secret carries no key prefix, so high_entropy is the only detector that
// would flag it; each exemption skips its run, and only the egress re-check
// stands between the plaintext and the upstream.
func TestHighEntropyStructuralExemptionEgressBypassBlocked(t *testing.T) {
	secret := "kR8mQ2vZ9pL4wX7nT1bY6cH3jF5dS0aG"

	for _, tc := range highEntropyExemptionFixtures(secret) {
		t.Run(tc.name, func(t *testing.T) {
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

			if tc.loadBearing && !redact.StructuralIdentifierContains([]byte(tc.payload), []byte(secret)) {
				t.Fatalf("fixture error: %q is not inside an exempted run", tc.payload)
			}

			before := pipe.EgressBlocks()
			status, upstream := egressE2E(t, pipe, egressEncodedBody(t, []byte(tc.payload)))
			sent := upstream.received()

			t.Logf("bypass proof class=%s load_bearing=%v status=%d upstream_hits=%d upstream_bytes=%d egress_blocks=%d",
				tc.name, tc.loadBearing, status, upstream.hits.Load(), len(sent), pipe.EgressBlocks())
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
		})
	}
}
