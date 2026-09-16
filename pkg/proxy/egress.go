package proxy

import (
	"bytes"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/redact"
)

// EgressBlockedError reports the W2.3 outbound re-check: after redaction, and
// immediately before the body would be forwarded, the request still carries a
// secret this pipeline's engine has already mapped to a placeholder — under at
// least one encoding covered by redact.NormalizeCandidates. Forwarding it would
// restore the plaintext upstream, so the request must be blocked fail-closed.
//
// Placeholder is the matched secret's placeholder token, exposed for metadata
// (W2.1's membership check returns the placeholder by design). The error never
// carries the plaintext, the matched candidate bytes or any body byte, and
// Error deliberately omits even the placeholder.
type EgressBlockedError struct {
	Placeholder string
}

// Error implements the error interface without embedding content, secret
// material or the placeholder token.
func (e *EgressBlockedError) Error() string {
	return "proxy: outbound body still carries a redacted secret"
}

// EgressBlocks reports how many outbound request bodies the egress re-check
// blocked since the pipeline was built. It mirrors ResponseWalkFailures: the
// count is metadata only (no content), safe to expose (for example on a status
// endpoint), and a nil receiver returns 0.
func (p *Pipeline) EgressBlocks() uint64 {
	if p == nil {
		return 0
	}
	return p.egressBlocks.Load()
}

// egressRecheck runs the W2.3 outbound re-check over body, the bytes the
// request transform is about to return, and returns nil when nothing was found.
// It is the single named entry point W2.5 times and bounds.
//
// The check is: redact.NormalizeCandidates(body) produces every covered decoded
// form of the body, and each candidate is tested with the engine's membership
// test. The first hit that is not exempted by egressSecretsVisibleInBody blocks
// via blockEgress (one counter increment plus one metadata-only event), so a
// hit aborts before the caller can forward anything.
//
// The cheap path is deliberate: an engine that knows no secrets skips the whole
// normalisation pass (KnownSecrets is an allocation-free snapshot for an empty
// engine), and an empty body has nothing to carry.
//
// Boundary (for W6.6; do not overstate it): this function sees only a body the
// walker could parse, because transformRequest returns ErrUnwalkableBody before
// reaching it. A body that fails the walk therefore does not go through the
// egress re-check at all; the HTTP layer decides its fate under W1.3 — a
// JSON-declared body answers 400, an explicitly non-JSON body takes the
// documented byte-identical passthrough. That is the pre-existing non-JSON
// passthrough boundary, narrowed by W1.3, and the re-check adds no coverage for
// it.
func (p *Pipeline) egressRecheck(body []byte) error {
	if p == nil || p.engine == nil || len(body) == 0 {
		return nil
	}
	secrets := p.engine.KnownSecrets()
	if len(secrets) == 0 {
		return nil
	}
	for _, candidate := range redact.NormalizeCandidates(body) {
		ok, placeholder := p.engine.ContainsKnownSecret(candidate)
		if !ok {
			continue
		}
		if egressSecretsVisibleInBody(body, candidate, secrets) {
			continue
		}
		return p.blockEgress(placeholder)
	}
	return nil
}

// egressSecretsVisibleInBody reports whether every known secret candidate
// carries is also present verbatim in the outbound body itself.
//
// This is the allowlist/C7 compatibility exemption, and it is load-bearing: a
// value the user allows through is forwarded unredacted by design, and once a
// redaction has mapped that value the engine knows it forever. Without the
// exemption the re-check would block the allowlisted request itself (and every
// separator-normalised variant of it), contradicting the documented allowlist
// semantics — an allowlist entry could never take effect after the value had
// ever been redacted once. The exemption is deliberately narrow: it applies
// only to a secret already leaving verbatim, i.e. plaintext the value
// detectors (and the allowlist) have already ruled on; the verdict for visible
// plaintext is theirs, not this re-check's. A secret that appears only after a
// covered transformation is never exempt and still blocks, which is the whole
// point of the re-check. Because the body is the post-redaction body, a
// plaintext occurrence can only be present when redaction deliberately left it
// (allowlist suppression, or a recorded detector exclusion); an attacker
// cannot resurrect one to smuggle a transformed copy past the check.
func egressSecretsVisibleInBody(body, candidate []byte, secrets [][]byte) bool {
	for _, secret := range secrets {
		if !bytes.Contains(candidate, secret) {
			continue
		}
		if !bytes.Contains(body, secret) {
			return false
		}
	}
	return true
}

// blockEgress records one blocked egress finding: it increments EgressBlocks and
// emits one metadata-only egress_blocked event whose only populated content
// field is the matched placeholder token, then returns the frozen error type.
func (p *Pipeline) blockEgress(placeholder string) error {
	p.egressBlocks.Add(1)
	p.report(RedactionEvent{
		Action:      RedactionActionEgressBlocked,
		Direction:   RedactionDirectionRequest,
		Phase:       extension.RequestContent.String(),
		Placeholder: placeholder,
	})
	return &EgressBlockedError{Placeholder: placeholder}
}
