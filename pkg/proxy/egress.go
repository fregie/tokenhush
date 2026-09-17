package proxy

import (
	"bytes"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
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

// egressRecheckDisabled is a test-only switch: when true, egressRecheck
// returns immediately, so a benchmark can measure the request transform
// without the outbound re-check and have the checked path compared against it
// with benchstat (see BenchmarkEgressRecheck). It is unexported and only ever
// set by tests; production always runs with the default false, which is the
// fully-checked path. It is deliberately not a configuration key: the
// re-check has no user-facing off switch (a config knob that disables it would
// be a default-insecure control).
var egressRecheckDisabled = false

// egressRecheckMaxBodyBytes bounds the body size the outbound re-check will
// normalise. It is exactly redact.NormalizeMaxInputBytes, the normaliser's own
// cap, so the short-circuit coincides with the point past which
// NormalizeCandidates would decline the input anyway: every body the normaliser
// could scan is scanned. It was half the cap (128 KiB), which left a 128–256 KiB
// window where NormalizeCandidates could still have decoded an encoded secret
// but the re-check returned before calling it — a measured leak (a base64 copy
// of a known secret in a 131200-byte body reached the upstream). At the full cap
// the body-size skip and the normaliser's own refusal are the same boundary.
//
// The pass costs tens of milliseconds on realistic text — it saturates the
// normaliser's candidate caps regardless of input size, so raising the bound
// widens the scanned range without adding a new cost class: see
// BenchmarkEgressRecheck and pkg/proxy/bench_egress.sh for the measured cost.
//
// The bound must not be read as "the enabled path is cheap": below the bound,
// with any known secret, the re-check still pays that tens-of-milliseconds
// normalisation pass. bench_egress.sh reports the below-threshold cost as an
// explicitly informational metric (BenchmarkEgressRecheck/CleanSmallBodyWithSecrets),
// never as a bound. This is a documented gap of the same class as the
// normaliser's own cap; W6.6 owns the public write-up of it.
//
// Zero disables the bound (every non-empty body is normalised). That is the
// falsification point bench_egress.sh flips to show the bound is load-bearing;
// production never sets it to zero.
const egressRecheckMaxBodyBytes = redact.NormalizeMaxInputBytes

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
// The cheap paths are deliberate, cheapest first: an empty body has nothing to
// carry, a body above egressRecheckMaxBodyBytes returns before any allocation
// (the documented cost bound), and an engine that knows no secrets returns
// without normalising anything (KnownSecrets is an allocation-free snapshot
// for an empty engine).
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
	if egressRecheckDisabled {
		return nil
	}
	if p == nil || p.engine == nil || len(body) == 0 {
		return nil
	}
	if egressRecheckMaxBodyBytes != 0 && len(body) > egressRecheckMaxBodyBytes {
		return nil
	}
	secrets := p.engine.KnownSecrets()
	if len(secrets) == 0 {
		return nil
	}
	keys, keysOK := egressObjectKeys(body)
	for _, candidate := range redact.NormalizeCandidates(body) {
		ok, placeholder := p.engine.ContainsKnownSecret(candidate)
		if !ok {
			continue
		}
		if egressSecretsVisibleInBody(body, candidate, secrets, keys, keysOK) {
			continue
		}
		return p.blockEgress(placeholder)
	}
	return nil
}

// egressObjectKeys returns the object keys of the outbound body so the re-check
// can tell plaintext the value detectors already ruled on from the same bytes
// used as an object key. The second result is false when the key scan failed;
// callers then treat a visible secret as key-borne (fail-closed), which cannot
// open a path. The scan cannot normally fail here: the request transform walked
// the same document before reaching the re-check.
func egressObjectKeys(body []byte) ([]protocol.KeySpan, bool) {
	keys, err := protocol.WalkKeys(body)
	if err != nil {
		return nil, false
	}
	return keys, true
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
//
// Two visible-plaintext cases are NOT exempt. A known secret sitting inside a
// high_entropy structural-identifier run (redact.StructuralIdentifierContains)
// is a blanket skip, not a positive verdict, so it must not buy a secret a free
// pass. And a known secret used as an object KEY is not rule-on plaintext
// either: keys never enter the value detectors and are never rewritten, so the
// allowlist-compat reasoning does not cover them (see
// secretUsedAsObjectKey). Both checks are fail-closed and narrower than the
// pure-hex exclusion, which remains a recorded limitation.
func egressSecretsVisibleInBody(body, candidate []byte, secrets [][]byte, keys []protocol.KeySpan, keysOK bool) bool {
	for _, secret := range secrets {
		if !bytes.Contains(candidate, secret) {
			continue
		}
		if !bytes.Contains(body, secret) {
			return false
		}
		if redact.StructuralIdentifierContains(body, secret) {
			return false
		}
		if secretUsedAsObjectKey(secret, keys, keysOK) {
			return false
		}
	}
	return true
}

// secretUsedAsObjectKey reports whether secret occurs inside an object key of
// the body. A redacted secret re-sent as a key is exactly the case the key
// guard no longer blocks (high_entropy is out of the frozen key set), so the
// outbound re-check must refuse it here: a key is never rewritten, so nothing
// else stands between it and the upstream. keysOK == false means the key scan
// failed; this fails closed.
func secretUsedAsObjectKey(secret []byte, keys []protocol.KeySpan, keysOK bool) bool {
	if !keysOK {
		return true
	}
	for _, key := range keys {
		if bytes.Contains([]byte(key.Key), secret) {
			return true
		}
	}
	return false
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
