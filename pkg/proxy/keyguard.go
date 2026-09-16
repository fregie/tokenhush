package proxy

import (
	"fmt"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// keyGuardType reports whether a finding type takes part in the key-position
// fail-closed check. The set is frozen to {api_key, high_entropy, jwt,
// private_key}. credit_card (luhn) and email are deliberately excluded at key
// positions: a 16-digit numeric member name and an email-shaped member name
// are ordinary structure in real provider traffic, and blocking them would be
// a false-positive gate failure.
//
// Mechanism (frozen, do not "improve" by swapping detectors): the decision
// below runs the unmodified extension.Policy.Evaluate over a synthetic key
// document. Evaluate runs every inspector registered for the phase, and its
// internal evaluate is unexported, so the key position cannot be given its own
// detector subset. The subset is therefore applied by post-filtering findings
// by Type: everything outside this set is dropped before the block decision,
// and keys are never rewritten (a key is either "no finding" or a fail-closed
// block). One case is exempt from that filter: an aggregate Block is returned
// before it, because Decision.Findings then carries only the block-forcing
// findings and filtering them by credential type would fail open (see
// keyFindings).
//
// Known limitation (open; W1.5 owns the documentation, not this code): the
// high_entropy detector excludes pure-hex runs at the value domain too
// (hexOnlyPattern in pkg/redact/high_entropy.go), and the same exclusion
// applies at key positions. A pure-hex secret placed in an object key is
// therefore NOT blocked. This is the existing value-domain exclusion, not a
// new key-domain gap, and it is deliberately not closed here:
// TestPipelinePureHexKeysNotBlocked pins it as an explicit, recorded
// limitation.
func keyGuardType(findingType string) bool {
	switch findingType {
	case redact.FindingTypeAPIKey,
		redact.FindingTypeHighEntropy,
		redact.FindingTypeJWT,
		redact.FindingTypePrivateKey:
		return true
	default:
		return false
	}
}

// walkRequestKeys is protocol.WalkKeys. It is a variable so the residual branch
// — Walk succeeded but the key scan failed — can be exercised directly; the
// two walkers share their validation (TestPipelineWalkKeysAgreesWithWalk), so
// that branch is an internal inconsistency. Production always uses
// protocol.WalkKeys; only tests replace it, before any request goroutine runs.
var walkRequestKeys = protocol.WalkKeys

// keyFindings scans the object keys of body and returns the findings that must
// block the request. Two outcomes block: an aggregate Block over the key
// document, and — when the key document did not aggregate to Block — the
// key-position findings whose Type is in the frozen key set. A nil result means
// "no key blocks the request" and the caller keeps the value decision. Keys are
// never rewritten, so a block is the only outcome besides "no finding".
//
// An aggregate Block is returned unchanged, before the type filter, because
// Decision.Findings carries only the findings whose Action equals the aggregate
// action. When a FailClosed inspector fails, the policy emits a block-forcing
// plugin_failure finding and every credential-type finding (all Action Redact)
// is absent from Decision.Findings; filtering that slice by type would drop the
// failure and fail open — the request would be forwarded even though a critical
// inspector had no verdict on its keys. Mirroring the value path, a detector
// failure at the key position must block, and it is not gated on a credential
// match.
//
// The synthetic document reuses contentDocument, giving each key the leaf shape
// the detectors expect (Path, Content, Len) without adding extension API:
// object keys are not protocol.Leaf values and are not marked Encoded (W1.1).
// Every registered inspector runs a second time over the keys — expected, and
// the reason the subset is a post-filter rather than a swapped detector set.
func (p *Pipeline) keyFindings(body []byte) ([]extension.Finding, error) {
	keys, err := walkRequestKeys(body)
	if err != nil {
		// Fail closed, never pass through: a failed key scan could hide a
		// credential-shaped key. WalkKeys mirrors Walk's validation, so after a
		// successful Walk this is an internal inconsistency; it surfaces as a
		// transform error (the forwarder answers 500 with zero upstream bytes),
		// deliberately not as a *BlockedError, because it is not a detector
		// verdict.
		return nil, fmt.Errorf("proxy: scan request keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	leaves := make([]protocol.Leaf, len(keys))
	for i, key := range keys {
		leaves[i] = protocol.Leaf{Path: key.Path, Content: key.Key, Len: len(key.Key)}
	}
	decision, err := p.policy.Evaluate(contentDocument(extension.RequestContent, p.tool, leaves))
	if err != nil {
		return nil, fmt.Errorf("proxy: evaluate request keys: %w", err)
	}
	if decision.Action == extension.Block {
		return decision.Findings, nil
	}
	var findings []extension.Finding
	for _, f := range decision.Findings {
		if keyGuardType(f.Type) {
			findings = append(findings, f)
		}
	}
	return findings, nil
}
