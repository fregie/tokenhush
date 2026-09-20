package filter

// sensitive.go is the per-leaf gate for the Feature-A sensitive_keys block. The
// frozen Rule contract never sees an object key (Inspect receives a leaf value
// only), so the gate lives in the shared evaluation loop instead: a
// request-phase leaf whose immediate member key matches the compiled set is not
// handed to Redact-producing rules, and one whole-value OriginRemotePack
// finding is emitted in their place. A Block-producing rule is still evaluated
// and the blocklist still runs, so the gate can never suppress a block, and an
// allowlisted literal covering the leaf value suppresses the gate finding. The
// matcher is immutable after compile; the gate keeps no state.

import (
	"strings"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// Frozen A-FD2 identity of the gate's finding: one rule id, a whole-value
// span, the custom category (no new category) and high confidence.
const (
	sensitiveKeyRuleID     = "sensitive_key"
	sensitiveKeyConfidence = 1.0
)

// sensitiveMatcher is the compiled sensitive_keys block (A-FD5): the folded key
// set, whether matching is case-sensitive, and a copy of the document's global
// allowlist so the gate respects it on every evaluation path.
type sensitiveMatcher struct {
	keys          map[string]struct{}
	caseSensitive bool
	allowlist     []string
}

// newSensitiveMatcher validates and builds the matcher from a decoded block and
// the document allowlist. A nil payload yields a nil matcher, so a document
// without the block adds no behaviour. The key list is re-validated here so a
// hand-built document cannot skip a bound the decoder enforces.
func newSensitiveMatcher(payload *SensitiveKeysPayload, allowlist []string) (*sensitiveMatcher, error) {
	if payload == nil {
		return nil, nil
	}
	if err := checkSensitiveKeys(payload.Keys); err != nil {
		return nil, err
	}
	keys := make(map[string]struct{}, len(payload.Keys))
	for _, key := range payload.Keys {
		if !payload.CaseSensitive {
			key = strings.ToLower(key)
		}
		keys[key] = struct{}{}
	}
	return &sensitiveMatcher{keys: keys, caseSensitive: payload.CaseSensitive, allowlist: append([]string(nil), allowlist...)}, nil
}

// matches reports whether leaf is an immediate object member whose key is
// configured, folding case unless the block asked for case-sensitive matching.
// A non-member leaf (the document root, an array element, a hand-built or
// plugin leaf) never matches, so `{"0":"x"}` matches where `["x"]` does not. A
// nil matcher never matches.
func (m *sensitiveMatcher) matches(leaf protocol.Leaf) bool {
	if m == nil || !leaf.Member {
		return false
	}
	key := leaf.Key
	if !m.caseSensitive {
		key = strings.ToLower(key)
	}
	_, ok := m.keys[key]
	return ok
}

// allows reports whether an allowlisted literal covers the whole leaf value.
// The gate's finding spans [0, len(value)), so only a literal that covers the
// entire value suppresses it. A nil matcher allows nothing.
func (m *sensitiveMatcher) allows(value []byte) bool {
	if m == nil {
		return false
	}
	for _, literal := range m.allowlist {
		if insideOccurrence(value, []byte(literal), 0, len(value)) {
			return true
		}
	}
	return false
}

// sensitiveKeyFinding builds the frozen A-FD2 whole-value finding for one gated
// leaf.
func sensitiveKeyFinding(index int, value []byte) Finding {
	return Finding{
		RuleID: sensitiveKeyRuleID, Category: CategoryCustom, Action: ActionRedact,
		LeafIndex: index, Start: 0, End: len(value), Confidence: sensitiveKeyConfidence,
	}
}
