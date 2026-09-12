package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// Placeholder grammar and digest policy (docs/architecture.md). A token is
//
//	__PII_<type>_<digest>__
//
// where <type> is sanitised to [a-z][a-z0-9_]* and <digest> is a hex prefix of
// HMAC-SHA256(type || 0x00 || secret) keyed by a per-session random salt. The
// grammar is JSON-safe and tokenizer-friendly, and the digest floor is 48 bits
// so distinct secrets cannot collide into a wrong backfill.
const (
	// placeholderOpen aliases the protocol package's opening so the streaming
	// backfill window and the engine can never drift apart.
	placeholderOpen  = protocol.PlaceholderPrefix
	placeholderClose = "__"
	placeholderSep   = "_"

	// placeholderMinDigestHex is 48 bits: the floor docs/architecture.md sets against
	// collisions. placeholderDigestStep is how much the digest grows
	// (12 -> 16 -> 20 ...) when two secrets would otherwise share a token.
	placeholderMinDigestHex = 12
	placeholderDigestStep   = 4

	// placeholderMaxDigestHex caps growth at the full SHA-256 output, so the
	// collision loop is bounded at 64 hex characters.
	placeholderMaxDigestHex = sha256.Size * 2

	// placeholderMaxTypeLen bounds the sanitised type; with the digest cap it
	// gives MaxPlaceholderLen its finite value.
	placeholderMaxTypeLen = 32

	// placeholderSaltBytes is the per-session HMAC salt entropy.
	placeholderSaltBytes = 32

	// placeholderEmptyType is the type used when a finding carries none.
	placeholderEmptyType = "generic"
)

// PlaceholderEngine maps secrets to deterministic placeholders and back.
//
// The mapping is in memory only and scoped to one session/process: it is never
// persisted, and a fresh engine (for example after a restart) cannot resolve a
// previous session's placeholders. That degrades safely — the client sees the
// placeholder verbatim instead of a wrong substitution, never a leak.
//
// Within one engine the same (secret,type) always yields the same placeholder,
// and two different secrets map to different placeholders: when a digest would
// collide the digest is lengthened until the token is unique. Secret is the
// reverse direction and must only be used for client-bound (inbound) data.
//
// PlaceholderEngine is safe for concurrent use.
type PlaceholderEngine struct {
	mu            sync.Mutex
	salt          []byte
	bySecret      map[string]string // "type\x00secret" -> placeholder
	byPlaceholder map[string]string // placeholder -> secret
}

// NewPlaceholderEngine returns an engine with a fresh cryptographically random
// per-session salt. The salt lives only in memory and is never persisted.
func NewPlaceholderEngine() (*PlaceholderEngine, error) {
	salt := make([]byte, placeholderSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("redact: generate placeholder salt: %w", err)
	}
	return newPlaceholderEngine(salt), nil
}

// newPlaceholderEngine builds an engine from an explicit salt. Tests use it to
// pin the salt; production always goes through NewPlaceholderEngine.
func newPlaceholderEngine(salt []byte) *PlaceholderEngine {
	return &PlaceholderEngine{
		salt:          append([]byte(nil), salt...),
		bySecret:      make(map[string]string),
		byPlaceholder: make(map[string]string),
	}
}

// Placeholder returns the deterministic placeholder for secret under the given
// finding type, creating the mapping on first use.
//
// The type is sanitised into the token grammar, so arbitrary findings cannot
// break the placeholder shape. A collision with a different secret lengthens
// the digest rather than overwriting the existing mapping.
func (e *PlaceholderEngine) Placeholder(secret, findingType string) string {
	typ := sanitizePlaceholderType(findingType)
	key := typ + "\x00" + secret

	e.mu.Lock()
	defer e.mu.Unlock()

	if p, ok := e.bySecret[key]; ok {
		return p
	}
	for n := placeholderMinDigestHex; n <= placeholderMaxDigestHex; n += placeholderDigestStep {
		p := e.candidate(typ, secret, n)
		existing, taken := e.byPlaceholder[p]
		if taken && existing != secret {
			continue // different secret already owns this prefix: lengthen
		}
		e.bySecret[key] = p
		e.byPlaceholder[p] = secret
		return p
	}
	// Unreachable: separating two secrets by 256 bits of HMAC output would be a
	// full SHA-256 collision. Return the longest token without disturbing the
	// existing mapping so the caller still gets a well-formed placeholder.
	return e.candidate(typ, secret, placeholderMaxDigestHex)
}

// Secret returns the original secret for a complete placeholder token produced
// by this engine, and whether the token is known. Unknown tokens — including a
// previous session's placeholders and any placeholder-shaped non-token — return
// ("", false) so the caller can leave them verbatim.
//
// Secret is the inbound-only direction: callers must never use it while writing
// toward the upstream (docs/security.md).
func (e *PlaceholderEngine) Secret(placeholder string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	secret, ok := e.byPlaceholder[placeholder]
	return secret, ok
}

// MaxPlaceholderLen is the longest token this engine can ever produce. Inbound
// stream backfill (protocol.BackfillWriter) uses it to size the sliding window
// that catches a placeholder split across chunk boundaries.
func (e *PlaceholderEngine) MaxPlaceholderLen() int {
	return len(placeholderOpen) + placeholderMaxTypeLen + len(placeholderSep) +
		placeholderMaxDigestHex + len(placeholderClose)
}

// candidate builds the token for (typ,secret) at the given digest length. The
// caller must hold e.mu, or own the engine (construction).
func (e *PlaceholderEngine) candidate(typ, secret string, digestHexLen int) string {
	mac := hmac.New(sha256.New, e.salt)
	mac.Write([]byte(typ))
	mac.Write([]byte{0})
	mac.Write([]byte(secret))
	digest := hex.EncodeToString(mac.Sum(nil))[:digestHexLen]
	return placeholderOpen + typ + placeholderSep + digest + placeholderClose
}

// sanitizePlaceholderType folds an arbitrary finding type into the placeholder
// grammar [a-z][a-z0-9_]*. Empty types become placeholderEmptyType; ASCII upper
// case is lowered; every other byte becomes '_'; a leading non-letter gets a
// 't' prefix. The result is capped at placeholderMaxTypeLen so MaxPlaceholderLen
// stays finite.
func sanitizePlaceholderType(findingType string) string {
	var b strings.Builder
	b.Grow(min(len(findingType), placeholderMaxTypeLen))
	for i := 0; i < len(findingType) && b.Len() < placeholderMaxTypeLen; i++ {
		c := findingType[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return placeholderEmptyType
	}
	if s[0] < 'a' || s[0] > 'z' {
		s = "t" + s
		if len(s) > placeholderMaxTypeLen {
			s = s[:placeholderMaxTypeLen]
		}
	}
	return s
}

// Redaction is one half-open byte range [Start,End) in a leaf plus the finding
// type that selects the placeholder's type segment.
type Redaction struct {
	Start int
	End   int
	Type  string
}

// ApplyPlaceholders is the outbound forward substitution: it rewrites content
// so every redaction span becomes the deterministic placeholder for that span's
// bytes and type, copying every other byte unchanged. This is the only outbound
// writer and it never consults the reverse mapping, so a placeholder already
// present in content is forwarded verbatim rather than restored (docs/security.md).
//
// Spans may overlap across detectors; overlapping or nested ranges are merged
// into their union (the type of the first range in start/end order is kept).
// Invalid ranges (negative, reversed or out of bounds) are ignored rather than
// panicking. With no applicable span, content is returned unchanged.
func (e *PlaceholderEngine) ApplyPlaceholders(content []byte, redactions []Redaction) []byte {
	spans := normalizeRedactions(redactions, len(content))
	if len(spans) == 0 {
		return content
	}
	out := make([]byte, 0, len(content)+len(spans)*(e.MaxPlaceholderLen()/2))
	prev := 0
	for _, r := range spans {
		out = append(out, content[prev:r.Start]...)
		out = append(out, e.Placeholder(string(content[r.Start:r.End]), r.Type)...)
		prev = r.End
	}
	out = append(out, content[prev:]...)
	return out
}

// normalizeRedactions drops invalid spans, orders the rest by start (longer,
// then lexicographically smaller type first on ties) and merges overlaps into
// their union, so the applier never double-writes a byte.
func normalizeRedactions(redactions []Redaction, contentLen int) []Redaction {
	valid := make([]Redaction, 0, len(redactions))
	for _, r := range redactions {
		if r.Start < 0 || r.Start >= r.End || r.End > contentLen {
			continue
		}
		valid = append(valid, r)
	}
	if len(valid) == 0 {
		return nil
	}
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].Start != valid[j].Start {
			return valid[i].Start < valid[j].Start
		}
		if valid[i].End != valid[j].End {
			return valid[i].End > valid[j].End
		}
		return valid[i].Type < valid[j].Type
	})
	merged := valid[:1]
	for _, r := range valid[1:] {
		last := &merged[len(merged)-1]
		if r.Start < last.End {
			if r.End > last.End {
				last.End = r.End
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}
