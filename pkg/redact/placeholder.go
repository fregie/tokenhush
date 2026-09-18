// Package redact implements session-scoped PII placeholder substitution for the
// outbound path. It never restores secrets into outbound bodies.
//
// The placeholder grammar is frozen (protected by the README verify recipe):
//
//	__PII_<type>_<digest>__
//
// where <type> is a sanitized, length-capped kind segment and <digest> is a hex
// digest that grows along a fixed ladder until it is unique within the engine.
package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
)

// Geometry of the frozen placeholder grammar.
const (
	placeholderPrefix = "__PII_"
	placeholderSuffix = "__"
	placeholderSep    = "_"

	// maxTypeLen caps the sanitized <type> segment, in bytes.
	maxTypeLen = 16
	// maxDigestLen caps the <digest> segment: 64 hex chars == 32 bytes.
	maxDigestLen = 64
	// minDigestLen is the shortest digest the engine mints.
	minDigestLen = 12
	// saltLen is the per-engine random salt size, in bytes.
	saltLen = 32
)

// maxPlaceholderLen is the worst-case length of any placeholder an engine can
// mint: a capped type segment plus a full-length digest, wrapped in the literal
// affixes.
const maxPlaceholderLen = len(placeholderPrefix) + maxTypeLen + len(placeholderSep) + maxDigestLen + len(placeholderSuffix)

// digestLadder is the deterministic growth sequence for the <digest> segment.
var digestLadder = [...]int{minDigestLen, 16, 24, 32, 48, maxDigestLen}

// errDigestExhausted reports that no length in the digest ladder yielded a
// placeholder unique within the engine session.
var errDigestExhausted = errors.New("redact: digest ladder exhausted")

// digestFunc computes the raw digest bytes for a sanitized (salt, kind, secret)
// triple. The default is HMAC-SHA256 keyed by the engine salt.
type digestFunc func(salt, kind string, secret []byte) []byte

// option configures an engine at construction time.
type option func(*engine)

// withDigest replaces the default digest function. Tests inject digests that
// collide on purpose; production code never does.
func withDigest(fn digestFunc) option {
	return func(e *engine) {
		if fn != nil {
			e.digest = fn
		}
	}
}

// engine mints session-scoped placeholders. It keeps ONLY the forward map
// (secret -> placeholder). It has no reverse map and no restore path.
type engine struct {
	digest  digestFunc
	salt    []byte
	mu      sync.Mutex
	forward map[string]string
}

// newEngine returns an engine holding a fresh 32-byte salt that lives in memory
// only and is never persisted.
func newEngine(opts ...option) *engine {
	e := &engine{
		digest:  defaultDigest,
		salt:    randomSalt(),
		forward: make(map[string]string),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// placeholder returns the placeholder for secret as kind. Within one engine the
// same (kind, secret) always yields the same placeholder, and distinct secrets
// never share one: on collision the digest grows along digestLadder.
func (e *engine) placeholder(secret []byte, kind string) (string, error) {
	clean := sanitizeKind(kind)
	key := clean + "\x00" + string(secret)

	e.mu.Lock()
	defer e.mu.Unlock()

	if p, ok := e.forward[key]; ok {
		return p, nil
	}

	hexDigest := hex.EncodeToString(e.digest(string(e.salt), clean, secret))
	for _, n := range digestLadder {
		if len(hexDigest) < n {
			continue
		}
		candidate := placeholderPrefix + clean + placeholderSep + hexDigest[:n] + placeholderSuffix
		if !e.taken(candidate) {
			e.forward[key] = candidate
			return candidate, nil
		}
	}
	return "", errDigestExhausted
}

// taken reports whether candidate is already assigned to another secret.
func (e *engine) taken(candidate string) bool {
	for _, existing := range e.forward {
		if existing == candidate {
			return true
		}
	}
	return false
}

// sanitizeKind maps kind onto the [a-z0-9] alphabet (every other byte becomes
// '_') and caps it at maxTypeLen.
func sanitizeKind(kind string) string {
	var b strings.Builder
	b.Grow(maxTypeLen)
	for i := 0; i < len(kind) && b.Len() < maxTypeLen; i++ {
		c := kind[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('_')
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// defaultDigest is HMAC-SHA256 over kind || 0x00 || secret, keyed by the engine
// salt.
func defaultDigest(salt, kind string, secret []byte) []byte {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write(secret)
	return mac.Sum(nil)
}

// randomSalt returns saltLen random bytes. crypto/rand.Read cannot fail on
// supported Go versions; a zero salt is the only non-panicking fallback.
func randomSalt() []byte {
	salt := make([]byte, saltLen)
	_, _ = rand.Read(salt)
	return salt
}
