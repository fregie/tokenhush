// Package supply implements the frozen supply-chain wire format (D6): the
// update and rules endpoints, the domain-separation tags, the embedded
// trust-root public keys and the document size caps are compile-time
// constants. Fetching and verification are injectable seams, so tests and
// callers can drive a verify-only path without touching the network; the
// bounded fetcher issues a request only when a caller explicitly invokes it.
package supply

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Frozen wire constants. D6 fixes the origin, the paths, the channel query,
// the domain tags, the root key ids and the caps: none is configurable.
const (
	BaseURL      = "https://updates.tokenhush.com"
	ChannelQuery = "?channel=stable"

	UpdateManifestPath    = "/v1/update/manifest"
	UpdateRevocationsPath = "/v1/update/revocations"
	UpdateKeylistPath     = "/v1/update/keylist"
	RulesManifestPath     = "/v1/rules/manifest"
	RulesBundlePath       = "/v1/rules/bundle"
	RulesRevocationsPath  = "/v1/rules/revocations"
)

// Domain-separation tags bind each signature to one document kind.
const (
	DomainUpdateManifest    = "tokenhush-update-manifest-v1"
	DomainUpdateRevocations = "tokenhush-update-revocations-v1"
	DomainUpdateKeylist     = "tokenhush-update-keylist-v1"
	DomainRulesManifest     = "tokenhush-rules-manifest-v1"
	DomainRulesPack         = "tokenhush-rules-pack-v1"
	DomainRulesRevocations  = "tokenhush-rules-revocations-v1"
)

// Embedded trust-root ids, public halves only.
const (
	// KeyRootUpdate is the update trust root. The online update key (upd-*) is
	// fetched through the root-signed key list and is never embedded.
	KeyRootUpdate = "root-2026-09"
	// KeyRulesRoot is the rule trust root.
	KeyRulesRoot = "rules-2026-09"
)

// Document size caps, exact and not tunable.
const (
	// MaxUpdateDocBytes caps manifest, revocations and keylist documents.
	MaxUpdateDocBytes int64 = 128 * 1024
	// MaxRulesDocBytes caps manifest, bundle and revocations documents.
	MaxRulesDocBytes int64 = 256 * 1024
	// MaxArtifactBytes caps the downloaded artifact.
	MaxArtifactBytes int64 = 256 * 1024 * 1024
)

// Typed sentinels so callers can branch with errors.Is.
var (
	ErrBadSignature = errors.New("supply: bad signature")
	ErrWrongKey     = errors.New("supply: wrong key")
	ErrDocTooLarge  = errors.New("supply: document too large")
	ErrFetchTimeout = errors.New("supply: fetch timed out")
)

// Embedded production trust-root public keys, base64 raw-URL encoded. Only the
// public halves ship: this binary verifies but can never sign.
const (
	rootUpdatePublic = "6X3Sz-1c9u5iySAkHMSR4MvxPy812FV7kjrqd-HHZvQ"
	rulesRootPublic  = "IBCvse8BQWafHk0HwLbaq9gycQm_9uDN8-6DHd-Ucvw"
)

// RootKey is an embedded trust-root public key.
type RootKey struct {
	ID     string
	Public string // base64 raw-URL Ed25519 public key
}

// DefaultRootKeys returns the embedded roots, exactly two.
func DefaultRootKeys() []RootKey {
	return []RootKey{
		{ID: KeyRootUpdate, Public: rootUpdatePublic},
		{ID: KeyRulesRoot, Public: rulesRootPublic},
	}
}

// StaticVerifier verifies against the embedded trust roots.
type StaticVerifier struct {
	keys map[string]string
}

// NewStaticVerifier returns a Verifier over DefaultRootKeys.
func NewStaticVerifier() *StaticVerifier {
	roots := DefaultRootKeys()
	keys := make(map[string]string, len(roots))
	for _, root := range roots {
		keys[root.ID] = root.Public
	}
	return &StaticVerifier{keys: keys}
}

// Verify implements Verifier. Key resolution is local and fails closed: any id
// that is not an embedded root is ErrWrongKey.
func (v *StaticVerifier) Verify(domain, keyID string, signingInput, sig []byte) error {
	if domain == "" {
		return fmt.Errorf("%w: empty domain tag", ErrBadSignature)
	}
	public, ok := v.keys[keyID]
	if !ok {
		return fmt.Errorf("%w: %q is not an embedded root", ErrWrongKey, keyID)
	}
	return VerifyEd25519(public, signingInput, sig)
}

// Fetcher retrieves one bounded document body. Implementations must enforce a
// timeout and a body cap, and must not act until the caller invokes Get.
type Fetcher interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

// Verifier checks sig over signingInput under a domain tag and key id.
type Verifier interface {
	Verify(domain string, keyID string, signingInput []byte, sig []byte) error
}

// BoundedHTTPFetcher is the production Fetcher: an http.Client with a timeout
// and an io.LimitReader cap, so a broken or hostile server can never make the
// caller buffer unboundedly. Constructing one performs no I/O.
type BoundedHTTPFetcher struct {
	timeout  time.Duration
	maxBytes int64
	client   *http.Client
}

// NewBoundedHTTPFetcher returns a fetcher that gives up after timeout and
// rejects any body larger than maxBytes.
func NewBoundedHTTPFetcher(timeout time.Duration, maxBytes int64) *BoundedHTTPFetcher {
	return &BoundedHTTPFetcher{
		timeout:  timeout,
		maxBytes: maxBytes,
		client:   &http.Client{Timeout: timeout},
	}
}

// Get performs one bounded GET. It never reads more than maxBytes+1 bytes, so
// the cap is enforced without unbounded buffering.
func (f *BoundedHTTPFetcher) Get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("supply: build request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		if ctx.Err() != nil || isTimeout(err) {
			return nil, fmt.Errorf("%w: %w", ErrFetchTimeout, err)
		}
		return nil, fmt.Errorf("supply: get %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("supply: get %s: unexpected status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("supply: read %s: %w", url, err)
	}
	if int64(len(body)) > f.maxBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes, cap %d", ErrDocTooLarge, url, len(body), f.maxBytes)
	}
	return body, nil
}

// isTimeout reports whether err is a timeout, including http.Client.Timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// DocLimit returns the document size cap for a domain tag. An unknown domain
// gets MaxUpdateDocBytes, the tighter bound: the lookup fails closed.
func DocLimit(domain string) int64 {
	switch domain {
	case DomainRulesManifest, DomainRulesPack, DomainRulesRevocations:
		return MaxRulesDocBytes
	default:
		return MaxUpdateDocBytes
	}
}

// CheckDocSize rejects raw when it exceeds the cap for its domain.
func CheckDocSize(domain string, raw []byte) error {
	if limit := DocLimit(domain); int64(len(raw)) > limit {
		return fmt.Errorf("%w: %s is %d bytes, cap %d", ErrDocTooLarge, domain, len(raw), limit)
	}
	return nil
}

// VerifyEd25519 verifies sig over signingInput under a base64 raw-URL Ed25519
// public key. A truncated or non-base64 key, a truncated signature and a
// mismatching signature each map to a typed sentinel; it never panics.
func VerifyEd25519(publicKey string, signingInput, sig []byte) error {
	pub, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("%w: public key is not base64 raw url: %w", ErrWrongKey, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key is %d bytes, want %d", ErrWrongKey, len(pub), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d", ErrBadSignature, len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, signingInput, sig) {
		return fmt.Errorf("%w: ed25519 verification failed", ErrBadSignature)
	}
	return nil
}

// DecodeSignature decodes a base64 raw-URL signature.
func DecodeSignature(signature string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64 raw url: %w", ErrBadSignature, err)
	}
	return raw, nil
}

// VerifyEd25519B64 is VerifyEd25519 over a base64 raw-URL signature string.
func VerifyEd25519B64(publicKey string, signingInput []byte, signature string) error {
	raw, err := DecodeSignature(signature)
	if err != nil {
		return err
	}
	return VerifyEd25519(publicKey, signingInput, raw)
}

// The two production types satisfy the injectable seams.
var (
	_ Fetcher  = (*BoundedHTTPFetcher)(nil)
	_ Verifier = (*StaticVerifier)(nil)
)
