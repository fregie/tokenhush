package proxy

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// TokenBytes is the entropy of a control token. 32 random bytes make guessing
// hopeless, and the hex rendering keeps the token safe in any text channel.
const TokenBytes = 32

// ErrControlUnauthorized is returned when a control request carries no bearer
// credential or the wrong one.
var ErrControlUnauthorized = errors.New("proxy: control token is missing or wrong")

// hexAlphabet is the lowercase hex alphabet used to render tokens. The
// encoding is hand-rolled so the package imports no decode/encode package.
const hexAlphabet = "0123456789abcdef"

// Token is the per-session bearer credential for control requests. The zero
// value never matches.
type Token struct {
	value string
}

// NewToken mints a fresh token from crypto/rand.
func NewToken() (Token, error) {
	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, fmt.Errorf("proxy: read %d random bytes: %w", TokenBytes, err)
	}
	return Token{value: encodeHex(raw)}, nil
}

// String returns the wire form of the token.
func (t Token) String() string { return t.value }

// IsZero reports whether the token was never minted.
func (t Token) IsZero() bool { return t.value == "" }

// Matches compares candidate against the token in constant time, so a wrong
// credential leaks nothing through timing. The early length check only
// reveals the token's fixed, public length.
func (t Token) Matches(candidate string) bool {
	if t.value == "" || len(candidate) != len(t.value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(t.value)) == 1
}

// AuthorizeControl accepts exactly one Authorization header shape: the Bearer
// scheme followed by a credential that Matches the token.
func (t Token) AuthorizeControl(authorization string) error {
	credential, ok := bearerCredential(authorization)
	if !ok {
		return fmt.Errorf("%w: no bearer credential", ErrControlUnauthorized)
	}
	if !t.Matches(credential) {
		return fmt.Errorf("%w: bearer credential rejected", ErrControlUnauthorized)
	}
	return nil
}

// ControlGuard wraps a control handler with the token check: a request without
// a bearer credential is refused with 401 and one with the wrong credential
// with 403; the wrapped handler only runs for the exact token.
func ControlGuard(t Token, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential, ok := bearerCredential(r.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tokenhush-control"`)
			http.Error(w, "control token required", http.StatusUnauthorized)
			return
		}
		if !t.Matches(credential) {
			http.Error(w, "control token rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerCredential extracts the credential of a Bearer Authorization header.
func bearerCredential(authorization string) (string, bool) {
	scheme, credential, ok := strings.Cut(strings.TrimSpace(authorization), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return "", false
	}
	return credential, true
}

// encodeHex renders src as lowercase hex without pulling in encoding/hex.
func encodeHex(src []byte) string {
	encoded := make([]byte, len(src)*2)
	for i, b := range src {
		encoded[2*i] = hexAlphabet[b>>4]
		encoded[2*i+1] = hexAlphabet[b&0x0f]
	}
	return string(encoded)
}
