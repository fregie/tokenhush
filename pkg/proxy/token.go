package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ControlTokenFileName is the per-session control-API token file below the
// platform data directory: <DataDir>/control.token (docs/13 §3.4). DataDir is
// resolved by the caller via pkg/platform.DataDir().
const ControlTokenFileName = "control.token"

// tokenBytes is the entropy of a generated control token. 32 bytes = 256 bits,
// comfortably above the 128-bit minimum; the token is Raw URL-safe base64 so
// it can travel in an Authorization header and a URL fragment unescaped.
const tokenBytes = 32

// ErrNoControlToken reports that <dataDir>/control.token is missing or empty:
// no control session is running. Callers must treat it as "no token", never
// invent one.
var ErrNoControlToken = errors.New("proxy: control token not found")

// ErrEmptyControlToken reports an attempt to persist an empty token. The
// guard would reject every request with it, so writing is refused instead.
var ErrEmptyControlToken = errors.New("proxy: control token must be non-empty")

// GenerateControlToken returns a fresh cryptographically random per-session
// token: tokenBytes from crypto/rand, Raw URL-safe base64 encoded.
func GenerateControlToken() (string, error) {
	var buf [tokenBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("proxy: generate control token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// NewControlToken generates a per-session token and persists it to
// <dataDir>/control.token. run calls it once at startup; every run overwrites
// the previous token, so a stale CLI token or browser handshake stops working
// the moment a new session starts. The token and the file path are returned so
// the caller can print the handshake URL; this package never logs the token.
func NewControlToken(dataDir string) (token, path string, err error) {
	token, err = GenerateControlToken()
	if err != nil {
		return "", "", err
	}
	path, err = WriteControlToken(dataDir, token)
	if err != nil {
		return "", "", err
	}
	return token, path, nil
}

// WriteControlToken persists token to <dataDir>/control.token and returns the
// file path. The data directory is created if needed. The file is created 0600
// on POSIX; on Windows POSIX mode bits do not apply and the file inherits the
// per-user %LOCALAPPDATA% ACL instead. The write is atomic (same-directory temp
// file + rename), so a concurrent reader never observes a half-written token
// and a pre-existing file is replaced, not truncated in place.
func WriteControlToken(dataDir, token string) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", ErrEmptyControlToken
	}
	dir := strings.TrimSpace(dataDir)
	if dir == "" {
		return "", errors.New("proxy: control token data directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("proxy: create data dir: %w", err)
	}
	path := filepath.Join(dir, ControlTokenFileName)

	tmp, err := os.CreateTemp(dir, ".control-token-*")
	if err != nil {
		return "", fmt.Errorf("proxy: create control token file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("proxy: write control token: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("proxy: write control token: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("proxy: persist control token: %w", err)
	}
	return path, nil
}

// ReadControlToken reads the current per-session token from
// <dataDir>/control.token, ignoring surrounding whitespace. A missing or empty
// file yields an error matching ErrNoControlToken. The token itself is never
// included in error text.
func ReadControlToken(dataDir string) (string, error) {
	dir := strings.TrimSpace(dataDir)
	if dir == "" {
		return "", errors.New("proxy: control token data directory is empty")
	}
	path := filepath.Join(dir, ControlTokenFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrNoControlToken, path)
		}
		return "", fmt.Errorf("proxy: read control token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%w: %s", ErrNoControlToken, path)
	}
	return token, nil
}

// ControlHandshakeURL builds the minimal one-time browser handshake URL for
// the control UI (docs/13 §3.4):
//
//	http://127.0.0.1:<port>/#token=<token>
//
// The token travels in the URL fragment, which browsers never transmit to the
// server (not in the request line, not in Referer), so it stays out of access
// logs. The control UI (full version W9.1) reads location.hash on first load,
// stores the token for its same-origin API calls, and immediately clears the
// fragment with history.replaceState. The handshake is per-session: the token
// is regenerated on every run. An unusable port or token yields "".
func ControlHandshakeURL(port int, token string) string {
	if port <= 0 || port > 65535 || token == "" {
		return ""
	}
	u := url.URL{
		Scheme:   "http",
		Host:     net.JoinHostPort(loopbackV4, strconv.Itoa(port)),
		Path:     "/",
		Fragment: "token=" + token,
	}
	return u.String()
}
