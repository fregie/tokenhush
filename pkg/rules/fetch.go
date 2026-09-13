package rules

// HTTP plumbing for the rule client: bounded GETs against the Cloudflare rule
// service and the constant-time bundle hash check against the signed manifest.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// manifestURL builds the channel rule-manifest URL.
func (c *Client) manifestURL() string {
	return strings.TrimRight(c.BaseURL, "/") + ManifestPath + "?channel=" + url.QueryEscape(c.Channel)
}

// bundleURL builds the channel rule-bundle URL.
func (c *Client) bundleURL() string {
	return strings.TrimRight(c.BaseURL, "/") + BundlePath + "?channel=" + url.QueryEscape(c.Channel)
}

// revocationsURL builds the independent rule kill-switch URL.
func (c *Client) revocationsURL() string {
	return strings.TrimRight(c.BaseURL, "/") + RevocationsPath + "?channel=" + url.QueryEscape(c.Channel)
}

// get performs a bounded JSON GET against the rule service.
func (c *Client) get(ctx context.Context, rawURL string) ([]byte, error) {
	client := c.HTTPClient
	if client == nil {
		client = defaultRuleClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: got %d", ErrHTTPStatus, resp.StatusCode)
	}
	return readBounded(resp.Body, MaxPackSize)
}

// readBounded reads at most limit bytes, rejecting anything larger.
func readBounded(r io.Reader, limit int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, ErrPackTooLarge
	}
	return raw, nil
}

// hashMatches compares the signed hex digest to the raw bundle bytes.
func hashMatches(expectedHex string, bundle []byte) bool {
	want, err := hex.DecodeString(expectedHex)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	sum := sha256.Sum256(bundle)
	return subtle.ConstantTimeCompare(want, sum[:]) == 1
}

// validateBaseURL requires a bare absolute https origin.
func validateBaseURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("%w: base URL is required", ErrClientConfig)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("rules: base URL must be an absolute https URL")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("rules: base URL must not contain a path, query or fragment")
	}
	return nil
}

// defaultRuleClient refuses any redirect that would downgrade to plain http.
func defaultRuleClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("rules: too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("rules: refusing non-https redirect")
			}
			return nil
		},
	}
}
