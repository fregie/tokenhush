package update

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// fetchRevocations downloads and verifies the independent kill-switch
// document. It is fetched before the manifest so a stale or forged revocation
// document fails closed without trusting the manifest.
func (a *Applier) fetchRevocations(ctx context.Context) (RevocationList, error) {
	raw, err := a.get(ctx, a.revocationsURL())
	if err != nil {
		return RevocationList{}, fmt.Errorf("update: fetch revocations: %w", err)
	}
	rev, err := a.reverifyRevocations(raw)
	if err != nil {
		return RevocationList{}, fmt.Errorf("update: revocations rejected: %w", err)
	}
	return rev, nil
}

// fetchManifest downloads and verifies the signed manifest using the reused B4
// verifier (signature, freshness, anti-rollback, downgrade). replayed reports
// that the manifest was an identical re-fetch of the last accepted serial.
func (a *Applier) fetchManifest(ctx context.Context) (Manifest, bool, error) {
	raw, err := a.get(ctx, a.manifestURL())
	if err != nil {
		return Manifest{}, false, fmt.Errorf("update: fetch manifest: %w", err)
	}
	m, replayed, err := a.reverifyManifest(raw)
	if err != nil {
		return Manifest{}, false, fmt.Errorf("update: manifest rejected: %w", err)
	}
	return m, replayed, nil
}

// reverifyManifest runs the B4 verifier and reports an identical re-fetch.
// ErrReplayed is returned only after signature, freshness and downgrade all
// passed, so a serial equal to the persisted high-water is the authentic
// manifest already accepted (replayed=true); a lower serial is a genuine
// rollback and stays rejected.
func (a *Applier) reverifyManifest(raw []byte) (Manifest, bool, error) {
	m, err := a.verifier.VerifyManifest(raw)
	if err == nil {
		return m, false, nil
	}
	if !errors.Is(err, ErrReplayed) {
		return Manifest{}, false, err
	}
	var cand Manifest
	if uerr := json.Unmarshal(raw, &cand); uerr != nil {
		return Manifest{}, false, ErrMalformed
	}
	if !a.atHighWater(KindManifest, cand.Serial) {
		return Manifest{}, false, err
	}
	return cand, true, nil
}

// reverifyRevocations is the revocation-document equivalent of
// reverifyManifest: an identical re-fetch is reused, a rollback is rejected.
func (a *Applier) reverifyRevocations(raw []byte) (RevocationList, error) {
	rev, err := a.verifier.VerifyRevocations(raw)
	if err == nil {
		return rev, nil
	}
	if !errors.Is(err, ErrReplayed) {
		return RevocationList{}, err
	}
	var cand RevocationList
	if uerr := json.Unmarshal(raw, &cand); uerr != nil {
		return RevocationList{}, ErrMalformed
	}
	if !a.atHighWater(KindRevocations, cand.Serial) {
		return RevocationList{}, err
	}
	return cand, nil
}

// atHighWater reports whether serial is exactly the persisted high-water mark,
// i.e. an identical re-fetch rather than a rollback.
func (a *Applier) atHighWater(kind string, serial uint64) bool {
	highest, ok, err := a.verifier.store().Highest(kind)
	return err == nil && ok && serial == highest
}

// get performs a bounded JSON GET against the update service.
func (a *Applier) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: got %d", ErrHTTPStatus, resp.StatusCode)
	}
	return readBounded(resp.Body, MaxDocumentSize)
}

// download streams the artifact into the staging path while hashing it, so the
// sha256 is verified without a second read. A mismatch removes the candidate
// and leaves the live binary alone.
func (a *Applier) download(ctx context.Context, m Manifest, l layout) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("update: download artifact: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: artifact got %d", ErrHTTPStatus, resp.StatusCode)
	}
	f, err := os.OpenFile(l.new, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, a.maxSize+1))
	if err != nil {
		_ = f.Close()
		_ = os.Remove(l.new)
		return fmt.Errorf("update: download artifact: %w", err)
	}
	if n > a.maxSize {
		_ = f.Close()
		_ = os.Remove(l.new)
		return ErrArtifactTooLarge
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(l.new)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(l.new)
		return err
	}
	if !hashMatches(m.SHA256, h.Sum(nil)) {
		_ = os.Remove(l.new)
		return ErrHashMismatch
	}
	return nil
}

// hashMatches compares the signed hex digest to the downloaded digest.
func hashMatches(expectedHex string, got []byte) bool {
	want, err := hex.DecodeString(expectedHex)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(want, got) == 1
}

// readBounded reads at most limit bytes, rejecting anything larger.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrTooLarge
	}
	return raw, nil
}

// validateBaseURL requires a bare absolute https origin.
func validateBaseURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("%w: base URL is required", ErrMissingConfig)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("update: base URL must be an absolute https URL")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("update: base URL must not contain a path, query or fragment")
	}
	return nil
}

// defaultApplyClient downloads large artifacts with a bounded timeout and
// refuses any redirect that would downgrade to plain http.
func defaultApplyClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("update: too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("update: refusing non-https redirect")
			}
			return nil
		},
	}
}

// manifestURL builds the channel manifest URL.
func (a *Applier) manifestURL() string {
	return a.baseURL + ManifestPath + "?channel=" + url.QueryEscape(a.channel)
}

// revocationsURL builds the independent revocation document URL.
func (a *Applier) revocationsURL() string {
	return a.baseURL + RevocationsPath + "?channel=" + url.QueryEscape(a.channel)
}
