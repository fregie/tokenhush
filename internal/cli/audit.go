// Audit view: `tokenhush audit` lists the newest metadata-only audit rows
// from the daemon's loopback control API (GET /audit), text or --json. The
// session discovery and authenticated client live in status.go.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// Audit-view tuning.
const (
	// defaultAuditLimit is how many of the newest rows `tokenhush audit`
	// shows when --limit is absent.
	defaultAuditLimit = 20

	// maxAuditScanPages caps the ascending scan recentAudit performs to reach
	// the newest rows; 1024 pages of proxy.MaxControlAuditLimit rows is far
	// beyond a V1 retention window and only guards a pathological store.
	maxAuditScanPages = 1024
)

// auditDownView is the snapshot `tokenhush audit --json` renders when no
// gateway answers.
type auditDownView struct {
	Running bool `json:"running"`
}

// auditCommand is the CLI entry for `tokenhush audit` (docs/12 §5): the newest
// metadata-only audit rows from the control API, text or --json.
func auditCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		asJSON bool
		limit  int
	)
	fs.BoolVar(&asJSON, "json", false, "print machine-readable JSON")
	fs.IntVar(&limit, "limit", defaultAuditLimit, "number of recent rows to show (1..1000)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: audit: unexpected argument %q\n", fs.Arg(0))
		fmt.Fprintln(stderr, "usage: tokenhush audit [--json] [--limit N]")
		return ExitUsage
	}
	if limit < 1 || limit > proxy.MaxControlAuditLimit {
		fmt.Fprintf(stderr, "tokenhush: audit: --limit must be in 1..%d\n", proxy.MaxControlAuditLimit)
		return ExitUsage
	}

	dataDir, err := platform.DataDir()
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: audit: %v\n", err)
		return ExitFailure
	}
	session, err := loadControlSession(dataDir)
	if err != nil {
		if errors.Is(err, errNoControlSession) {
			return renderAuditDown(stdout, stderr, asJSON)
		}
		fmt.Fprintf(stderr, "tokenhush: audit: %v\n", err)
		return ExitFailure
	}

	client := newControlClient(session, defaultControlHTTPClient)
	ctx, cancel := context.WithTimeout(context.Background(), controlRequestTimeout)
	defer cancel()
	records, err := recentAudit(ctx, client.auditPage, limit)
	if err != nil {
		if errors.Is(err, errControlUnreachable) {
			fmt.Fprintf(stderr, "tokenhush: audit: %v\n", err)
			return renderAuditDown(stdout, stderr, asJSON)
		}
		fmt.Fprintf(stderr, "tokenhush: audit: %v\n", err)
		return ExitFailure
	}
	if asJSON {
		if records == nil {
			records = []audit.Record{}
		}
		return writeJSON(stdout, stderr, "audit", records)
	}
	writeAuditText(stdout, records)
	return ExitOK
}

// auditPage fetches one ascending /audit page for the recent-audit scan.
func (c controlClient) auditPage(ctx context.Context, query url.Values) ([]audit.Record, error) {
	body, err := c.get(ctx, controlAuditPath, query)
	if err != nil {
		return nil, err
	}
	var page []audit.Record
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("malformed control response: %w", err)
	}
	return page, nil
}

// controlAuditFetcher fetches one ascending page from the control API. It is
// the seam recentAudit is tested through.
type controlAuditFetcher func(ctx context.Context, query url.Values) ([]audit.Record, error)

// recentAudit returns the newest want rows of the audit timeline in ascending
// (oldest-first) order. The control API only pages ascending, so the scan walks
// forward page by page until a short (final) page; IDs deduplicate rows the
// time-based `since` cursor repeats at a page boundary. The scan is bounded by
// maxAuditScanPages and fails loudly rather than returning a stale window.
func recentAudit(ctx context.Context, fetch controlAuditFetcher, want int) ([]audit.Record, error) {
	if want <= 0 {
		return nil, nil
	}
	var (
		recent []audit.Record
		lastID int64
		since  int64
	)
	for page := 0; page < maxAuditScanPages; page++ {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(proxy.MaxControlAuditLimit))
		if since > 0 {
			query.Set("since", strconv.FormatInt(since, 10))
		}
		records, err := fetch(ctx, query)
		if err != nil {
			return nil, err
		}
		advanced := false
		for _, rec := range records {
			if rec.ID <= lastID {
				// A boundary row the previous page already covered.
				continue
			}
			recent = append(recent, rec)
			lastID = rec.ID
			advanced = true
		}
		if len(recent) > want {
			recent = append([]audit.Record(nil), recent[len(recent)-want:]...)
		}
		if len(records) < proxy.MaxControlAuditLimit {
			return recent, nil
		}
		if !advanced {
			// A full page with no new ID means the API repeats rows; walking
			// further cannot reveal a newer tip.
			return recent, nil
		}
		since = records[len(records)-1].TS
	}
	return nil, fmt.Errorf("audit history exceeds %d pages; refusing to show a stale window", maxAuditScanPages)
}

// writeAuditText renders the metadata-only audit timeline. An empty timeline
// prints one line instead of a bare header.
func writeAuditText(w io.Writer, records []audit.Record) {
	if len(records) == 0 {
		fmt.Fprintln(w, "tokenhush: no audit rows")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tPROVIDER\tMETHOD\tPATH\tSTATUS\tREQ_BYTES\tRESP_BYTES\tREDACTIONS\tDETECTORS")
	for _, rec := range records {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
			time.UnixMilli(rec.TS).UTC().Format(time.RFC3339),
			rec.Provider, rec.Method, rec.Path, rec.Status,
			rec.ReqBytes, rec.RespBytes, rec.Redactions,
			strings.Join(rec.Detectors, ","))
	}
	_ = tw.Flush()
}

// renderAuditDown prints the audit view for an absent gateway.
func renderAuditDown(stdout, stderr io.Writer, asJSON bool) int {
	if asJSON {
		if code := writeJSON(stdout, stderr, "audit", auditDownView{Running: false}); code != ExitOK {
			return code
		}
		return ExitFailure
	}
	fmt.Fprintln(stdout, "tokenhush: gateway not running")
	return ExitFailure
}
