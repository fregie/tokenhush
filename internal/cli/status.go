// Status view: `tokenhush status` reports whether the gateway is running plus
// its session counters by reading the daemon's loopback control API with the
// per-session bearer token from <DataDir>/control.token. It also owns the
// shared control-session discovery and loopback client used by other CLI views.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fregie/tokenhush/pkg/gateway"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// controlStatusPath is the control-plane liveness route the CLI reads. It
// mirrors the gateway's unexported registration constant.
const controlStatusPath = "/status"

// Control-client tuning.
const (
	// controlRequestTimeout bounds one loopback control request, so a wedged
	// daemon fails the view instead of hanging the terminal.
	controlRequestTimeout = 5 * time.Second

	// maxControlBody bounds a control response before decoding; a response
	// from our own daemon is metadata-only and small.
	maxControlBody = 4 << 20
)

// Sentinel failures the command layer branches on.
var (
	// errNoControlSession reports that <DataDir>/run.json does not exist: no
	// gateway has been started (or it shut down cleanly and cleaned up).
	errNoControlSession = errors.New("no running gateway session")

	// errControlUnreachable reports that the session files exist but the
	// control API does not answer: the daemon crashed without cleanup.
	errControlUnreachable = errors.New("gateway session not reachable")

	// errControlUnauthorized reports that the daemon rejected our bearer
	// token. The token value is never included.
	errControlUnauthorized = errors.New("control token rejected (HTTP 401)")

	// defaultControlHTTPClient is the loopback client every view uses.
	defaultControlHTTPClient = &http.Client{Timeout: controlRequestTimeout}
)

// controlSession is the metadata-only discovery state of a running daemon:
// the pid/port file plus the per-session bearer token. The token never leaves
// this process except in the Authorization header.
type controlSession struct {
	state gateway.RunState
	token string
}

// loadControlSession reads and validates <dataDir>/run.json and the control
// token beside it. A missing run.json is errNoControlSession; an unreadable,
// malformed or inconsistent state is a hard error (never a silent "running").
func loadControlSession(dataDir string) (controlSession, error) {
	statePath := filepath.Join(dataDir, gateway.RunStateFileName)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return controlSession{}, fmt.Errorf("%w at %s", errNoControlSession, statePath)
		}
		return controlSession{}, fmt.Errorf("read session state: %w", err)
	}
	var state gateway.RunState
	if err := json.Unmarshal(raw, &state); err != nil {
		return controlSession{}, fmt.Errorf("session state is malformed: %w", err)
	}
	if state.Port <= 0 || state.Port > 65535 {
		return controlSession{}, fmt.Errorf("session state has invalid port %d", state.Port)
	}
	token, err := proxy.ReadControlToken(dataDir)
	if err != nil {
		return controlSession{}, fmt.Errorf("read control token: %w", err)
	}
	return controlSession{state: state, token: token}, nil
}

// controlClient talks to one daemon control session over loopback.
type controlClient struct {
	http  *http.Client
	base  string
	addr  string
	token string
}

// newControlClient binds a client to the session's bound port. The CLI always
// dials 127.0.0.1; the daemon also binds [::1] but the two listeners serve the
// same handler, so the v4 spelling is sufficient and never triggers DNS.
func newControlClient(session controlSession, httpClient *http.Client) controlClient {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(session.state.Port))
	return controlClient{
		http:  httpClient,
		base:  "http://" + addr,
		addr:  addr,
		token: session.token,
	}
}

// get performs one authenticated GET and returns the raw response body. Any
// transport failure is errControlUnreachable; 401 is errControlUnauthorized; a
// non-200 is a *controlHTTPError carrying only the API's stable error string.
func (c controlClient) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	endpoint := c.base + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build control request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errControlUnreachable, c.addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBody+1))
	if err != nil {
		return nil, fmt.Errorf("read control response: %w", err)
	}
	if len(body) > maxControlBody {
		return nil, fmt.Errorf("control response exceeds %d bytes", maxControlBody)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errControlUnauthorized
		}
		return nil, &controlHTTPError{status: resp.StatusCode, message: controlErrorMessage(body)}
	}
	return body, nil
}

// controlHTTPError is a non-200 control answer. It keeps the server's stable
// {"error": ...} string (bounded) and never a raw body.
type controlHTTPError struct {
	status  int
	message string
}

// Error renders the HTTP status and, when present, the API's stable message.
func (e *controlHTTPError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("control API returned HTTP %d", e.status)
	}
	return fmt.Sprintf("control API returned HTTP %d: %s", e.status, e.message)
}

// controlErrorMessage extracts the bounded {"error": ...} value from a failed
// response body. A malformed body simply yields "".
func controlErrorMessage(body []byte) string {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	const maxMessage = 200
	if len(payload.Error) > maxMessage {
		return payload.Error[:maxMessage]
	}
	return payload.Error
}

// statusUpView is the snapshot `tokenhush status` renders for a running
// gateway: liveness, pid, bound addresses and session counters, all metadata.
type statusUpView struct {
	Running    bool     `json:"running"`
	PID        int      `json:"pid"`
	State      string   `json:"state"`
	Addrs      []string `json:"addrs"`
	UptimeMS   int64    `json:"uptime_ms"`
	Requests   uint64   `json:"requests"`
	Redactions uint64   `json:"redactions"`
	License    string   `json:"license,omitempty"`
}

// statusDownView is the snapshot rendered when no gateway answers.
type statusDownView struct {
	Running bool   `json:"running"`
	License string `json:"license,omitempty"`
}

// statusCommand is the CLI entry for `tokenhush status` (docs/12 §5). It reads
// the control API's /status via the session token and always renders the W6.7
// read-only license badge line when a valid license is present.
func statusCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "print machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: status: unexpected argument %q\n", fs.Arg(0))
		fmt.Fprintln(stderr, "usage: tokenhush status [--json]")
		return ExitUsage
	}

	// W6.7 seam: keep calling proLicenseBadge() for the badge line instead of
	// duplicating the license path resolution.
	license := proLicenseBadge()

	dataDir, err := platform.DataDir()
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: status: %v\n", err)
		return ExitFailure
	}
	session, err := loadControlSession(dataDir)
	if err != nil {
		if errors.Is(err, errNoControlSession) {
			return renderStatusDown(stdout, stderr, asJSON, license)
		}
		fmt.Fprintf(stderr, "tokenhush: status: %v\n", err)
		return ExitFailure
	}

	client := newControlClient(session, defaultControlHTTPClient)
	ctx, cancel := context.WithTimeout(context.Background(), controlRequestTimeout)
	defer cancel()
	body, err := client.get(ctx, controlStatusPath, nil)
	if err != nil {
		if errors.Is(err, errControlUnreachable) {
			fmt.Fprintf(stderr, "tokenhush: status: %v\n", err)
			return renderStatusDown(stdout, stderr, asJSON, license)
		}
		fmt.Fprintf(stderr, "tokenhush: status: %v\n", err)
		return ExitFailure
	}

	var status proxy.ControlStatus
	if err := json.Unmarshal(body, &status); err != nil {
		fmt.Fprintf(stderr, "tokenhush: status: malformed control response: %v\n", err)
		return ExitFailure
	}
	if status.State == "" {
		status.State = proxy.ControlStateRunning
	}
	view := statusUpView{
		Running:    true,
		PID:        session.state.PID,
		State:      status.State,
		Addrs:      append([]string(nil), status.Addrs...),
		UptimeMS:   status.UptimeMS,
		Requests:   status.Requests,
		Redactions: status.Redactions,
		License:    license,
	}
	if asJSON {
		return writeJSON(stdout, stderr, "status", view)
	}
	writeStatusText(stdout, view)
	return ExitOK
}

// writeStatusText renders the human status view.
func writeStatusText(w io.Writer, view statusUpView) {
	fmt.Fprintln(w, "tokenhush: gateway running")
	fmt.Fprintf(w, "  pid: %d\n", view.PID)
	fmt.Fprintf(w, "  address: %s\n", strings.Join(view.Addrs, ", "))
	uptime := (time.Duration(view.UptimeMS) * time.Millisecond).String()
	fmt.Fprintf(w, "  uptime: %s\n", uptime)
	fmt.Fprintf(w, "  requests: %d\n", view.Requests)
	fmt.Fprintf(w, "  redactions: %d\n", view.Redactions)
	if view.License != "" {
		fmt.Fprintln(w, view.License)
	}
}

// renderStatusDown prints the "not running" view and returns ExitFailure: a
// status probe that cannot see a running gateway is a failure for scripts.
// badge is the display-only Pro line returned by proLicenseBadge ("" when no
// valid license is present); it never branches core behavior.
func renderStatusDown(stdout, stderr io.Writer, asJSON bool, badge string) int {
	if asJSON {
		if code := writeJSON(stdout, stderr, "status", statusDownView{Running: false, License: badge}); code != ExitOK {
			return code
		}
		return ExitFailure
	}
	fmt.Fprintln(stdout, "tokenhush: gateway not running")
	if badge != "" {
		fmt.Fprintln(stdout, badge)
	}
	return ExitFailure
}

// writeJSON is the shared --json writer: indented, newline-terminated, and a
// clean ExitFailure when the destination cannot be written.
func writeJSON(stdout, stderr io.Writer, command string, payload any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		fmt.Fprintf(stderr, "tokenhush: %s: encode json: %v\n", command, err)
		return ExitFailure
	}
	return ExitOK
}
