package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/supply"
)

func init() { register("status", statusCommand) }

// statusTimeout bounds the control API call so a hung gateway cannot hang the
// command.
const statusTimeout = 5 * time.Second

// errNotRunning is the sentinel behind the "not running" report: no readable
// session exists, so nothing can be asked. It is deliberately not an error
// message: the frozen behaviour prints "not running" and exits 1.
var errNotRunning = errors.New("tokenhush: the gateway is not running")

// statusPayload is the frozen status surface: exactly these ten keys, all of
// them metadata. pack_serial is merged from the rules cache because
// pkg/proxy is forbidden to import pkg/supply and must not produce it; there
// is no self_protection_interceptions and no egress_blocks.
type statusPayload struct {
	State               string   `json:"state"`
	Addrs               []string `json:"addrs"`
	Port                int      `json:"port"`
	UptimeMS            int64    `json:"uptime_ms"`
	Requests            int64    `json:"requests"`
	Redactions          int64    `json:"redactions"`
	ContentPolicyBlocks int64    `json:"content_policy_blocks"`
	RuleBlocks          int64    `json:"rule_blocks"`
	WalkSkips           int64    `json:"walk_skips"`
	PackSerial          uint64   `json:"pack_serial"`
}

// statusCommand is the CLI entry for `tokenhush status`.
func statusCommand(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&asJSON, "json", false, "emit the frozen status document as JSON")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: status: unexpected argument %q\n", flags.Arg(0))
		return exitUsage
	}
	dataDir, err := platform.DataDir()
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: status: %v\n", err)
		return exitFailure
	}
	payload, err := readStatus(dataDir)
	if errors.Is(err, errNotRunning) {
		fmt.Fprintln(stdout, "not running")
		return exitFailure
	}
	if err != nil {
		fmt.Fprintf(stderr, "tokenhush: status: %v\n", err)
		return exitFailure
	}
	if asJSON {
		fmt.Fprintln(stdout, encodeStatus(payload))
		return exitOK
	}
	printStatus(stdout, payload)
	return exitOK
}

// readStatus reads the session files, calls the running gateway's GET /status
// with the session token and merges pack_serial from the rules cache. Every
// other field comes from the proxy-owned payload.
func readStatus(dataDir string) (statusPayload, error) {
	state, err := proxy.ReadSession(dataDir)
	if errors.Is(err, fs.ErrNotExist) {
		return statusPayload{}, errNotRunning
	}
	if err != nil {
		return statusPayload{}, err
	}
	token, err := os.ReadFile(filepath.Join(dataDir, "control.token"))
	if errors.Is(err, fs.ErrNotExist) {
		return statusPayload{}, errNotRunning
	}
	if err != nil {
		return statusPayload{}, err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", state.Port)
	if len(state.Addrs) > 0 {
		addr = state.Addrs[0]
	}
	request, err := http.NewRequest(http.MethodGet, "http://"+addr+"/status", nil)
	if err != nil {
		return statusPayload{}, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	client := &http.Client{Timeout: statusTimeout}
	response, err := client.Do(request)
	if err != nil {
		return statusPayload{}, fmt.Errorf("call the gateway: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return statusPayload{}, fmt.Errorf("gateway returned %s", response.Status)
	}
	var payload statusPayload
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return statusPayload{}, fmt.Errorf("decode the gateway status: %w", err)
	}
	if serial, err := supply.NewRulesCache(dataDir).ActiveSerial(); err == nil {
		payload.PackSerial = serial
	}
	return payload, nil
}

// encodeStatus renders the exact frozen key set. The default Marshal cannot
// omit or reorder keys: every field is a plain JSON name.
func encodeStatus(payload statusPayload) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return `{"state":"unknown"}`
	}
	return string(encoded)
}

// printStatus writes the human-readable form: one key per line, in the frozen
// order.
func printStatus(stdout io.Writer, payload statusPayload) {
	fmt.Fprintf(stdout, "state: %s\n", payload.State)
	fmt.Fprintf(stdout, "addrs: %s\n", strings.Join(payload.Addrs, ","))
	fmt.Fprintf(stdout, "port: %d\n", payload.Port)
	fmt.Fprintf(stdout, "uptime_ms: %d\n", payload.UptimeMS)
	fmt.Fprintf(stdout, "requests: %d\n", payload.Requests)
	fmt.Fprintf(stdout, "redactions: %d\n", payload.Redactions)
	fmt.Fprintf(stdout, "content_policy_blocks: %d\n", payload.ContentPolicyBlocks)
	fmt.Fprintf(stdout, "rule_blocks: %d\n", payload.RuleBlocks)
	fmt.Fprintf(stdout, "walk_skips: %d\n", payload.WalkSkips)
	fmt.Fprintf(stdout, "pack_serial: %d\n", payload.PackSerial)
}
