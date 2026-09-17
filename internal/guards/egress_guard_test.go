// egress_guard_test.go guards Invariant 6: the product has exactly TWO
// vendor-bound egress categories, each naming its switch, and every switch
// short-circuits before any network call.
//
// The three halves:
//   - disclosure (W6.3): TestEgressGuardProductTree reads egress.yaml, asserts
//     exactly two categories with their switches, that every host is the frozen
//     supply host and that every retention is disclosed;
//   - short-circuit (W6.3): TestEgressGuardSwitchesShortCircuit proves each
//     disclosed switch returns before any request, in the supply layer with a
//     counting fetcher and at the product boundary through the real CLI;
//   - no-dial (W4.8): TestEgressGuardNoVendorDial serves a request through
//     pkg/proxy and asserts exactly the stub upstream was dialled.
//
// The guard never fails on absence - only on a present-but-forbidden
// disclosure.
package guards

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/internal/cli"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/supply"
)

// reservedDisclosureKeys are YAML keys that introduce the disclosure document
// or a category's own fields rather than a category name.
var reservedDisclosureKeys = map[string]bool{
	"egress":      true,
	"categories":  true,
	"disclosure":  true,
	"version":     true,
	"meta":        true,
	"name":        true,
	"category":    true,
	"switch":      true,
	"description": true,
	"enabled":     true,
	"default":     true,
	"host":        true,
	"retention":   true,
	"id":          true,
	"status":      true,
	"title":       true,
	"purpose":     true,
	"fields":      true,
	"updated":     true,
	"items":       true,
}

// egressCategory is one parsed disclosure category: its name, its environment
// switch, the vendor host it would reach and its retention.
type egressCategory struct {
	Name      string
	Switch    string
	Host      string
	Retention string
}

// egressCategories parses a simple YAML-ish egress disclosure and returns its
// categories in document order. It accepts either the list form:
//
//	egress:
//	  - name: provider
//	    switch: TOKENHUSH_EGRESS_PROVIDER
//
// or the map form:
//
//	egress:
//	  provider:
//	    switch: TOKENHUSH_EGRESS_PROVIDER
//
// empty reports a document with no content lines at all.
func egressCategories(text string) (categories []egressCategory, empty bool) {
	var lines []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, true
	}

	var current *egressCategory
	flush := func() {
		if current != nil {
			categories = append(categories, *current)
			current = nil
		}
	}
	ensure := func() *egressCategory {
		if current == nil {
			current = &egressCategory{}
		}
		return current
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "-") {
			flush()
			rest := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			cat := &egressCategory{}
			if value, ok := disclosureValue(rest, "name"); ok {
				cat.Name = value
			}
			if value, ok := disclosureValue(rest, "category"); ok {
				cat.Name = value
			}
			current = cat
			continue
		}
		if value, ok := disclosureValue(line, "switch"); ok {
			ensure().Switch = value
			continue
		}
		if value, ok := disclosureValue(line, "host"); ok {
			ensure().Host = value
			continue
		}
		if value, ok := disclosureValue(line, "retention"); ok {
			ensure().Retention = value
			continue
		}
		if strings.HasSuffix(line, ":") {
			key := strings.TrimSpace(strings.TrimSuffix(line, ":"))
			if key == "" || reservedDisclosureKeys[key] {
				continue
			}
			flush()
			current = &egressCategory{Name: key}
			continue
		}
	}
	flush()
	return categories, false
}

// checkDisclosure parses a simple YAML-ish egress disclosure and reports every
// violation of Invariant 6: it requires exactly two categories, each naming a
// distinct, non-empty switch. The result is sorted and deduplicated.
func checkDisclosure(text string) []string {
	categories, empty := egressCategories(text)
	if empty {
		return []string{"disclosure is empty"}
	}

	var violations []string
	if len(categories) != 2 {
		violations = append(violations, fmt.Sprintf("expected exactly two egress categories, found %d", len(categories)))
	}
	switches := map[string]bool{}
	for _, cat := range categories {
		if cat.Switch == "" {
			name := cat.Name
			if name == "" {
				name = "<unnamed>"
			}
			violations = append(violations, fmt.Sprintf("category %s does not name a switch", name))
			continue
		}
		if switches[cat.Switch] {
			violations = append(violations, fmt.Sprintf("duplicate switch %s", cat.Switch))
		}
		switches[cat.Switch] = true
	}
	sort.Strings(violations)
	return guardsUniqueStrings(violations)
}

// disclosureValue returns the inline value of `key: value` when line starts
// with that key, with any trailing `#` comment and surrounding quotes removed.
func disclosureValue(line, key string) (string, bool) {
	prefix := key + ":"
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if idx := strings.Index(value, " #"); idx >= 0 {
		value = strings.TrimSpace(value[:idx])
	}
	value = strings.Trim(value, `"'`)
	return value, true
}

// egressContains reports whether violations contains want.
func egressContains(violations []string, want string) bool {
	for _, violation := range violations {
		if violation == want {
			return true
		}
	}
	return false
}

// TestEgressGuardRejectsBadDisclosure is the always-running positive control:
// it proves checkDisclosure rejects too many categories, unnamed switches and
// duplicate switches, and accepts a valid two-category disclosure.
func TestEgressGuardRejectsBadDisclosure(t *testing.T) {
	threeCategories := "egress:\n  - name: provider\n    switch: SW_PROVIDER\n  - name: telemetry\n    switch: SW_TELEMETRY\n  - name: analytics\n    switch: SW_ANALYTICS\n"
	if v := checkDisclosure(threeCategories); !egressContains(v, "expected exactly two egress categories, found 3") {
		t.Errorf("three categories: violations = %v, want the count violation", v)
	}

	missingSwitch := "egress:\n  - name: provider\n    switch: SW_PROVIDER\n  - name: telemetry\n    description: preferences only\n"
	if v := checkDisclosure(missingSwitch); !egressContains(v, "category telemetry does not name a switch") {
		t.Errorf("missing switch: violations = %v, want the unnamed-switch violation", v)
	}

	duplicateSwitch := "egress:\n  - name: provider\n    switch: SW_SAME\n  - name: telemetry\n    switch: SW_SAME\n"
	if v := checkDisclosure(duplicateSwitch); !egressContains(v, "duplicate switch SW_SAME") {
		t.Errorf("duplicate switch: violations = %v, want the duplicate-switch violation", v)
	}

	valid := "egress:\n  - name: provider\n    switch: TOKENHUSH_EGRESS_PROVIDER\n  - name: telemetry\n    switch: TOKENHUSH_EGRESS_TELEMETRY\n"
	if v := checkDisclosure(valid); len(v) != 0 {
		t.Errorf("valid disclosure produced violations: %v", v)
	}

	mapForm := "egress:\n  provider:\n    switch: TOKENHUSH_EGRESS_PROVIDER\n  telemetry:\n    switch: TOKENHUSH_EGRESS_TELEMETRY\n"
	if v := checkDisclosure(mapForm); len(v) != 0 {
		t.Errorf("valid map-form disclosure produced violations: %v", v)
	}

	if v := checkDisclosure("   \n# nothing here\n"); !egressContains(v, "disclosure is empty") {
		t.Errorf("empty disclosure: violations = %v, want the emptiness violation", v)
	}
}

// supplyChannelHost is the one vendor host the two disclosed egress categories
// may reach: the frozen supply base URL's host. A disclosure naming any other
// host is a lie about where the product connects.
var supplyChannelHost = strings.TrimPrefix(supply.BaseURL, "https://")

// TestEgressGuardProductTree checks the real egress disclosure: exactly two
// categories, each naming its switch, and every category reaching the frozen
// supply host with a disclosed retention.
func TestEgressGuardProductTree(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "egress.yaml")
	if !guardsPathExists(path) {
		skipGuard(t, "egress", "egress.yaml not written yet (disclosure half completes in W6.3); no-dial half completes in W4.8")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read egress.yaml: %v", err)
	}
	for _, violation := range checkDisclosure(string(data)) {
		t.Error(violation)
	}

	categories, _ := egressCategories(string(data))
	if len(categories) != 2 {
		return
	}
	switches := make([]string, 0, len(categories))
	for _, category := range categories {
		switches = append(switches, category.Switch)
		if category.Host != supplyChannelHost {
			t.Errorf("category %s names host %q, want the frozen supply host %q", category.Name, category.Host, supplyChannelHost)
		}
		if category.Retention == "" {
			t.Errorf("category %s does not disclose its retention", category.Name)
		}
	}
	sort.Strings(switches)
	wantSwitches := []string{"TOKENHUSH_NO_RULE_SYNC", "TOKENHUSH_NO_UPDATE_CHECK"}
	if !slices.Equal(switches, wantSwitches) {
		t.Errorf("disclosed switches = %v, want exactly %v", switches, wantSwitches)
	}
}

// egressGuardFetcher records every fetch attempt and refuses to serve one, so
// a short-circuit can be proven by the call count alone.
type egressGuardFetcher struct{ calls atomic.Int64 }

func (f *egressGuardFetcher) Get(context.Context, string) ([]byte, error) {
	f.calls.Add(1)
	return nil, errors.New("egress guard: fetch blocked")
}

func (f *egressGuardFetcher) invoked() int64 { return f.calls.Load() }

// egressGuardVerifier refuses every signature: a disabled switch must return
// before verification is ever reached.
type egressGuardVerifier struct{}

func (egressGuardVerifier) Verify(string, string, []byte, []byte) error {
	return errors.New("egress guard: verifier must not be reached")
}

// guardsRunCLI runs the real CLI entry point and captures its stdout.
func guardsRunCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writer
	code := cli.Main(args)
	os.Stdout = original
	if err := writer.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close pipe reader: %v", err)
	}
	return code, string(out)
}

// TestEgressGuardSwitchesShortCircuit proves every disclosed switch returns
// before any network call: the rules switch at the supply layer, where a
// counting fetcher sees zero requests, and both switches at the product
// boundary, where `tokenhush rules sync` and `tokenhush update` print that no
// request was sent.
func TestEgressGuardSwitchesShortCircuit(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "egress.yaml"))
	if err != nil {
		t.Fatalf("read egress.yaml: %v", err)
	}
	categories, _ := egressCategories(string(data))
	if len(categories) != 2 {
		t.Fatalf("egress.yaml declares %d categories, want the two the switches belong to", len(categories))
	}

	t.Run("the rules switch short-circuits the signed sync", func(t *testing.T) {
		counted := &egressGuardFetcher{}
		syncer, err := supply.NewRulesSync(supply.RulesSyncConfig{
			DataDir: t.TempDir(), Fetcher: counted, Verifier: egressGuardVerifier{},
			LookupEnv: func(name string) (string, bool) {
				if name == "TOKENHUSH_NO_RULE_SYNC" {
					return "1", true
				}
				return "", false
			},
		})
		if err != nil {
			t.Fatalf("NewRulesSync: %v", err)
		}
		if err := syncer.Sync(context.Background()); err != nil {
			t.Errorf("Sync with TOKENHUSH_NO_RULE_SYNC=1 = %v, want nil", err)
		}
		if got := counted.invoked(); got != 0 {
			t.Errorf("the disabled rules switch made %d request(s), want 0", got)
		}

		live := &egressGuardFetcher{}
		liveSyncer, err := supply.NewRulesSync(supply.RulesSyncConfig{
			DataDir: t.TempDir(), Fetcher: live, Verifier: egressGuardVerifier{},
			LookupEnv: func(string) (string, bool) { return "", false },
		})
		if err != nil {
			t.Fatalf("NewRulesSync(live): %v", err)
		}
		if err := liveSyncer.Sync(context.Background()); err == nil {
			t.Error("the live control expected the blocked fetch to fail")
		}
		if got := live.invoked(); got == 0 {
			t.Error("the live control never consulted the fetcher: the switch probe is vacuous")
		}
	})

	cliDir := filepath.Join(root, "internal", "cli")
	if !guardsPathExists(filepath.Join(cliDir, "rules.go")) || !guardsPathExists(filepath.Join(cliDir, "update.go")) {
		skipGuard(t, "egress", "rules.go and update.go not written yet: the CLI short-circuit half activates with W6.4")
		return
	}
	for _, probe := range []struct {
		name       string
		switchName string
		args       []string
	}{
		{"rules sync", "TOKENHUSH_NO_RULE_SYNC", []string{"rules", "sync"}},
		{"rules sync --check", "TOKENHUSH_NO_RULE_SYNC", []string{"rules", "sync", "--check"}},
		{"update", "TOKENHUSH_NO_UPDATE_CHECK", []string{"update"}},
		{"update --check", "TOKENHUSH_NO_UPDATE_CHECK", []string{"update", "--check"}},
	} {
		t.Run("the CLI short-circuits "+probe.name, func(t *testing.T) {
			t.Setenv(probe.switchName, "1")
			code, stdout := guardsRunCLI(t, probe.args...)
			if code != 0 {
				t.Errorf("tokenhush %s = %d, want 0", probe.name, code)
			}
			if !strings.Contains(stdout, "no request was sent") {
				t.Errorf("tokenhush %s printed %q, want the no-request message", probe.name, stdout)
			}
		})
	}
}

// vendorEgressHosts are the two vendor destinations the product may ever reach,
// and only as the explicitly forwarded upstream of a provider request. A dial
// to either host while a stub upstream is configured is hidden egress.
var vendorEgressHosts = []string{"api.openai.com", "api.anthropic.com"}

// egressDialRecorder records every address pkg/proxy asks the dialer for.
type egressDialRecorder struct {
	mu    sync.Mutex
	addrs []string
}

// record appends one requested dial address.
func (r *egressDialRecorder) record(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addrs = append(r.addrs, addr)
}

// recorded returns a sorted copy of the requested addresses, so the assertion
// can inspect them without racing the dialer.
func (r *egressDialRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.addrs...)
	sort.Strings(out)
	return out
}

// TestEgressGuardNoVendorDial is W4.8's no-dial half of the egress guard: it
// serves a real request through pkg/proxy's data plane against a stub upstream
// and asserts the product dialled exactly that upstream and no vendor host.
func TestEgressGuardNoVendorDial(t *testing.T) {
	var served atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	recorder := &egressDialRecorder{}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		recorder.record(addr)
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	forwarder, err := proxy.NewForwarder("http://upstream.test", nil, proxy.WithDialFunc(dial))
	if err != nil {
		t.Fatalf("proxy.NewForwarder: %v", err)
	}
	plane := proxy.NewDataPlane(forwarder, proxy.DataPlaneConfig{})

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[{"content":"hello"}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	plane.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("served request status = %d, want 200 (body %q)", response.Code, response.Body.String())
	}
	if got := served.Load(); got != 1 {
		t.Fatalf("the stub upstream served %d requests, want exactly 1", got)
	}
	dialed := recorder.recorded()
	if len(dialed) != 1 {
		t.Fatalf("the proxy dialled %v, want exactly one upstream dial", dialed)
	}
	for _, addr := range dialed {
		for _, vendor := range vendorEgressHosts {
			if strings.Contains(addr, vendor) {
				t.Errorf("the proxy dialled vendor host %s (%s): invariant 6 has no vendor egress here", vendor, addr)
			}
		}
	}
	t.Logf("guard egress no-dial: status=%d upstream_requests=1 dialed=%v vendor_dials=0", response.Code, dialed)
}
