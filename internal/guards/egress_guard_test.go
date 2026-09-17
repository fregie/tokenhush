// egress_guard_test.go guards Invariant 6: the product has exactly TWO
// vendor-bound egress categories, each naming its switch, and every switch
// short-circuits before any network call.
//
// Consumer todos that extend this guard:
//   - W6.3 owns egress.yaml (the disclosure half below): TestEgressGuardProductTree
//     reads it and runs checkDisclosure once it exists; until then the product
//     test skips with the recorded "egress" guard id.
//   - W4.8 owns pkg/proxy (the no-dial half): when pkg/proxy lands, extend this
//     file to assert every switch named in egress.yaml is consulted before any
//     dial. The no-dial half intentionally has no code yet, so this guard never
//     fails on absence - only on a present-but-forbidden disclosure.
package guards

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/proxy"
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
}

// checkDisclosure parses a simple YAML-ish egress disclosure and reports every
// violation of Invariant 6. It accepts either the list form:
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
// and requires exactly two categories, each naming a distinct, non-empty
// switch. The result is sorted and deduplicated.
func checkDisclosure(text string) []string {
	var lines []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return []string{"disclosure is empty"}
	}

	type category struct {
		name       string
		switchName string
	}
	var (
		categories []category
		current    *category
	)
	flush := func() {
		if current != nil {
			categories = append(categories, *current)
			current = nil
		}
	}
	ensure := func() *category {
		if current == nil {
			current = &category{}
		}
		return current
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "-") {
			flush()
			rest := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			cat := &category{}
			if value, ok := disclosureValue(rest, "name"); ok {
				cat.name = value
			}
			if value, ok := disclosureValue(rest, "category"); ok {
				cat.name = value
			}
			current = cat
			continue
		}
		if value, ok := disclosureValue(line, "switch"); ok {
			ensure().switchName = value
			continue
		}
		if strings.HasSuffix(line, ":") {
			key := strings.TrimSpace(strings.TrimSuffix(line, ":"))
			if key == "" || reservedDisclosureKeys[key] {
				continue
			}
			flush()
			current = &category{name: key}
			continue
		}
	}
	flush()

	var violations []string
	if len(categories) != 2 {
		violations = append(violations, fmt.Sprintf("expected exactly two egress categories, found %d", len(categories)))
	}
	switches := map[string]bool{}
	for _, cat := range categories {
		if cat.switchName == "" {
			name := cat.name
			if name == "" {
				name = "<unnamed>"
			}
			violations = append(violations, fmt.Sprintf("category %s does not name a switch", name))
			continue
		}
		if switches[cat.switchName] {
			violations = append(violations, fmt.Sprintf("duplicate switch %s", cat.switchName))
		}
		switches[cat.switchName] = true
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

// TestEgressGuardProductTree checks the real egress disclosure. It skips (with
// the recorded "egress" guard id) until egress.yaml exists, so every wave stays
// green while the disclosure half is absent. pkg/proxy (the no-dial half) is
// owned by W4.8 and will be asserted here once it lands.
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
