package proxy

// controlapi_test.go pins the metadata-only control surface: exactly one route,
// GET /status, carrying the nine proxy-owned keys of the frozen status surface
// and nothing else. There is no allowlist mutation endpoint and no second
// endpoint, every non-GET method is a JSON 405, and the payload can never carry
// the control token.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// controlStatusKeys is the frozen proxy-owned subset of the status surface.
// pack_serial is deliberately absent (internal/cli merges it), and there is no
// self_protection_interceptions and no egress_blocks.
var controlStatusKeys = []string{
	"state",
	"addrs",
	"port",
	"uptime_ms",
	"requests",
	"redactions",
	"content_policy_blocks",
	"rule_blocks",
	"walk_skips",
}

// controlRequest performs one control request.
func controlRequest(t *testing.T, api *ControlAPI, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
	return response
}

// mustDecodeStatus decodes one raw status field, failing on a shape mismatch.
func mustDecodeStatus[T any](t *testing.T, fields map[string]json.RawMessage, key string) T {
	t.Helper()
	raw, ok := fields[key]
	if !ok {
		t.Fatalf("status payload is missing key %q", key)
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("status field %q does not decode as %T (raw %s): %v", key, value, raw, err)
	}
	return value
}

// TestControlAPIStatusSurface: GET /status returns exactly the frozen nine
// keys with their metadata values, and none of the forbidden ones.
func TestControlAPIStatusSurface(t *testing.T) {
	counters := NewCounters()
	counters.countRequest()
	counters.countRequest()
	counters.countRedaction()
	counters.countContentPolicyBlock()
	counters.countRuleBlock()
	counters.countWalkSkip()
	counters.countWalkSkip()

	api := NewControlAPI(ControlConfig{
		State:    "running",
		Addrs:    []string{"127.0.0.1:8787", "[::1]:8787"},
		Port:     8787,
		Started:  time.Now().Add(-1500 * time.Millisecond),
		Counters: counters,
	})
	response := controlRequest(t, api, http.MethodGet, "/status")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /status = %d, want 200 (body %q)", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
		t.Fatalf("decode status payload %q: %v", response.Body.String(), err)
	}
	if len(fields) != len(controlStatusKeys) {
		t.Errorf("status payload carries %d keys, want exactly %d", len(fields), len(controlStatusKeys))
	}
	for _, key := range controlStatusKeys {
		if _, ok := fields[key]; !ok {
			t.Errorf("status payload is missing key %q", key)
		}
	}
	for key := range fields {
		if !slices.Contains(controlStatusKeys, key) {
			t.Errorf("status payload carries unexpected key %q", key)
		}
	}
	for _, forbidden := range []string{"pack_serial", "self_protection_interceptions", "egress_blocks", "token", "control_token"} {
		if _, ok := fields[forbidden]; ok {
			t.Errorf("status payload must not carry %q", forbidden)
		}
	}

	if got := mustDecodeStatus[string](t, fields, "state"); got != "running" {
		t.Errorf("state = %q, want running", got)
	}
	if got := mustDecodeStatus[[]string](t, fields, "addrs"); !slices.Equal(got, []string{"127.0.0.1:8787", "[::1]:8787"}) {
		t.Errorf("addrs = %v, want the configured array", got)
	}
	if got := mustDecodeStatus[int](t, fields, "port"); got != 8787 {
		t.Errorf("port = %d, want 8787", got)
	}
	if got := mustDecodeStatus[int64](t, fields, "uptime_ms"); got < 1400 {
		t.Errorf("uptime_ms = %d, want at least 1400", got)
	}
	if got := mustDecodeStatus[int64](t, fields, "requests"); got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
	if got := mustDecodeStatus[int64](t, fields, "redactions"); got != 1 {
		t.Errorf("redactions = %d, want 1", got)
	}
	if got := mustDecodeStatus[int64](t, fields, "content_policy_blocks"); got != 1 {
		t.Errorf("content_policy_blocks = %d, want 1", got)
	}
	if got := mustDecodeStatus[int64](t, fields, "rule_blocks"); got != 1 {
		t.Errorf("rule_blocks = %d, want 1", got)
	}
	if got := mustDecodeStatus[int64](t, fields, "walk_skips"); got != 2 {
		t.Errorf("walk_skips = %d, want 2", got)
	}

	t.Run("empty addrs stays an array", func(t *testing.T) {
		bare := NewControlAPI(ControlConfig{Counters: NewCounters()})
		response := controlRequest(t, bare, http.MethodGet, "/status")
		if response.Code != http.StatusOK {
			t.Fatalf("GET /status = %d, want 200", response.Code)
		}
		var bareFields map[string]json.RawMessage
		if err := json.Unmarshal(response.Body.Bytes(), &bareFields); err != nil {
			t.Fatalf("decode status payload: %v", err)
		}
		if got := string(bareFields["addrs"]); got != "[]" {
			t.Errorf("addrs = %s, want [] rather than null", got)
		}
		if got := mustDecodeStatus[string](t, bareFields, "state"); got != "running" {
			t.Errorf("default state = %q, want running", got)
		}
		if got := mustDecodeStatus[int64](t, bareFields, "uptime_ms"); got != 0 {
			t.Errorf("uptime_ms with an unset start = %d, want 0", got)
		}
	})
}

// TestControlAPIHasNoMutationRoutes: every non-GET method on any path is a JSON
// 405 naming the method, and no GET beyond /status exists.
func TestControlAPIHasNoMutationRoutes(t *testing.T) {
	api := NewControlAPI(ControlConfig{Counters: NewCounters()})
	for _, path := range []string{"/status", "/allowlist", "/anything"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			t.Run(method+" "+path, func(t *testing.T) {
				response := controlRequest(t, api, method, path)
				if response.Code != http.StatusMethodNotAllowed {
					t.Fatalf("%s %s = %d, want 405 (body %q)", method, path, response.Code, response.Body.String())
				}
				if got := response.Header().Get("Content-Type"); got != "application/json" {
					t.Errorf("405 Content-Type = %q, want application/json", got)
				}
				if got := response.Header().Get("Allow"); got != http.MethodGet {
					t.Errorf("Allow = %q, want GET", got)
				}
				var fields map[string]string
				if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
					t.Fatalf("405 body %q is not a JSON object: %v", response.Body.String(), err)
				}
				if fields["error"] != "method_not_allowed" {
					t.Errorf("405 body error = %q, want method_not_allowed", fields["error"])
				}
				t.Logf("qa: %s %s -> status=%d body=%s", method, path, response.Code, response.Body.String())
			})
		}
	}

	t.Run("only GET /status exists", func(t *testing.T) {
		for _, path := range []string{"/allowlist", "/anything", "/status/extra"} {
			response := controlRequest(t, api, http.MethodGet, path)
			if response.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", path, response.Code)
			}
			var fields map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
				t.Fatalf("404 body %q is not a JSON object: %v", response.Body.String(), err)
			}
			if fields["error"] != "not_found" {
				t.Errorf("GET %s error = %q, want not_found", path, fields["error"])
			}
		}
	})
}

// TestControlAPIStatusCarriesNoToken: the status payload never carries the
// control token, so a status read can never be the session's credential leak.
func TestControlAPIStatusCarriesNoToken(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if token.String() == "" {
		t.Fatal("NewToken returned an empty token; the token check would be vacuous")
	}
	api := NewControlAPI(ControlConfig{
		Addrs:    []string{"127.0.0.1:8787"},
		Port:     8787,
		Started:  time.Now(),
		Counters: NewCounters(),
	})
	response := controlRequest(t, api, http.MethodGet, "/status")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /status = %d, want 200", response.Code)
	}
	if bytes.Contains(response.Body.Bytes(), []byte(token.String())) {
		t.Error("the status payload carries the control token")
	}
	if bytes.Contains(response.Body.Bytes(), []byte("token")) {
		t.Errorf("the status payload mentions a token: %s", response.Body.String())
	}
}
