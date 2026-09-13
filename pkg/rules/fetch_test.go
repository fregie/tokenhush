package rules

import (
	"net/http/httptest"
	"testing"
)

// TestDefaultBaseURLIsExactHost asserts the production rule client has exactly
// one origin, pinned at compile time. There is no lookup that could fall back
// to a redirect, an env value or a sibling host (DNS typosquatting).
func TestDefaultBaseURLIsExactHost(t *testing.T) {
	if DefaultBaseURL != "https://updates.tokenhush.com" {
		t.Fatalf("DefaultBaseURL = %q, want the exact pinned host", DefaultBaseURL)
	}
}

// TestValidateBaseURLRejectsNonHTTPSAndPaths asserts a base URL must be a bare
// https origin: plain http, a path, a query or a fragment are all refused.
func TestValidateBaseURLRejectsNonHTTPSAndPaths(t *testing.T) {
	bad := []string{
		"",
		"http://updates.tokenhush.com",
		"https://updates.tokenhush.com/rules",
		"https://updates.tokenhush.com?x=1",
		"https://updates.tokenhush.com#frag",
	}
	for _, raw := range bad {
		if err := validateBaseURL(raw); err == nil {
			t.Fatalf("validateBaseURL(%q) = nil, want rejection", raw)
		}
	}
	if err := validateBaseURL(DefaultBaseURL); err != nil {
		t.Fatalf("validateBaseURL(DefaultBaseURL) = %v, want nil", err)
	}
}

// TestDefaultRuleClientRefusesHTTPSDowngradeRedirect asserts the default client
// never follows a redirect to a non-https origin.
func TestDefaultRuleClientRefusesHTTPSDowngradeRedirect(t *testing.T) {
	client := defaultRuleClient()
	if client.CheckRedirect == nil {
		t.Fatal("defaultRuleClient must install a redirect policy")
	}
	downgrade := httptest.NewRequest("GET", "http://updates.tokenhush.com/v1/rules/manifest", nil)
	if err := client.CheckRedirect(downgrade, nil); err == nil {
		t.Fatal("a redirect downgrading to http must be refused")
	}
	secure := httptest.NewRequest("GET", "https://updates.tokenhush.com/v1/rules/manifest", nil)
	if err := client.CheckRedirect(secure, nil); err != nil {
		t.Fatalf("an https redirect must be allowed: %v", err)
	}
}
