// precise_email_e2e_test.go pins precise email behavior through the REAL run
// gateway: an address whose domain ends at a known public suffix leaves as a
// session placeholder and returns to the client restored, while an address
// with an unlisted or TLD-less suffix is forwarded byte-identically in both
// directions. Every assertion is made on captured bytes -- the recorded
// upstream request and the client-bound response -- never on a log line.
package cli

import (
	"bytes"
	"net/http"
	"testing"
)

// The precise-email fixtures. Each address is assembled from parts at the
// source level, so the built-in suffix table alone decides each case at run
// time and no contiguous address literal sits in this file.
const (
	preciseKnownAddress   = "dana" + "@" + "example.com"
	preciseUnknownSuffix  = "erin" + "@" + "example.zz"
	preciseReservedSuffix = "frank" + "@" + "example.invalid"
	preciseTLDLessAddress = "gina" + "@" + "example"
)

// TestE2EPreciseEmailRoundTrip drives the assembled gateway over a loopback
// echo upstream and asserts both directions of the precise email gate with a
// binary observable: the upstream request either carries an email placeholder
// or it carries the address unchanged, and the client either gets the
// original back or the unchanged address back.
func TestE2EPreciseEmailRoundTrip(t *testing.T) {
	upstream := newE2EUpstream(t)
	base := e2eGateway(t, upstream)

	t.Run("a known public suffix leaves as a placeholder and returns restored", func(t *testing.T) {
		status, got := e2ePost(t, base+e2ePath, e2eBody("my email is "+preciseKnownAddress), nil)
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		if bytes.Contains(sent, []byte(preciseKnownAddress)) {
			t.Errorf("the known-suffix address left the process: %s", sent)
		}
		placeholder := e2ePlaceholder.Find(sent)
		if placeholder == nil {
			t.Fatalf("no placeholder reached the upstream: %s", sent)
		}
		if !bytes.HasPrefix(placeholder, []byte("__PII_email_")) {
			t.Errorf("the upstream placeholder %q is not an email placeholder", placeholder)
		}
		if !bytes.Contains(got, []byte(preciseKnownAddress)) {
			t.Errorf("the original address did not return to the client: %s", got)
		}
		if bytes.Contains(got, []byte("__PII_")) {
			t.Errorf("a placeholder reached the client: %s", got)
		}
	})

	t.Run("an unlisted or TLD-less address is forwarded unchanged", func(t *testing.T) {
		content := "reach " + preciseUnknownSuffix + " or " + preciseReservedSuffix + " or " + preciseTLDLessAddress + " please"
		status, got := e2ePost(t, base+e2ePath, e2eBody(content), nil)
		if status != http.StatusOK {
			t.Fatalf("POST = %d, want 200 (body %s)", status, got)
		}
		sent := upstream.recorded()
		for _, address := range []string{preciseUnknownSuffix, preciseReservedSuffix, preciseTLDLessAddress} {
			if !bytes.Contains(sent, []byte(address)) {
				t.Errorf("the unlisted address %q did not reach the upstream unchanged: %s", address, sent)
			}
			if !bytes.Contains(got, []byte(address)) {
				t.Errorf("the unlisted address %q did not return to the client unchanged: %s", address, got)
			}
		}
		if bytes.Contains(sent, []byte("__PII_")) {
			t.Errorf("the upstream request was altered with a placeholder: %s", sent)
		}
		if bytes.Contains(got, []byte("__PII_")) {
			t.Errorf("the client response was altered with a placeholder: %s", got)
		}
	})
}
