package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// FuzzParse exercises the token parser with arbitrary bytes. The contract is
// totality: any input either returns an error or a license that re-verifies
// and round-trips; no input may panic.
func FuzzParse(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	v := Verifier{Keys: []Key{{ID: testKeyID, Public: pub}}, Now: func() time.Time { return refNow }}

	f.Add(signedToken(f, priv, nil))
	f.Add([]byte{})
	f.Add([]byte("{"))
	f.Add([]byte("null"))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":2,"key_id":"test-key"}`))
	f.Add([]byte(`{"version":1,"key_id":"test-key","license_id":"x",` +
		`"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z",` +
		`"signature":"AAAA"}`))
	f.Add([]byte{0xff, 0xfe, 0x00, 0x01})
	f.Add(bytes.Repeat([]byte("A"), 4096))
	f.Add(bytes.Repeat([]byte("A"), MaxTokenSize+1))
	f.Add([]byte(`{"version":1,"key_id":"test-key","license_id":"` + strings.Repeat("x", maxFieldLen+1) + `"}`))
	f.Add([]byte(`{"version":1,"key_id":"test-key","license_id":"x","features":[1,2,3]}`))
	f.Add([]byte(`{"version":1,"key_id":"test-key","license_id":"x","issued_at":"not-a-time"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		lic, err := v.Parse(raw)
		if err != nil {
			return
		}
		if lic.Version != Version {
			t.Fatalf("parsed license has version %d, want %d", lic.Version, Version)
		}
		reencoded, err := json.Marshal(lic)
		if err != nil {
			t.Fatalf("parsed license does not marshal: %v", err)
		}
		again, err := v.Parse(reencoded)
		if err != nil {
			t.Fatalf("re-encoded license no longer verifies: %v", err)
		}
		if !bytes.Equal(SigningInput(lic), SigningInput(again)) {
			t.Fatalf("signing input changed across a JSON round-trip")
		}
	})
}
