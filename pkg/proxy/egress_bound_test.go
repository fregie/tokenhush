package proxy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fregie/tokenhush/pkg/redact"
)

// TestEgressRecheckBodyBound pins the W2.5 cost bound: the re-check normalises
// a body at or below egressRecheckMaxBodyBytes (so an encoded copy of a known
// secret is blocked there), and it deliberately skips a larger body, which is
// the same class of documented gap as redact.NormalizeMaxInputBytes. The
// oversized case is asserted as a skip, not as a pass-through accident: it is
// the known limitation bench_egress.sh's falsification gate makes visible.
func TestEgressRecheckBodyBound(t *testing.T) {
	secret := egressSecret()
	encoded := []byte(hex.EncodeToString([]byte(secret)))
	base := encodedSecretBody(t, encoded)
	if len(base) > egressRecheckMaxBodyBytes {
		t.Fatalf("the fixture is %d bytes, want at most the %d-byte bound",
			len(base), egressRecheckMaxBodyBytes)
	}

	cases := []struct {
		name      string
		size      int
		wantBlock bool
	}{
		{"below_the_bound_is_checked", len(base), true},
		// 131200 bytes is the measured leak: the encoded secret reached the
		// upstream when the bound was half the normaliser's cap.
		{"above_the_old_half_bound_is_checked", 131200, true},
		{"at_the_bound_is_checked", egressRecheckMaxBodyBytes, true},
		{"above_the_bound_is_skipped", egressRecheckMaxBodyBytes + 1, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := w45Engine(t)
			engine.Placeholder(secret, "api_key")
			pipe := w45Pipeline(t, PipelineConfig{
				Registry: w45Registry(t, redact.NewPrefixDetector()),
				Engine:   engine,
			})

			body := padBodyTo(t, base, tc.size)
			out, err := pipe.RequestTransform()(body)

			if tc.wantBlock {
				var egressErr *EgressBlockedError
				if !errors.As(err, &egressErr) {
					t.Fatalf("err = %v, want *EgressBlockedError", err)
				}
				if out != nil {
					t.Errorf("blocked transform returned a %d-byte body, want none", len(out))
				}
				if got := pipe.EgressBlocks(); got != 1 {
					t.Errorf("EgressBlocks = %d, want 1", got)
				}
				t.Logf("size=%d bound=%d status=blocked", len(body), egressRecheckMaxBodyBytes)
				return
			}

			if err != nil {
				t.Fatalf("oversized body: %v", err)
			}
			if !bytes.Equal(out, body) {
				t.Errorf("oversized body changed: %d bytes in, %d out", len(body), len(out))
			}
			if got := pipe.EgressBlocks(); got != 0 {
				t.Errorf("EgressBlocks = %d, want 0 for a body above the bound", got)
			}
			t.Logf("documented gap: size=%d exceeds bound=%d, so the re-check skipped this body",
				len(body), egressRecheckMaxBodyBytes)
		})
	}
}

// TestEgressRecheckBodyBoundValue pins the bound's value and its place above
// the realistic-body floor and at the normaliser's own cap: a smaller bound
// would silently drop the re-check for realistic traffic, and a larger one
// could never fire.
func TestEgressRecheckBodyBoundValue(t *testing.T) {
	if egressRecheckMaxBodyBytes <= 0 {
		t.Fatalf("bound = %d, want a positive bound", egressRecheckMaxBodyBytes)
	}
	if egressRecheckMaxBodyBytes > redact.NormalizeMaxInputBytes {
		t.Fatalf("bound = %d exceeds the normaliser's cap %d: the short-circuit could never fire",
			egressRecheckMaxBodyBytes, redact.NormalizeMaxInputBytes)
	}
	if want := redact.NormalizeMaxInputBytes; egressRecheckMaxBodyBytes != want {
		t.Fatalf("bound = %d, want %d (the normaliser's own cap)", egressRecheckMaxBodyBytes, want)
	}
	const realisticBodyFloorBytes = 64 << 10
	if egressRecheckMaxBodyBytes < realisticBodyFloorBytes {
		t.Fatalf("bound = %d is below the %d-byte realistic-request floor: realistic traffic would silently skip the re-check",
			egressRecheckMaxBodyBytes, realisticBodyFloorBytes)
	}
}

// encodedSecretBody wraps an encoded secret in a valid provider-shaped body.
func encodedSecretBody(t *testing.T, encoded []byte) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": string(encoded)},
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return body
}

// padBodyTo right-pads a JSON body with spaces (legal whitespace after the
// top-level value) until it is exactly size bytes long.
func padBodyTo(t *testing.T, body []byte, size int) []byte {
	t.Helper()
	if len(body) > size {
		t.Fatalf("body is %d bytes, want at most %d", len(body), size)
	}
	padded := make([]byte, size)
	copy(padded, body)
	for i := len(body); i < size; i++ {
		padded[i] = ' '
	}
	return padded
}
