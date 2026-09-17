package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/redact"
)

// Test keys are assembled at runtime from fragments so no contiguous
// credential-shaped literal is committed (the pkg/gateway/build_test.go
// pattern). The assembled values still match their built-in detectors.
const (
	kgPrefixPartA = "sk"
	kgPrefixPartB = "proj"
	kgPrefixPartC = "A1b2C3d4"
	kgPrefixPartD = "E5f6G7h8"
	kgPrefixPartE = "I9j0K1l2"
)

// kgPrefixKey returns a runtime-assembled key matching the `sk-` prefix rule
// (Type api_key).
func kgPrefixKey() string {
	return kgPrefixPartA + "-" + kgPrefixPartB + "-" + kgPrefixPartC + kgPrefixPartD + kgPrefixPartE
}

// kgEntropyKey returns a runtime-assembled non-hex high-entropy run: 32
// distinct characters over the entropy alphabet, with digits and punctuation.
func kgEntropyKey() string {
	return "Xk9_" + "mQ2v" + "B7nL" + "4pR8" + "tW1y" + "Z6cD" + "3fG5" + "hJ0s"
}

// kgJWTKey returns a runtime-assembled JWT-shaped key whose header decodes to
// a JSON object with "alg" (Type jwt).
func kgJWTKey() string {
	header := "eyJhbGciOiJIUzI1NiIs" + "InR5cCI6IkpXVCJ9"
	return header + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dQw4w9WgXcQ"
}

// kgPEMKey returns a runtime-assembled PEM private-key header (Type
// private_key).
func kgPEMKey() string {
	return "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
}

// kgLuhnDigits returns a 16-digit number that passes the Luhn checksum. It is
// the false-positive probe: as a VALUE it is redacted (see
// TestPipelineFalsePositiveKeys), so a key-position pass-through proves the
// frozen type filter, not a dead detector.
func kgLuhnDigits() string {
	return "4111" + "1111" + "1111" + "1111"
}

// kgEmailKey returns an email-shaped object key.
func kgEmailKey() string {
	return "user" + "@" + "example.com"
}

// kgLuhn15Digits and kgLuhn19Digits return Luhn-valid 15- and 19-digit runs, the
// bounds of the credit-card length window. At key positions they pin the
// bare-numeric-id exemption: a 14-19 digit structural id used as an object key
// is not blocked, while the same run as a value is still redacted.
func kgLuhn15Digits() string {
	return "378282246310005"
}

func kgLuhn19Digits() string {
	return "4000000000000000006"
}

// kgKeyTypes is the frozen key-position detector set written out literally, so
// a production change to the filter fails these tests instead of silently
// redefining them. high_entropy is deliberately absent: a random alphanumeric
// object key is ordinary structure, and blocking it was the measured
// whole-request 403 this set dropped (see TestPipelineFalsePositiveKeys).
var kgKeyTypes = map[string]bool{
	"api_key":     true,
	"jwt":         true,
	"private_key": true,
}

// kgJSON marshals a body so tests never hand-quote JSON.
func kgJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return body
}

// kgKeyBody builds {"<key>":"<value>"}.
func kgKeyBody(t *testing.T, key, value string) []byte {
	t.Helper()
	return kgJSON(t, map[string]string{key: value})
}

// kgArrayNestedBody builds {"outer":[{"<key>":"x"}]}: the credential-shaped
// key sits inside an object inside an array.
func kgArrayNestedBody(t *testing.T, key string) []byte {
	t.Helper()
	return kgJSON(t, map[string]any{"outer": []map[string]string{{key: "x"}}})
}

// kgDoubleEncodedBody builds {"payload":"{\"<key>\":\"x\"}"}: the key sits
// inside a double-encoded string leaf, so WalkKeys reports it with
// Encoded == true.
func kgDoubleEncodedBody(t *testing.T, key string) []byte {
	t.Helper()
	return kgJSON(t, map[string]string{"payload": string(kgKeyBody(t, key, "x"))})
}

// kgAllDetectors registers the complete built-in detector set, so a key or
// value that passes these tests passed after every detector could have flagged
// it. The key-position filter — not a missing detector — is what keeps
// credit_card and email findings from blocking.
func kgAllDetectors(t *testing.T, opts ...redact.Option) *extension.Registry {
	t.Helper()
	return w45Registry(t,
		redact.NewPrefixDetector(opts...),
		redact.NewHighEntropyDetector(opts...),
		redact.NewJWTDetector(opts...),
		redact.NewPrivateKeyDetector(opts...),
		redact.NewLuhnDetector(opts...),
		redact.NewEmailDetector(opts...),
	)
}

// kgProviderRequestSample mirrors the provider request shape used by
// w45RequestBody: a top-level provider payload whose tool_call value is a
// double-encoded JSON document. Every value here is deliberately ordinary, so
// the sample must pass through byte-identically.
func kgProviderRequestSample(t *testing.T) []byte {
	t.Helper()
	inner, err := json.Marshal(map[string]any{
		"name": "read_file",
		"args": map[string]any{"path": "/tmp/notes.txt"},
	})
	if err != nil {
		t.Fatalf("marshal tool call: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"model":         "claude-test",
		"messages":      []map[string]any{{"role": "user", "content": "summarize the file"}},
		"tools":         []map[string]any{{"name": "read_file", "type": "custom", "index": 0}},
		"finish_reason": "tool_use",
		"tool_use_id":   "toolu_01ABC",
		"tool_call":     string(inner),
	})
	if err != nil {
		t.Fatalf("marshal provider sample: %v", err)
	}
	return body
}

// TestPipelineCredentialShapedKeys is the W1.2 acceptance test for the key
// guard: a credential-shaped object key participates in the frozen detector
// set {api_key, jwt, private_key}, and a hit fails closed before any value
// redaction can run. Findings must never carry a type outside that set, and no
// transformed body may be produced (upstream receives zero bytes).
func TestPipelineCredentialShapedKeys(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: kgAllDetectors(t), Engine: engine, Tool: "w1.2-keys"})
	transform := pipe.RequestTransform()

	// The exported type constants are the wire contract the filter selects on;
	// a rename must fail here rather than silently stop blocking.
	t.Run("frozen_finding_type_values", func(t *testing.T) {
		for got, want := range map[string]string{
			redact.FindingTypeAPIKey:      "api_key",
			redact.FindingTypeHighEntropy: "high_entropy",
			redact.FindingTypeJWT:         "jwt",
			redact.FindingTypePrivateKey:  "private_key",
		} {
			if got != want {
				t.Errorf("exported finding type = %q, want %q", got, want)
			}
		}
	})

	cases := []struct {
		name      string
		body      []byte
		wantTypes []string
	}{
		{"api_key_prefix_key", kgKeyBody(t, kgPrefixKey(), "x"), []string{"api_key"}},
		{"jwt_key", kgKeyBody(t, kgJWTKey(), "x"), []string{"jwt"}},
		{"private_key_header_key", kgKeyBody(t, kgPEMKey(), "x"), []string{"private_key"}},
		{"key_nested_in_object_in_array", kgArrayNestedBody(t, kgPrefixKey()), []string{"api_key"}},
		{"key_inside_double_encoded_leaf", kgDoubleEncodedBody(t, kgPrefixKey()), []string{"api_key"}},
		// The key check runs before the value path is applied: a credential
		// key plus a credential value must block, not return a redacted body.
		{"credential_key_with_credential_value", kgKeyBody(t, kgPrefixKey(), w45Secret()), []string{"api_key"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transform(tc.body)
			if err == nil {
				t.Fatalf("transform passed a credential-shaped key through: %s", got)
			}
			var blocked *BlockedError
			if !errors.As(err, &blocked) {
				t.Fatalf("error = %T %v, want *BlockedError", err, err)
			}
			if blocked.Phase != extension.RequestContent {
				t.Errorf("phase = %v, want %v", blocked.Phase, extension.RequestContent)
			}
			if got != nil {
				t.Errorf("blocked transform returned a body: %q", got)
			}
			if len(blocked.Findings) == 0 {
				t.Fatal("key block reported no findings")
			}
			types := make(map[string]bool, len(blocked.Findings))
			for _, f := range blocked.Findings {
				types[f.Type] = true
				if !kgKeyTypes[f.Type] {
					t.Errorf("key block reported type %q, outside the frozen key set", f.Type)
				}
			}
			for _, want := range tc.wantTypes {
				if !types[want] {
					t.Errorf("findings = %v, want type %q present", types, want)
				}
			}
			t.Logf("blocked with %v; phase=%v; finding types=%v; transformed bytes=%d", err, blocked.Phase, types, len(got))
		})
	}

	t.Run("upstream_receives_zero_bytes", func(t *testing.T) {
		var hits, received atomic.Int64
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			n, _ := io.Copy(io.Discard, r.Body)
			received.Add(n)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(upstream.Close)
		srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
		t.Cleanup(srv.Close)

		body := kgKeyBody(t, kgPrefixKey(), "x")
		resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("through proxy: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
		if hits.Load() != 0 {
			t.Errorf("upstream was dialed %d time(s) after a key block", hits.Load())
		}
		if received.Load() != 0 {
			t.Errorf("upstream received %d byte(s) after a key block", received.Load())
		}
		t.Logf("status=%d upstream_hits=%d upstream_bytes=%d", resp.StatusCode, hits.Load(), received.Load())
	})
}

// TestPipelineFalsePositiveKeys is the W1.2 false-positive gate: ordinary
// structural keys, a high-entropy random-alphanumeric key, a Luhn-valid 16-digit
// numeric key, an email-shaped key and a real-ish provider request sample all
// pass through byte-identically. The luhn and email detectors are registered
// and proven live on values below, so the pass-through is the frozen key-type
// filter at work; the high_entropy key is the measured live false positive
// ({"<random40>": "value"} once produced a whole-request 403).
func TestPipelineFalsePositiveKeys(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: kgAllDetectors(t), Engine: engine, Tool: "w1.2-fp"})
	transform := pipe.RequestTransform()

	cases := []struct {
		name string
		body []byte
	}{
		{"structural_keys", []byte(`{"model":"claude-test","role":"user","content":"hello","type":"text","name":"read_file","index":0,"finish_reason":"stop","tool_use_id":"toolu_01ABC"}`)},
		{"high_entropy_random_alnum_key", kgKeyBody(t, kgEntropyKey(), "x")},
		{"luhn_valid_16_digit_key", kgKeyBody(t, kgLuhnDigits(), "x")},
		{"luhn_valid_15_digit_key", kgKeyBody(t, kgLuhn15Digits(), "x")},
		{"luhn_valid_19_digit_key", kgKeyBody(t, kgLuhn19Digits(), "x")},
		{"email_shaped_key", kgKeyBody(t, kgEmailKey(), "x")},
		{"provider_request_sample", kgProviderRequestSample(t)},
		{"double_encoded_structural_keys", kgDoubleEncodedBody(t, "model")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transform(tc.body)
			if err != nil {
				t.Fatalf("transform rejected a false-positive key: %v", err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Errorf("body changed:\n got: %s\nwant: %s", got, tc.body)
			}
		})
	}

	// Non-vacuity: the excluded detectors are alive. The same digits and the
	// same address are redacted at value positions, so the key-position
	// pass-through above is the filter, not a missing detector.
	t.Run("excluded_detectors_are_live_on_values", func(t *testing.T) {
		body := kgJSON(t, map[string]string{"card": kgLuhnDigits(), "amex": kgLuhn15Digits(), "mail": kgEmailKey()})
		got, err := transform(body)
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		if bytes.Contains(got, []byte(kgLuhnDigits())) {
			t.Errorf("luhn detector did not redact the digits as a value: %s", got)
		}
		if bytes.Contains(got, []byte(kgLuhn15Digits())) {
			t.Errorf("luhn detector did not redact the 15-digit run as a value: %s", got)
		}
		if bytes.Contains(got, []byte(kgEmailKey())) {
			t.Errorf("email detector did not redact the address as a value: %s", got)
		}
	})
}

// TestPipelinePureHexKeysNotBlocked pins the accepted, documented limitation:
// high_entropy excludes pure-hex runs (hexOnlyPattern) at the value domain, so
// the identical exclusion applies at key positions and a pure-hex key is NOT
// blocked. The test also proves the miss is the value-domain exclusion rather
// than a new key-domain gap, and that the detector is otherwise live. W1.5
// owns documenting this limitation; this test keeps it honest and explicit so
// nobody can mistake it for closed.
func TestPipelinePureHexKeysNotBlocked(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: kgAllDetectors(t), Engine: engine, Tool: "w1.2-hex"})
	transform := pipe.RequestTransform()
	hexRun := strings.Repeat("a1b2c3d4", 5) // 40 chars, pure hex

	keyBody := kgKeyBody(t, hexRun, "x")
	got, err := transform(keyBody)
	if err != nil {
		t.Fatalf("pure-hex key was blocked, but the recorded limitation says it is not: %v", err)
	}
	if !bytes.Equal(got, keyBody) {
		t.Errorf("pure-hex key body changed:\n got: %s\nwant: %s", got, keyBody)
	}
	t.Logf("documented limitation (open, W1.5 owns the docs): pure-hex key forwarded unchanged")

	// The same exclusion at the value domain: the identical run is not
	// redacted as a value either, so the key-domain miss introduces no new gap.
	valueBody := kgKeyBody(t, "value", hexRun)
	got, err = transform(valueBody)
	if err != nil {
		t.Fatalf("transform pure-hex value: %v", err)
	}
	if !bytes.Equal(got, valueBody) {
		t.Errorf("pure-hex value was rewritten, but the value-domain exclusion says it is not:\n got: %s", got)
	}

	// Non-vacuity: the high_entropy detector is live and redacts a non-hex run
	// of the same length, so the passes above are the hex exclusion.
	entropyBody := kgKeyBody(t, "value", kgEntropyKey())
	got, err = transform(entropyBody)
	if err != nil {
		t.Fatalf("transform high-entropy value: %v", err)
	}
	if bytes.Contains(got, []byte(kgEntropyKey())) {
		t.Errorf("non-hex high-entropy value survived redaction: %s", got)
	}
}

// TestPipelineAllowlistedKeysNotBlocked proves the allowlist interaction falls
// out of the existing machinery: the detectors' own Inspect suppresses a
// finding whose span lies inside an allowlisted literal, so an allowlisted
// credential-shaped key yields no finding and therefore no block. The control
// pipeline without the allowlist blocks the same body, proving the allowlist —
// not a detector gap — is what suppresses it.
func TestPipelineAllowlistedKeysNotBlocked(t *testing.T) {
	engine := w45Engine(t)
	key := kgPrefixKey()
	pipe := w45Pipeline(t, PipelineConfig{
		Registry: kgAllDetectors(t, redact.WithAllowlist(key)),
		Engine:   engine,
		Tool:     "w1.2-allow",
	})
	body := kgKeyBody(t, key, "x")

	got, err := pipe.RequestTransform()(body)
	if err != nil {
		t.Fatalf("allowlisted credential-shaped key was blocked: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("allowlisted key body changed:\n got: %s\nwant: %s", got, body)
	}
	t.Logf("allowlisted key forwarded byte-identically: %s", got)

	control := w45Pipeline(t, PipelineConfig{Registry: kgAllDetectors(t), Engine: engine, Tool: "w1.2-allow-control"})
	if _, err := control.RequestTransform()(body); err == nil {
		t.Fatal("control pipeline without the allowlist did not block the same key")
	}
}

// TestPipelineKnownSecretKeyStillBlockedAtEgress proves the compensating
// control for dropping high_entropy from the key set: a secret the engine
// already knows, re-sent as an object key, is refused at the outbound re-check
// even though the key guard no longer blocks it. The registry carries only the
// prefix detector, so the key guard cannot block the high-entropy key and the
// egress key-position carve-out is the load-bearing defense (removing it
// forwards the plaintext key; see the failure evidence).
func TestPipelineKnownSecretKeyStillBlockedAtEgress(t *testing.T) {
	secret := "kR8mQ2vZ9pL4wX7nT1bY6cH3jF5dS0aG"
	engine := w45Engine(t)
	engine.Placeholder(secret, "api_key")
	pipe := w45Pipeline(t, PipelineConfig{
		Registry: w45Registry(t, redact.NewPrefixDetector()),
		Engine:   engine,
		Tool:     "w1.2-known-key-egress",
	})
	body := kgKeyBody(t, secret, "value")

	status, upstream := egressE2E(t, pipe, body)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (a known secret as a key must be refused)", status, http.StatusForbidden)
	}
	if upstream.hits.Load() != 0 || len(upstream.received()) != 0 {
		t.Fatalf("upstream dialed %d time(s) / received %d bytes, want 0/0", upstream.hits.Load(), len(upstream.received()))
	}
	if got := pipe.EgressBlocks(); got != 1 {
		t.Errorf("EgressBlocks = %d, want 1", got)
	}
	t.Logf("known secret as an object key refused at egress: status=%d upstream_hits=%d upstream_bytes=%d",
		status, upstream.hits.Load(), len(upstream.received()))
}

// TestPipelineKeysDoNotBypassValueRedaction is the regression control for the
// existing value path: a safe (non-credential-shaped) key with a secret value
// still goes through value redaction, and the object key itself is never
// rewritten.
func TestPipelineKeysDoNotBypassValueRedaction(t *testing.T) {
	engine := w45Engine(t)
	reg := w45Registry(t, redact.NewPrefixDetector(), redact.NewHighEntropyDetector())
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine, Tool: "w1.2-value"})
	secret := w45Secret()
	body := kgKeyBody(t, "api_key", secret)

	got, err := pipe.RequestTransform()(body)
	if err != nil {
		t.Fatalf("safe key with a secret value was blocked: %v", err)
	}
	if bytes.Contains(got, []byte(secret)) {
		t.Fatalf("secret value survived value redaction: %s", got)
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v\n%s", err, got)
	}
	value, ok := decoded["api_key"]
	if !ok {
		t.Fatalf("the object key was rewritten away: %s", got)
	}
	if value == secret || !w45PlaceholderRe.MatchString(value) {
		t.Errorf("value = %q, want a placeholder", value)
	}
	t.Logf("key kept verbatim, value redacted: %s", got)
}

// TestPipelineWalkKeysAgreesWithWalk pins the invariant the residual branch
// relies on: Walk and WalkKeys share their validation, so they agree on
// success and on the sentinel error for the same inputs. A disagreement would
// mean the key scan can fail where the value scan succeeded, which is exactly
// the case TestPipelineWalkKeysFailureFailsClosed handles fail-closed.
//
// Encoded-depth exhaustion is deliberately absent: constructing it needs
// exponentially growing escaped bytes, and pkg/protocol's own walker tests
// already pin that sentinel for both walkers.
func TestPipelineWalkKeysAgreesWithWalk(t *testing.T) {
	// +2 so a non-empty array exists one level past MaxNestingDepth; an empty
	// container one level short of the bound is accepted by both walkers.
	deep := strings.Repeat("[", protocol.MaxNestingDepth+2) + strings.Repeat("]", protocol.MaxNestingDepth+2)
	cases := []struct {
		name    string
		body    []byte
		wantErr error // nil: both must succeed
	}{
		{"valid_object", []byte(`{"a":1,"b":{"c":"d"}}`), nil},
		{"valid_with_double_encoding", kgDoubleEncodedBody(t, "inner"), nil},
		{"empty_object", []byte(`{}`), nil},
		{"non_json_scalar", []byte(`"just a string"`), nil},
		{"trailing_data", []byte(`{"a":1} extra`), protocol.ErrMalformedJSON},
		{"truncated", []byte(`{"a":`), protocol.ErrMalformedJSON},
		{"invalid_utf8", []byte{0xff, 0xfe, 0x00, 0x01}, protocol.ErrMalformedJSON},
		{"over_depth", []byte(deep), protocol.ErrNestingDepth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, walkErr := protocol.Walk(tc.body)
			_, keysErr := protocol.WalkKeys(tc.body)
			if (walkErr == nil) != (keysErr == nil) {
				t.Fatalf("Walk err = %v, WalkKeys err = %v; the two walkers must agree", walkErr, keysErr)
			}
			if tc.wantErr == nil {
				if walkErr != nil {
					t.Fatalf("Walk(%s) = %v, want success", tc.name, walkErr)
				}
				return
			}
			if !errors.Is(walkErr, tc.wantErr) || !errors.Is(keysErr, tc.wantErr) {
				t.Fatalf("sentinels: Walk = %v, WalkKeys = %v, want %v", walkErr, keysErr, tc.wantErr)
			}
		})
	}
}

// TestPipelineWalkKeysFailureFailsClosed pins the documented decision for the
// residual branch: if the key scan fails after Walk succeeded, the transform
// returns an error and never passes the body through — a credential-shaped key
// could otherwise be hidden. It is an internal fail-closed error (the forwarder
// answers 500 with zero upstream bytes), deliberately not a *BlockedError,
// because it is not a detector verdict.
func TestPipelineWalkKeysFailureFailsClosed(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t, redact.NewPrefixDetector()), Engine: engine})

	original := walkRequestKeys
	t.Cleanup(func() { walkRequestKeys = original })
	walkRequestKeys = func([]byte) ([]protocol.KeySpan, error) {
		return nil, protocol.ErrMalformedJSON
	}

	body := []byte(`{"stable":"value"}`)
	got, err := pipe.RequestTransform()(body)
	if err == nil {
		t.Fatalf("a failed key scan passed the body through: %s", got)
	}
	if !errors.Is(err, protocol.ErrMalformedJSON) {
		t.Errorf("error %v does not wrap the key-scan failure", err)
	}
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		t.Errorf("a failed key scan reported a policy block: %v", err)
	}
	if got != nil {
		t.Errorf("a failed key scan produced a body: %q", got)
	}
	t.Logf("documented fail-closed decision: %v", err)
}

// kgFailOnContentInspector is a FailClosed-capable Inspector that panics as
// soon as it is shown any content leaf. It models a detector that fails only
// for some inputs, and that is what keeps the pinning test below non-vacuous:
// a body whose only strings are object keys has no value leaves, so the value
// evaluation succeeds while the key evaluation fails. The aggregate Block is
// therefore observable only through the key scan.
type kgFailOnContentInspector struct{}

func (kgFailOnContentInspector) ID() string { return "kg-fail-on-content" }

func (kgFailOnContentInspector) Capabilities() extension.Capabilities {
	return extension.Capabilities{
		Phases:      []extension.Phase{extension.RequestContent},
		ReadContent: true,
	}
}

func (kgFailOnContentInspector) Inspect(doc *extension.Document) ([]extension.Finding, error) {
	if len(doc.Leaves) > 0 {
		panic("kg-fail-on-content: intentional detector failure")
	}
	return nil, nil
}

// kgFindingTypes lists the finding types in order, for test logs only.
func kgFindingTypes(findings []extension.Finding) []string {
	types := make([]string, 0, len(findings))
	for _, f := range findings {
		types = append(types, f.Type)
	}
	return types
}

// TestPipelineKeysFailClosedOnDetectorFailure pins the aggregate-Block rule of
// the key scan. extension.Policy.evaluate copies only the findings whose
// Action equals the aggregate action into Decision.Findings, so when a
// FailClosed inspector fails, a block-forcing plugin_failure finding hides
// every credential-type finding (all Action Redact). Filtering that slice by
// type would drop the failure and fail open; the key scan must honour the
// aggregate Block before the type filter, mirroring the value path.
func TestPipelineKeysFailClosedOnDetectorFailure(t *testing.T) {
	engine := w45Engine(t)
	key := kgPrefixKey()

	newPipeline := func(t *testing.T, failures map[string]extension.FailurePolicy) *Pipeline {
		t.Helper()
		reg := w45Registry(t, kgFailOnContentInspector{}, redact.NewPrefixDetector())
		policy := extension.NewPolicy(reg, extension.PolicyConfig{Failures: failures})
		return w45Pipeline(t, PipelineConfig{Registry: reg, Policy: policy, Engine: engine, Tool: "w1.2-detector-failure"})
	}

	t.Run("aggregate_block_at_the_key_position_blocks", func(t *testing.T) {
		pipe := newPipeline(t, map[string]extension.FailurePolicy{"kg-fail-on-content": extension.FailClosed})
		// The value is a number, so the value document has no string leaf and
		// its evaluation succeeds: only the key scan observes the failure.
		body := kgJSON(t, map[string]any{key: 1})
		got, err := pipe.RequestTransform()(body)
		if err == nil {
			t.Fatalf("aggregate Block at the key position was masked; forwarded: %s", got)
		}
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("error = %T %v, want *BlockedError", err, err)
		}
		if blocked.Phase != extension.RequestContent {
			t.Errorf("phase = %v, want %v", blocked.Phase, extension.RequestContent)
		}
		if got != nil {
			t.Errorf("blocked transform produced a body: %q", got)
		}
		if len(blocked.Findings) == 0 {
			t.Error("blocked with no findings")
		}
		t.Logf("blocked on detector failure: findings=%d types=%v", len(blocked.Findings), kgFindingTypes(blocked.Findings))
	})

	// FailClosed means the request must not proceed without the inspector's
	// verdict on the keys, so the block is not gated on a credential match.
	t.Run("aggregate_block_blocks_even_a_safe_key", func(t *testing.T) {
		pipe := newPipeline(t, map[string]extension.FailurePolicy{"kg-fail-on-content": extension.FailClosed})
		body := kgJSON(t, map[string]any{"model": 1})
		got, err := pipe.RequestTransform()(body)
		if err == nil {
			t.Fatalf("a FailClosed detector failure did not block: %s", got)
		}
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("error = %T %v, want *BlockedError", err, err)
		}
		if got != nil {
			t.Errorf("blocked transform produced a body: %q", got)
		}
	})

	// Mirror: with no failing inspector the ordinary path is unchanged — a
	// credential key blocks through the frozen type filter.
	t.Run("credential_key_still_blocks_without_a_failing_inspector", func(t *testing.T) {
		pipe := newPipeline(t, nil)
		body := kgJSON(t, map[string]any{key: 1})
		got, err := pipe.RequestTransform()(body)
		if err == nil {
			t.Fatalf("credential key did not block via the type filter: %s", got)
		}
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("error = %T %v, want *BlockedError", err, err)
		}
		if got != nil {
			t.Errorf("blocked transform produced a body: %q", got)
		}
	})

	// Mirror: and a safe key still passes byte-identically.
	t.Run("safe_key_still_passes_without_a_failing_inspector", func(t *testing.T) {
		pipe := newPipeline(t, nil)
		body := []byte(`{"model":"claude-test"}`)
		got, err := pipe.RequestTransform()(body)
		if err != nil {
			t.Fatalf("safe key was blocked: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("body changed:\n got: %s\nwant: %s", got, body)
		}
	})
}
