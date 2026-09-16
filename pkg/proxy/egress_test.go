package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/redact"
)

// egressSecret assembles the fixture credential from fragments (repo
// convention: no contiguous key-shaped literal is committed). It is
// alphanumeric on purpose, mirroring the W2.2 fixture: separator-strip variants
// then leave the bytes intact, and no covered encoding collides with a
// separator byte.
func egressSecret() string {
	return strings.Join([]string{"sk", "live", "4f8a2c9e", "71b3d650", "aa19ff02"}, "")
}

// egressMappedEngine returns a fresh engine that already maps the fixture
// secret to a placeholder — exactly the mapping the pipeline's own redaction
// performs when it rewrites a detected value. The secret therefore counts as
// known to the pipeline while the request body itself carries only an encoded
// form, which no value detector flags.
func egressMappedEngine(t *testing.T) (*redact.PlaceholderEngine, string) {
	t.Helper()
	secret := egressSecret()
	engine := w45Engine(t)
	engine.Placeholder(secret, "api_key")
	return engine, secret
}

// egressEncodedBody wraps an encoded payload in a valid provider-shaped JSON
// request body through encoding/json, so every byte is escaped the way a client
// must escape it to keep the request valid JSON. This is the wire form the
// outbound re-check scans.
func egressEncodedBody(t *testing.T, payload []byte) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": string(payload)},
		},
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return body
}

// egressVariant is one wire spelling of a covered form.
type egressVariant struct {
	name    string
	payload []byte
}

// egressForm is one of the frozen W2.2 ①–⑬ encoding forms with its variants.
type egressForm struct {
	name     string
	variants []egressVariant
}

// egressForms builds the frozen ①–⑬ table for one secret. The encoders are
// deliberately local to this test (no shelling out): each emits the exact bytes
// the real encoder would, and the JSON body around them is valid JSON, which is
// the only way such a payload reaches the egress re-check at all.
func egressForms(t *testing.T, secret string) []egressForm {
	t.Helper()
	raw := []byte(secret)
	gzipped := egressGzip(t, raw)
	return []egressForm{
		{name: "01_separators", variants: []egressVariant{
			{"space", egressInterleave(raw, " ")},
			{"dot", egressInterleave(raw, ".")},
			{"dash", egressInterleave(raw, "-")},
			{"zero_width", egressInterleave(raw, "\u200b")},
		}},
		{name: "02_hex", variants: []egressVariant{
			{"lower", []byte(hex.EncodeToString(raw))},
			{"upper", []byte(strings.ToUpper(hex.EncodeToString(raw)))},
		}},
		{name: "03_od_tu1_v", variants: []egressVariant{
			{"od", egressOdTu1V(raw)},
		}},
		{name: "04_rot13", variants: []egressVariant{
			{"rot13", egressRot13(raw)},
		}},
		{name: "05_base64", variants: []egressVariant{
			{"std_padded", []byte(base64.StdEncoding.EncodeToString(raw))},
			{"std_raw_w0", []byte(base64.RawStdEncoding.EncodeToString(raw))},
			{"url_padded", []byte(base64.URLEncoding.EncodeToString(raw))},
			{"url_raw", []byte(base64.RawURLEncoding.EncodeToString(raw))},
		}},
		{name: "06_four_char_chunks", variants: []egressVariant{
			{"dash", egressChunks(raw, "-")},
			{"space", egressChunks(raw, " ")},
		}},
		{name: "07_gzip_base64", variants: []egressVariant{
			{"gzip_std", []byte(base64.StdEncoding.EncodeToString(gzipped))},
		}},
		{name: "08_base32", variants: []egressVariant{
			{"base32", []byte(base32.StdEncoding.EncodeToString(raw))},
			{"base32_gzip", []byte(base32.StdEncoding.EncodeToString(gzipped))},
		}},
		{name: "09_percent_url", variants: []egressVariant{
			{"percent", egressPercent(raw)},
		}},
		{name: "10_fold_w1", variants: []egressVariant{
			{"fold", egressFoldW1(raw)},
		}},
		{name: "11_rot47_atbash", variants: []egressVariant{
			{"rot47", egressRot47(raw)},
			{"atbash", egressAtbash(raw)},
		}},
		{name: "12_dollar_hex_escapes", variants: []egressVariant{
			{"dollar_hex", egressDollarHex(raw)},
		}},
		{name: "13_utf16le", variants: []egressVariant{
			{"utf16le", egressUTF16LE(secret)},
		}},
	}
}

// egressE2E drives body through the real forwarder and a real httptest upstream
// and returns the client status plus the capturing upstream.
func egressE2E(t *testing.T, pipe *Pipeline, body []byte) (int, *w45EchoUpstream) {
	t.Helper()
	upstream := &w45EchoUpstream{}
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstreamServer.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, upstream
}

// TestPipelineEgressRecheckBlocksEncodedSecrets is the W2.3 negative gate: for
// every frozen W2.2 encoding form ①–⑬, a request that carries the encoded
// secret in a JSON string field must be blocked at egress — 403, the upstream
// is never dialed and receives zero bytes, and the block is counted. The
// secret is mapped through the engine before the request, so the pipeline knows
// it in exactly the way a prior redaction would have taught it.
func TestPipelineEgressRecheckBlocksEncodedSecrets(t *testing.T) {
	for _, form := range egressForms(t, egressSecret()) {
		for _, variant := range form.variants {
			t.Run(form.name+"_"+variant.name, func(t *testing.T) {
				engine, _ := egressMappedEngine(t)
				pipe := w45Pipeline(t, PipelineConfig{
					Registry: w45Registry(t, redact.NewPrefixDetector()),
					Engine:   engine,
					Tool:     "w2.3-egress",
				})
				body := egressEncodedBody(t, variant.payload)

				status, upstream := egressE2E(t, pipe, body)
				sent := upstream.received()

				if status != http.StatusForbidden {
					t.Errorf("status = %d, want %d", status, http.StatusForbidden)
				}
				if got := upstream.hits.Load(); got != 0 {
					t.Errorf("upstream dialed %d time(s), want 0", got)
				}
				if len(sent) != 0 {
					t.Errorf("upstream received %d bytes, want 0", len(sent))
				}
				if got := pipe.EgressBlocks(); got != 1 {
					t.Errorf("EgressBlocks = %d, want 1", got)
				}
				t.Logf("form=%s variant=%s status=%d upstream_hits=%d upstream_bytes=%d egress_blocks=%d",
					form.name, variant.name, status, upstream.hits.Load(), len(sent), pipe.EgressBlocks())
			})
		}
	}
}

// TestPipelineEgressRecheckNormalPathUntouched is the zero-false-positive gate.
// A normal provider-shaped request keeps its pre-re-check output byte for byte:
// the redaction is still applied exactly (expected bytes derived from the
// engine's own deterministic mapping), a secret-free request is forwarded
// untouched, the upstream capture proves no plaintext, and nothing is blocked.
func TestPipelineEgressRecheckNormalPathUntouched(t *testing.T) {
	secret := w45Secret()
	noSecret := []byte(`{"model":"claude-3-5-sonnet-20241022","max_tokens":1024,"messages":[{"role":"user","content":"hello, what is 2+2?"}]}`)

	cases := []struct {
		name         string
		body         []byte
		wantRedacted bool
	}{
		{"redaction_still_applied", w45RequestBody(secret), true},
		{"no_secret_forwarded_byte_identically", noSecret, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := w45Engine(t)
			reg := w45Registry(t, redact.NewPrefixDetector(), redact.NewHighEntropyDetector())
			pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine, Tool: "w2.3-normal"})

			status, upstream := egressE2E(t, pipe, tc.body)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want %d", status, http.StatusOK)
			}

			want := tc.body
			if tc.wantRedacted {
				want = bytes.ReplaceAll(tc.body, []byte(secret),
					[]byte(engine.Placeholder(secret, "api_key")))
			}
			sent := upstream.received()
			if !bytes.Equal(sent, want) {
				t.Errorf("upstream body changed:\n got %s\nwant %s", sent, want)
			}
			if bytes.Contains(sent, []byte(secret)) {
				t.Fatal("upstream received the raw secret")
			}
			if got := pipe.EgressBlocks(); got != 0 {
				t.Errorf("EgressBlocks = %d, want 0", got)
			}
			t.Logf("upstream body (no plaintext): %s", sent)
		})
	}
}

// TestPipelineEgressBlockedErrorShape pins the frozen error shape: the block
// returns *EgressBlockedError carrying the matched placeholder (never the
// plaintext), Error() embeds neither the plaintext, the placeholder nor any
// body byte, the counter increments once, and the reporter receives exactly one
// metadata-only egress_blocked event whose only content-bearing field is the
// placeholder token.
func TestPipelineEgressBlockedErrorShape(t *testing.T) {
	engine := w45Engine(t)
	secret := egressSecret()
	placeholder := engine.Placeholder(secret, "api_key")
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	var events []RedactionEvent
	pipe.SetRedactionReporter(func(ev RedactionEvent) { events = append(events, ev) })

	body := egressEncodedBody(t, []byte(hex.EncodeToString([]byte(secret))))
	got, err := pipe.RequestTransform()(body)

	if got != nil {
		t.Errorf("blocked transform returned a %d-byte body, want none", len(got))
	}
	var egressErr *EgressBlockedError
	if !errors.As(err, &egressErr) {
		t.Fatalf("err = %v, want *EgressBlockedError", err)
	}
	if egressErr.Placeholder != placeholder {
		t.Errorf("Placeholder = %q, want the engine's token %q", egressErr.Placeholder, placeholder)
	}
	if strings.Contains(egressErr.Placeholder, secret) {
		t.Fatal("the error's placeholder field contains the plaintext")
	}
	if msg := err.Error(); strings.Contains(msg, secret) {
		t.Fatal("Error() contains the plaintext")
	} else if strings.Contains(msg, placeholder) {
		t.Fatal("Error() contains the placeholder")
	} else if len(msg) > 256 {
		t.Errorf("Error() is %d bytes, want a short metadata message", len(msg))
	}

	if got := pipe.EgressBlocks(); got != 1 {
		t.Errorf("EgressBlocks = %d, want 1", got)
	}

	if len(events) != 1 {
		t.Fatalf("reporter received %d events, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.Action != RedactionActionEgressBlocked {
		t.Errorf("event Action = %q, want %q", ev.Action, RedactionActionEgressBlocked)
	}
	if ev.Direction != RedactionDirectionRequest {
		t.Errorf("event Direction = %q, want %q", ev.Direction, RedactionDirectionRequest)
	}
	if ev.Phase != extension.RequestContent.String() {
		t.Errorf("event Phase = %q, want %q", ev.Phase, extension.RequestContent.String())
	}
	if ev.Placeholder != placeholder {
		t.Errorf("event Placeholder = %q, want %q", ev.Placeholder, placeholder)
	}
	if ev.Type != "" || ev.Masked != "" || ev.Length != 0 {
		t.Errorf("event carries detector fields for a block: Type=%q Masked=%q Length=%d",
			ev.Type, ev.Masked, ev.Length)
	}
	rendered := fmt.Sprintf("%+v", ev)
	if strings.Contains(rendered, secret) {
		t.Fatal("the reporter event contains the plaintext")
	}
	if strings.Contains(rendered, string(body)) {
		t.Fatal("the reporter event contains body bytes")
	}
	t.Logf("egress block event: %+v", ev)
}

// TestPipelineEgressExemptsVisiblePlaintext pins the allowlist/C7 exemption:
// a secret the allowlist lets through (and which the engine therefore knows
// from an earlier redaction) is forwarded verbatim, while the very same secret
// in an encoded-only form still blocks. Without the exemption the allowlist
// could never take effect after the value had been redacted once.
func TestPipelineEgressExemptsVisiblePlaintext(t *testing.T) {
	secret := w45Secret()
	wrapper := "keep." + secret + ".keep"

	engine := w45Engine(t)
	engine.Placeholder(secret, "api_key")
	reg := w45Registry(t, redact.NewPrefixDetector(redact.WithAllowlist(wrapper)))
	pipe := w45Pipeline(t, PipelineConfig{Registry: reg, Engine: engine})

	body := []byte(`{"payload":"` + wrapper + `"}`)
	got, err := pipe.RequestTransform()(body)
	if err != nil {
		t.Fatalf("allowlisted request blocked: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("allowlisted body changed: %s", got)
	}
	if n := pipe.EgressBlocks(); n != 0 {
		t.Errorf("EgressBlocks = %d, want 0 for allowlisted plaintext", n)
	}

	encoded := egressEncodedBody(t, []byte(base64.StdEncoding.EncodeToString([]byte(secret))))
	if _, err := pipe.RequestTransform()(encoded); err == nil {
		t.Fatal("encoded copy of an allowlisted secret was not blocked")
	}
	if n := pipe.EgressBlocks(); n != 1 {
		t.Errorf("EgressBlocks = %d, want 1 after the encoded copy", n)
	}
}

// TestPipelineEgressRecheckWithoutKnownSecrets pins the cheap skip: with an
// engine that knows no secrets the re-check must not block even a payload that
// would be caught once the same secret is mapped, and the body is forwarded
// byte-identically.
func TestPipelineEgressRecheckWithoutKnownSecrets(t *testing.T) {
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	body := egressEncodedBody(t, []byte(hex.EncodeToString([]byte(egressSecret()))))
	got, err := pipe.RequestTransform()(body)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("body changed although no secret is known")
	}
	if got := pipe.EgressBlocks(); got != 0 {
		t.Errorf("EgressBlocks = %d, want 0", got)
	}
	if got := (*Pipeline)(nil).EgressBlocks(); got != 0 {
		t.Errorf("nil pipeline EgressBlocks = %d, want 0", got)
	}
}

// TestPipelineEgressErrorHandlerMapsTo403 pins the additive mapping: an
// *EgressBlockedError (directly or wrapped) becomes a 403, while the existing
// BlockedError path stays byte-identical and any other error is still left to
// the forwarder's fail-closed default.
func TestPipelineEgressErrorHandlerMapsTo403(t *testing.T) {
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: w45Engine(t)})
	handler := pipe.TransformErrorHandler()

	cases := []struct {
		name        string
		err         error
		wantHandled bool
	}{
		{"egress_blocked", &EgressBlockedError{Placeholder: "__PII_api_key_0123456789abcdef__"}, true},
		{"wrapped_egress_blocked", fmt.Errorf("proxy: transform: %w",
			&EgressBlockedError{Placeholder: "__PII_api_key_0123456789abcdef__"}), true},
		{"blocked_error_unchanged", &BlockedError{Phase: extension.RequestContent}, true},
		{"other_error_defaults", errors.New("boom"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handled := handler(rec, tc.err)
			if handled != tc.wantHandled {
				t.Fatalf("handled = %v, want %v", handled, tc.wantHandled)
			}
			if !tc.wantHandled {
				if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
					t.Fatalf("unhandled error wrote a response: code=%d body=%q", rec.Code, rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			if body := rec.Body.String(); strings.Contains(body, "sk-") {
				t.Errorf("403 body looks like content: %q", body)
			}
		})
	}
}

// --- fixture encoders (test-only, hermetic: no shelling out) ---

// egressInterleave joins every byte of in with sep.
func egressInterleave(in []byte, sep string) []byte {
	parts := make([]string, len(in))
	for i, c := range in {
		parts[i] = string(c)
	}
	return []byte(strings.Join(parts, sep))
}

// egressChunks splits in into four-byte chunks joined by sep.
func egressChunks(in []byte, sep string) []byte {
	var parts []string
	for i := 0; i < len(in); i += 4 {
		end := i + 4
		if end > len(in) {
			end = len(in)
		}
		parts = append(parts, string(in[i:end]))
	}
	return []byte(strings.Join(parts, sep))
}

// egressOdTu1V reproduces `od -tu1 -v` byte for byte: a seven-digit octal
// offset then each byte right-aligned in four columns, sixteen bytes per line,
// with a trailing offset-only line.
func egressOdTu1V(data []byte) []byte {
	var b strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(&b, "%07o", off)
		for _, c := range data[off:end] {
			fmt.Fprintf(&b, "%4d", c)
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%07o\n", len(data))
	return []byte(b.String())
}

func egressRot13(in []byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + (c-'A'+13)%26
		default:
			out[i] = c
		}
	}
	return out
}

// egressRot47 follows the frozen definition: only printable ASCII 33..126 is
// transformed, every other byte is unchanged, so the transform is self-inverse.
func egressRot47(in []byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		if c >= 33 && c <= 126 {
			out[i] = 33 + (c-33+47)%94
		} else {
			out[i] = c
		}
	}
	return out
}

func egressAtbash(in []byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'z' - (c - 'a')
		case c >= 'A' && c <= 'Z':
			out[i] = 'Z' - (c - 'A')
		default:
			out[i] = c
		}
	}
	return out
}

func egressPercent(in []byte) []byte {
	var b strings.Builder
	for _, c := range in {
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return []byte(b.String())
}

func egressFoldW1(in []byte) []byte {
	parts := make([]string, len(in))
	for i, c := range in {
		parts[i] = string(c)
	}
	return []byte(strings.Join(parts, "\n"))
}

func egressDollarHex(in []byte) []byte {
	var b strings.Builder
	b.WriteString("$'")
	for _, c := range in {
		fmt.Fprintf(&b, "\\x%02x", c)
	}
	b.WriteString("'")
	return []byte(b.String())
}

func egressUTF16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func egressGzip(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(in); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
