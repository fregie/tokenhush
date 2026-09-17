package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// responsePayload is the decoded body the buffered response tests start from.
const responsePayload = `{"message":"hello"}`

// upstreamResponse builds one upstream response with the given status,
// Content-Encoding and raw (possibly still encoded) body.
func upstreamResponse(status int, encoding string, body []byte) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("X-Upstream", "fake")
	if encoding != "" {
		header.Set("Content-Encoding", encoding)
	}
	return &http.Response{
		StatusCode:    status,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// encodeGzip returns body as one gzip stream.
func encodeGzip(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// encodeDeflate returns body as one raw deflate stream.
func encodeDeflate(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// scriptedEvaluator records every body it is asked to evaluate and returns a
// fixed verdict, so a test can assert both what the pipeline saw and what the
// handler did with it.
type scriptedEvaluator struct {
	mu       sync.Mutex
	bodies   [][]byte
	decision ResponseDecision
	err      error
}

func (e *scriptedEvaluator) EvaluateResponse(_ context.Context, body []byte) (ResponseDecision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bodies = append(e.bodies, bytes.Clone(body))
	return e.decision, e.err
}

func (e *scriptedEvaluator) seen() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][]byte(nil), e.bodies...)
}

// recordingBackfiller records every body it is asked to backfill and applies
// an optional rewrite, so a test can prove backfill ran and where in the order
// it ran.
type recordingBackfiller struct {
	mu      sync.Mutex
	bodies  [][]byte
	rewrite func([]byte) []byte
}

func (b *recordingBackfiller) Backfill(body []byte) []byte {
	b.mu.Lock()
	b.bodies = append(b.bodies, bytes.Clone(body))
	rewrite := b.rewrite
	b.mu.Unlock()
	if rewrite == nil {
		return body
	}
	return rewrite(body)
}

func (b *recordingBackfiller) seen() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]byte(nil), b.bodies...)
}

// recordingWarnings collects the metadata-only warning lines.
type recordingWarnings struct {
	mu    sync.Mutex
	lines []string
}

func (w *recordingWarnings) Warn(line string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, line)
}

func (w *recordingWarnings) seen() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.lines...)
}

// allowEvaluator is the inert allow verdict shared by the happy-path tests.
func allowEvaluator() *scriptedEvaluator {
	return &scriptedEvaluator{decision: ResponseDecision{Action: ResponseAllow}}
}

// TestResponseHandlerDecodesAndEvaluates pins the happy buffered path: gzip,
// x-gzip and deflate are decoded before the status is committed, the
// Content-Encoding header is removed from the client-bound response, the
// decoded body is evaluated, and backfill runs last.
func TestResponseHandlerDecodesAndEvaluates(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
		encode   func(*testing.T, []byte) []byte
	}{
		{"gzip", "gzip", encodeGzip},
		{"x-gzip", "x-gzip", encodeGzip},
		{"deflate", "deflate", encodeDeflate},
		{"upper-case", "GZIP", encodeGzip},
		{"list-with-identity", "gzip, identity", encodeGzip},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.encode(t, []byte(responsePayload))
			evaluator := allowEvaluator()
			backfills := &recordingBackfiller{rewrite: func(body []byte) []byte {
				return append(bytes.Clone(body), []byte("-backfilled")...)
			}}
			counters := NewCounters()
			handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Backfiller: backfills, Counters: counters})

			status, header, body, err := handler.Handle(upstreamResponse(http.StatusOK, tc.encoding, raw))
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if status != http.StatusOK {
				t.Errorf("status = %d, want 200", status)
			}
			if got := header.Get("Content-Encoding"); got != "" {
				t.Errorf("client-bound Content-Encoding = %q, want removed", got)
			}
			if got, want := string(body), responsePayload+"-backfilled"; got != want {
				t.Errorf("client body = %q, want %q", got, want)
			}
			if got := header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
				t.Errorf("Content-Length = %q, want %d", got, len(body))
			}
			if got := header.Get("X-Upstream"); got != "fake" {
				t.Errorf("end-to-end header X-Upstream = %q, want fake", got)
			}
			if seen := evaluator.seen(); len(seen) != 1 || string(seen[0]) != responsePayload {
				t.Errorf("evaluator saw %q, want the decoded payload exactly once", seen)
			}
			if seen := backfills.seen(); len(seen) != 1 || string(seen[0]) != responsePayload {
				t.Errorf("backfill saw %q, want the evaluated decoded payload", seen)
			}
			if counters.WalkSkips() != 0 || counters.ContentPolicyBlocks() != 0 || counters.RuleBlocks() != 0 {
				t.Errorf("counters moved on the happy path: walk=%d content=%d rule=%d",
					counters.WalkSkips(), counters.ContentPolicyBlocks(), counters.RuleBlocks())
			}
		})
	}
}

// TestResponseHandlerDecodesEncodingListsInReverse pins that a list of
// supported codings is unwound in reverse declared order: "gzip, deflate"
// means gzip was applied first, so the wire bytes are deflate(gzip(payload)).
func TestResponseHandlerDecodesEncodingListsInReverse(t *testing.T) {
	payload := []byte(responsePayload)
	wire := encodeDeflate(t, encodeGzip(t, payload))
	handler := NewResponseHandler(ResponseConfig{Evaluator: allowEvaluator(), Counters: NewCounters()})

	status, header, body, err := handler.Handle(upstreamResponse(http.StatusOK, "gzip, deflate", wire))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if got := header.Get("Content-Encoding"); got != "" {
		t.Errorf("client-bound Content-Encoding = %q, want removed", got)
	}
	if !bytes.Equal(body, payload) {
		t.Errorf("body = %q, want the twice-decoded payload", body)
	}
}

// TestResponseHandlerRefusesUndecodableEncodings pins the transport refusal:
// any coding outside gzip/x-gzip/deflate (and any list mixing one in) is a 502
// with the upstream bytes discarded and no content-policy counter moved.
func TestResponseHandlerRefusesUndecodableEncodings(t *testing.T) {
	secret := []byte("UPSTREAM-SECRET-BYTE-CONTENT")
	payload := []byte(responsePayload)
	leaky := bytes.Repeat([]byte("PREFIX-LEAK-"), 128)
	leakyStream := encodeGzip(t, leaky)

	cases := []struct {
		name     string
		encoding string
		body     []byte
		blank    bool
		leaked   []byte
	}{
		{"br", "br", secret, false, secret},
		{"zstd", "zstd", secret, false, secret},
		{"bogus", "bogus", secret, false, secret},
		{"gzip-then-br", "gzip, br", encodeGzip(t, payload), false, payload},
		{"br-then-gzip", "br, gzip", secret, false, secret},
		{"blank-value", "", secret, true, secret},
		{"corrupt-gzip", "gzip", []byte("not a gzip stream"), false, nil},
		{"corrupt-deflate", "deflate", []byte("not a deflate stream"), false, nil},
		{"truncated-gzip", "gzip", leakyStream[:len(leakyStream)-8], false, []byte("PREFIX-LEAK")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := allowEvaluator()
			counters := NewCounters()
			handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: counters})

			upstream := upstreamResponse(http.StatusOK, tc.encoding, tc.body)
			if tc.blank {
				upstream.Header["Content-Encoding"] = []string{""}
			}
			status, header, body, err := handler.Handle(upstream)
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if status != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", status)
			}
			if header.Get("Content-Type") != "application/json" {
				t.Errorf("refusal Content-Type = %q, want application/json", header.Get("Content-Type"))
			}
			if !strings.Contains(string(body), "undecodable_content_encoding") {
				t.Errorf("refusal body = %q, want the undecodable_content_encoding reason", body)
			}
			if bytes.Contains(body, tc.body) {
				t.Errorf("refusal body carries the raw upstream bytes")
			}
			if tc.leaked != nil && bytes.Contains(body, tc.leaked) {
				t.Errorf("refusal body carries upstream plaintext %q", tc.leaked)
			}
			if got := evaluator.seen(); len(got) != 0 {
				t.Errorf("evaluator ran on an undecodable body: %q", got)
			}
			if counters.ContentPolicyBlocks() != 0 || counters.RuleBlocks() != 0 || counters.WalkSkips() != 0 {
				t.Errorf("transport refusal moved a content counter: content=%d rule=%d walk=%d",
					counters.ContentPolicyBlocks(), counters.RuleBlocks(), counters.WalkSkips())
			}
		})
	}
}

// TestResponseHandlerRefusesBeforeStatusIsCommitted pins that the status code
// is chosen only after decoding succeeded: a valid encoded body keeps the
// upstream status, an undecodable one is a 502 even when the upstream status
// was a success.
func TestResponseHandlerRefusesBeforeStatusIsCommitted(t *testing.T) {
	handler := NewResponseHandler(ResponseConfig{Evaluator: allowEvaluator(), Counters: NewCounters()})

	status, _, body, err := handler.Handle(upstreamResponse(http.StatusTeapot, "gzip", encodeGzip(t, []byte(responsePayload))))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if status != http.StatusTeapot {
		t.Errorf("decodable status = %d, want the upstream 418", status)
	}
	if !bytes.Equal(body, []byte(responsePayload)) {
		t.Errorf("decodable body = %q, want %q", body, responsePayload)
	}

	status, _, _, err = handler.Handle(upstreamResponse(http.StatusTeapot, "br", []byte("opaque")))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if status != http.StatusBadGateway {
		t.Errorf("undecodable status = %d, want 502 rather than the upstream 418", status)
	}
}

// TestResponseHandlerWalkFailureForwardsByteIdentical pins the one forwarding
// failure: a client-bound body the evaluator cannot walk is not a refusal. It
// is forwarded byte-identically with backfill still running and walk_skips
// incremented, because both directions are client-bound.
func TestResponseHandlerWalkFailureForwardsByteIdentical(t *testing.T) {
	plain := []byte("tokenhush: upstream error: quota exceeded\n")

	t.Run("plain-text body is forwarded untouched", func(t *testing.T) {
		counters := NewCounters()
		backfills := &recordingBackfiller{}
		handler := NewResponseHandler(ResponseConfig{
			Evaluator:  &scriptedEvaluator{err: errors.New("walk: not JSON")},
			Backfiller: backfills,
			Counters:   counters,
		})

		status, header, body, err := handler.Handle(upstreamResponse(http.StatusBadRequest, "", plain))
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want the upstream 400", status)
		}
		if !bytes.Equal(body, plain) {
			t.Errorf("body = %q, want the byte-identical %q", body, plain)
		}
		if got := header.Get("Content-Length"); got != strconv.Itoa(len(plain)) {
			t.Errorf("Content-Length = %q, want %d", got, len(plain))
		}
		if got := counters.WalkSkips(); got != 1 {
			t.Errorf("walk_skips = %d, want exactly 1", got)
		}
		if counters.ContentPolicyBlocks() != 0 || counters.RuleBlocks() != 0 {
			t.Errorf("walk skip moved a block counter: content=%d rule=%d",
				counters.ContentPolicyBlocks(), counters.RuleBlocks())
		}
		if got := backfills.seen(); len(got) != 1 {
			t.Errorf("backfill calls = %d, want backfill to still run on the walk-failure path", len(got))
		}
	})

	t.Run("backfill still restores placeholders", func(t *testing.T) {
		placeholder := []byte("__PII_email_0badc0de__")
		body := []byte("cannot walk: ")
		body = append(body, placeholder...)
		counters := NewCounters()
		backfills := &recordingBackfiller{rewrite: func(in []byte) []byte {
			return bytes.ReplaceAll(in, placeholder, []byte("user@example.com"))
		}}
		handler := NewResponseHandler(ResponseConfig{
			Evaluator:  &scriptedEvaluator{err: errors.New("walk: not JSON")},
			Backfiller: backfills,
			Counters:   counters,
		})

		_, _, out, err := handler.Handle(upstreamResponse(http.StatusOK, "gzip", encodeGzip(t, body)))
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		if got, want := string(out), "cannot walk: user@example.com"; got != want {
			t.Errorf("body = %q, want the restored %q", got, want)
		}
		if got := counters.WalkSkips(); got != 1 {
			t.Errorf("walk_skips = %d, want 1", got)
		}
	})
}

// TestResponseHandlerBlockRefusesWithRuleID pins the response-scoped Block:
// a 502 naming the rule id, the upstream bytes discarded, and both the
// content-policy and the rule-block counters moved.
func TestResponseHandlerBlockRefusesWithRuleID(t *testing.T) {
	upstreamBody := []byte(`{"message":"UPSTREAM-SECRET"}`)
	evaluator := &scriptedEvaluator{decision: ResponseDecision{Action: ResponseBlock, RuleIDs: []string{"custom-block-rule"}}}
	backfills := &recordingBackfiller{}
	warnings := &recordingWarnings{}
	counters := NewCounters()
	handler := NewResponseHandler(ResponseConfig{
		Evaluator:  evaluator,
		Backfiller: backfills,
		Counters:   counters,
		Warnings:   warnings,
	})

	status, header, body, err := handler.Handle(upstreamResponse(http.StatusOK, "gzip", encodeGzip(t, upstreamBody)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", status)
	}
	if !strings.Contains(string(body), "custom-block-rule") {
		t.Errorf("refusal body = %q, want the rule id", body)
	}
	if !strings.Contains(string(body), "rule_blocked") {
		t.Errorf("refusal body = %q, want the rule_blocked reason", body)
	}
	if bytes.Contains(body, upstreamBody) || bytes.Contains(body, []byte("UPSTREAM-SECRET")) {
		t.Errorf("refusal body carries the upstream bytes: %q", body)
	}
	if header.Get("Content-Type") != "application/json" {
		t.Errorf("refusal Content-Type = %q, want application/json", header.Get("Content-Type"))
	}
	if got := counters.ContentPolicyBlocks(); got != 1 {
		t.Errorf("content_policy_blocks = %d, want 1", got)
	}
	if got := counters.RuleBlocks(); got != 1 {
		t.Errorf("rule_blocks = %d, want 1", got)
	}
	if got := counters.WalkSkips(); got != 0 {
		t.Errorf("walk_skips = %d, want 0", got)
	}
	if got := backfills.seen(); len(got) != 0 {
		t.Errorf("backfill saw the discarded upstream bytes: %q", got)
	}
	if got := warnings.seen(); len(got) != 0 {
		t.Errorf("warnings = %q, want none on a block", got)
	}
}

// TestResponseHandlerUndefinedActionFailsClosed pins that an action outside
// the client-bound contract (including redact, which only the request phase
// may apply) is refused, never passed through.
func TestResponseHandlerUndefinedActionFailsClosed(t *testing.T) {
	for _, action := range []ResponseAction{"", "redact", "bogus"} {
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{
			Evaluator: &scriptedEvaluator{decision: ResponseDecision{Action: action, RuleIDs: []string{"weird-rule"}}},
			Counters:  counters,
		})

		status, _, body, err := handler.Handle(upstreamResponse(http.StatusOK, "", []byte(responsePayload)))
		if err != nil {
			t.Fatalf("action %q: Handle: %v", action, err)
		}
		if status != http.StatusBadGateway {
			t.Errorf("action %q: status = %d, want 502", action, status)
		}
		if !strings.Contains(string(body), "weird-rule") {
			t.Errorf("action %q: refusal body = %q, want the rule id", action, body)
		}
		if counters.ContentPolicyBlocks() != 1 || counters.RuleBlocks() != 1 {
			t.Errorf("action %q: counters = content:%d rule:%d, want 1 and 1",
				action, counters.ContentPolicyBlocks(), counters.RuleBlocks())
		}
	}
}

// TestResponseHandlerWarnForwardsUnchanged pins the response-scoped Warn: the
// response is forwarded unchanged, one metadata-only warning line names the
// rule, and no counter moves.
func TestResponseHandlerWarnForwardsUnchanged(t *testing.T) {
	payload := []byte(responsePayload)
	t.Run("unchanged bytes and one warning line", func(t *testing.T) {
		warnings := &recordingWarnings{}
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{
			Evaluator: &scriptedEvaluator{decision: ResponseDecision{Action: ResponseWarn, RuleIDs: []string{"warn-rule"}}},
			Counters:  counters,
			Warnings:  warnings,
		})

		status, _, body, err := handler.Handle(upstreamResponse(http.StatusOK, "gzip", encodeGzip(t, payload)))
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
		if !bytes.Equal(body, payload) {
			t.Errorf("body = %q, want the unchanged %q", body, payload)
		}
		lines := warnings.seen()
		if len(lines) != 1 {
			t.Fatalf("warning lines = %q, want exactly one", lines)
		}
		if !strings.Contains(lines[0], "warn-rule") || !strings.Contains(lines[0], "response warn") {
			t.Errorf("warning line = %q, want the phase and the rule id", lines[0])
		}
		if strings.Contains(lines[0], "hello") {
			t.Errorf("warning line = %q, want metadata only", lines[0])
		}
		if counters.ContentPolicyBlocks() != 0 || counters.RuleBlocks() != 0 || counters.WalkSkips() != 0 {
			t.Errorf("warn moved a counter: content=%d rule=%d walk=%d",
				counters.ContentPolicyBlocks(), counters.RuleBlocks(), counters.WalkSkips())
		}
	})

	t.Run("a hostile rule id cannot inject a second line", func(t *testing.T) {
		warnings := &recordingWarnings{}
		handler := NewResponseHandler(ResponseConfig{
			Evaluator: &scriptedEvaluator{decision: ResponseDecision{Action: ResponseWarn, RuleIDs: []string{"evil\nforged line"}}},
			Counters:  NewCounters(),
			Warnings:  warnings,
		})

		if _, _, _, err := handler.Handle(upstreamResponse(http.StatusOK, "", payload)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
		lines := warnings.seen()
		if len(lines) != 1 {
			t.Fatalf("warning lines = %q, want exactly one", lines)
		}
		if strings.Contains(lines[0], "\n") {
			t.Errorf("warning line %q contains a newline", lines[0])
		}
	})

	t.Run("a nil warning writer is inert", func(t *testing.T) {
		handler := NewResponseHandler(ResponseConfig{
			Evaluator: &scriptedEvaluator{decision: ResponseDecision{Action: ResponseWarn, RuleIDs: []string{"warn-rule"}}},
			Counters:  NewCounters(),
		})
		if _, _, _, err := handler.Handle(upstreamResponse(http.StatusOK, "", payload)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	})
}

// TestResponseHandlerIdentityEncodingsPassThrough pins the accepted side:
// absent or all-identity declarations pass through untouched, header included,
// and are still evaluated and backfilled.
func TestResponseHandlerIdentityEncodingsPassThrough(t *testing.T) {
	for _, encoding := range []string{"", "identity", "Identity", "identity, identity"} {
		t.Run("encoding="+encoding, func(t *testing.T) {
			evaluator := allowEvaluator()
			handler := NewResponseHandler(ResponseConfig{Evaluator: evaluator, Counters: NewCounters()})

			status, header, body, err := handler.Handle(upstreamResponse(http.StatusOK, encoding, []byte(responsePayload)))
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if status != http.StatusOK {
				t.Errorf("status = %d, want 200", status)
			}
			if !bytes.Equal(body, []byte(responsePayload)) {
				t.Errorf("body = %q, want the untouched %q", body, responsePayload)
			}
			if got := header.Get("Content-Encoding"); got != encoding {
				t.Errorf("Content-Encoding = %q, want the untouched %q", got, encoding)
			}
			if seen := evaluator.seen(); len(seen) != 1 || !bytes.Equal(seen[0], []byte(responsePayload)) {
				t.Errorf("evaluator saw %q, want the body exactly once", seen)
			}
		})
	}
}

// failingReader yields data once and then fails, so a test can prove a
// partially read upstream body is discarded.
type failingReader struct {
	data []byte
	read bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, errors.New("connection reset")
	}
	r.read = true
	return copy(p, r.data), nil
}

// TestResponseHandlerReadFailureRefuses pins that a body the gateway cannot
// read at all is a 502 with the partial bytes discarded, not a partial
// pass-through.
func TestResponseHandlerReadFailureRefuses(t *testing.T) {
	secret := []byte("UPSTREAM-SECRET")
	counters := NewCounters()
	handler := NewResponseHandler(ResponseConfig{Counters: counters})

	upstream := upstreamResponse(http.StatusOK, "", nil)
	upstream.Body = io.NopCloser(&failingReader{data: secret})

	status, _, body, err := handler.Handle(upstream)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", status)
	}
	if bytes.Contains(body, secret) {
		t.Errorf("refusal body carries partial upstream bytes: %q", body)
	}
	if counters.ContentPolicyBlocks() != 0 || counters.RuleBlocks() != 0 || counters.WalkSkips() != 0 {
		t.Errorf("read failure moved a content counter")
	}
}

// TestResponseHandlerNilSeamsAreInert pins the constructor's documented
// defaults: no evaluator, no backfiller, no counters and no warning writer is
// still a working handler over an empty counter set.
func TestResponseHandlerNilSeamsAreInert(t *testing.T) {
	handler := NewResponseHandler(ResponseConfig{})

	status, header, body, err := handler.Handle(upstreamResponse(http.StatusOK, "", []byte(responsePayload)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if status != http.StatusOK || !bytes.Equal(body, []byte(responsePayload)) {
		t.Errorf("status/body = %d/%q, want the untouched 200 %q", status, body, responsePayload)
	}
	if got := header.Get("Content-Length"); got != strconv.Itoa(len(responsePayload)) {
		t.Errorf("Content-Length = %q, want %d", got, len(responsePayload))
	}
	if handler.counters == nil {
		t.Fatal("NewResponseHandler left a nil counter set")
	}
	if got := handler.counters.WalkSkips(); got != 0 {
		t.Errorf("walk_skips = %d, want 0", got)
	}

	upstream := upstreamResponse(http.StatusOK, "", nil)
	upstream.Body = nil
	if status, _, body, err = handler.Handle(upstream); err != nil {
		t.Fatalf("Handle with a nil body: %v", err)
	}
	if status != http.StatusOK || len(body) != 0 {
		t.Errorf("nil body: status/body = %d/%q, want 200 with no body", status, body)
	}

	if _, _, _, err := handler.Handle(nil); !errors.Is(err, ErrNilResponse) {
		t.Errorf("Handle(nil) error = %v, want ErrNilResponse", err)
	}
}

// TestCountersAreMetadataOnlyTotals pins the frozen counter names: each
// accessor reports its own monotonic total, a nil set reads as zero, and the
// unexported increment helpers are nil-safe.
func TestCountersAreMetadataOnlyTotals(t *testing.T) {
	var nilSet *Counters
	nilSet.countRequest()
	nilSet.countRedaction()
	nilSet.countContentPolicyBlock()
	nilSet.countRuleBlock()
	nilSet.countWalkSkip()
	for name, got := range map[string]int64{
		"Requests":            nilSet.Requests(),
		"Redactions":          nilSet.Redactions(),
		"ContentPolicyBlocks": nilSet.ContentPolicyBlocks(),
		"RuleBlocks":          nilSet.RuleBlocks(),
		"WalkSkips":           nilSet.WalkSkips(),
	} {
		if got != 0 {
			t.Errorf("nil set %s = %d, want 0", name, got)
		}
	}

	counters := NewCounters()
	counters.countRequest()
	counters.countRedaction()
	counters.countContentPolicyBlock()
	counters.countRuleBlock()
	counters.countWalkSkip()
	for name, got := range map[string]int64{
		"Requests":            counters.Requests(),
		"Redactions":          counters.Redactions(),
		"ContentPolicyBlocks": counters.ContentPolicyBlocks(),
		"RuleBlocks":          counters.RuleBlocks(),
		"WalkSkips":           counters.WalkSkips(),
	} {
		if got != 1 {
			t.Errorf("%s = %d, want 1", name, got)
		}
	}
}

// TestQAW45Happy is the W4.5 QA happy path: a gzipped JSON response is
// decoded, evaluated and backfilled.
func TestQAW45Happy(t *testing.T) {
	placeholder := []byte("__PII_api_key_cafebabe__")
	payload := append([]byte(`{"message":"hello","api_key":"`), placeholder...)
	payload = append(payload, []byte(`"}`)...)

	evaluator := allowEvaluator()
	counters := NewCounters()
	handler := NewResponseHandler(ResponseConfig{
		Evaluator: evaluator,
		Backfiller: &recordingBackfiller{rewrite: func(body []byte) []byte {
			return bytes.ReplaceAll(body, placeholder, []byte("sk-restored"))
		}},
		Counters: counters,
	})

	status, header, body, err := handler.Handle(upstreamResponse(http.StatusOK, "gzip", encodeGzip(t, payload)))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	t.Logf("QA happy: status=%d content_encoding=%q evaluated=%q body=%s", status, header.Get("Content-Encoding"), evaluator.seen(), body)
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if header.Get("Content-Encoding") != "" {
		t.Errorf("Content-Encoding = %q, want removed", header.Get("Content-Encoding"))
	}
	if !bytes.Contains(body, []byte("sk-restored")) {
		t.Errorf("body = %q, want the restored secret", body)
	}
	if len(evaluator.seen()) != 1 {
		t.Errorf("evaluator calls = %d, want 1", len(evaluator.seen()))
	}
}

// TestQAW45Failure is the W4.5 QA failure sweep: an unsupported coding, a
// corrupt stream, a plain-text walk failure and a response-scoped Block.
func TestQAW45Failure(t *testing.T) {
	t.Run("br is refused", func(t *testing.T) {
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{Counters: counters})
		status, _, body, err := handler.Handle(upstreamResponse(http.StatusOK, "br", []byte("opaque")))
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		t.Logf("QA failure: encoding=br status=%d body=%s content_blocks=%d rule_blocks=%d",
			status, body, counters.ContentPolicyBlocks(), counters.RuleBlocks())
		if status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", status)
		}
	})

	t.Run("invalid gzip is refused", func(t *testing.T) {
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{Counters: counters})
		status, _, body, err := handler.Handle(upstreamResponse(http.StatusOK, "gzip", []byte("definitely not gzip")))
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		t.Logf("QA failure: encoding=gzip stream=invalid status=%d body=%s", status, body)
		if status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", status)
		}
	})

	t.Run("a plain-text error body is forwarded byte-identically", func(t *testing.T) {
		plain := []byte("upstream error: rate limited\n")
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{
			Evaluator: &scriptedEvaluator{err: errors.New("walk: not JSON")},
			Counters:  counters,
		})
		status, _, body, err := handler.Handle(upstreamResponse(http.StatusTooManyRequests, "", plain))
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		t.Logf("QA failure: plain_text status=%d identical=%v walk_skips=%d", status, bytes.Equal(body, plain), counters.WalkSkips())
		if !bytes.Equal(body, plain) {
			t.Errorf("body = %q, want the byte-identical %q", body, plain)
		}
		if counters.WalkSkips() != 1 {
			t.Errorf("walk_skips = %d, want 1", counters.WalkSkips())
		}
	})

	t.Run("a response-scoped Block names the rule id", func(t *testing.T) {
		counters := NewCounters()
		handler := NewResponseHandler(ResponseConfig{
			Evaluator: &scriptedEvaluator{decision: ResponseDecision{Action: ResponseBlock, RuleIDs: []string{"qa-block-rule"}}},
			Counters:  counters,
		})
		status, _, body, err := handler.Handle(upstreamResponse(http.StatusOK, "gzip", encodeGzip(t, []byte(`{"secret":"leak-me"}`))))
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		t.Logf("QA failure: response_block status=%d body=%s content_blocks=%d rule_blocks=%d",
			status, body, counters.ContentPolicyBlocks(), counters.RuleBlocks())
		if status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", status)
		}
		if !strings.Contains(string(body), "qa-block-rule") {
			t.Errorf("body = %q, want the rule id", body)
		}
		if bytes.Contains(body, []byte("leak-me")) {
			t.Errorf("body = %q, want the upstream bytes discarded", body)
		}
	})
}
