package proxy

// T6 boundary / invariant / incremental-delivery coverage for the SSE-aware
// inbound backfiller. The fix-verifying regressions already live in
// inbound_backfill_test.go, ssebackfill_test.go and ssebackfill_probe_test.go;
// this file adds the cases those do not cover and states, in one place, which
// of the plan's T6 list were pre-covered:
//
//	T6#1  non-JSON data: split across chunks  -> pre-covered
//	     (TestSSEBackfillerRawData/split_across_records,
//	      TestPipelineSSEBackfillAcrossChunks)
//	T6#8  br -> 502, no Content-Encoding, no upstream bytes -> pre-covered
//	     (TestPipelineUndecodableEncodingFailsClosed)
//	T6#11 invariant regressions -> pre-covered
//	     (TestPipelinePlaceholderLiteralNotBackfilled,
//	      TestNeverBackfillOutbound)
//
// Everything else is added here. Case #3 is explicitly a boundary/negative
// case: it passes before the fix and is NOT fix-verifying.

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// t6Event frames one SSE record with an explicit data payload.
func t6Event(payload string) string { return "data: " + payload + "\n\n" }

// t6StreamSSE starts an upstream that writes every event and flushes after
// each one, so a client can observe them incrementally.
func t6StreamSSE(t *testing.T, events ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		for _, ev := range events {
			if _, err := io.WriteString(w, ev); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// t6ClientBody drives one GET through the pipeline and returns the client body.
func t6ClientBody(t *testing.T, pipe *Pipeline, upstream string) []byte {
	t.Helper()
	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream, pipe)))
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	return body
}

// TestSSEBackfillerRestoresAcrossProviderDeltaPaths is T6#2: a placeholder split
// across events must be restored for the Anthropic `/delta/text` and
// `/delta/thinking` leaves and the Responses `/delta` leaf. Leaf selection is
// path-agnostic, so every provider shape is covered by one table.
func TestSSEBackfillerRestoresAcrossProviderDeltaPaths(t *testing.T) {
	cases := []struct {
		name string
		tmpl string
	}{
		{"anthropic_text", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`},
		{"anthropic_thinking", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":%q}}`},
		{"responses_delta", `{"type":"response.output_text.delta","delta":%q}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fragments := []string{t4Placeholder[:5], t4Placeholder[5:17], t4Placeholder[17:]}
			var in strings.Builder
			for _, f := range fragments {
				in.WriteString(t6Event(fmt.Sprintf(tc.tmpl, f)))
			}
			var want strings.Builder
			for range fragments[:len(fragments)-1] {
				want.WriteString(t6Event(fmt.Sprintf(tc.tmpl, "")))
			}
			want.WriteString(t6Event(fmt.Sprintf(tc.tmpl, t4Secret)))

			got := t4Run(t, []byte(in.String()))
			if !bytes.Equal(got, []byte(want.String())) {
				t.Fatalf("%s split:\n got %q\nwant %q", tc.name, got, want.String())
			}
			if !bytes.Contains(got, []byte(t4Secret)) {
				t.Errorf("%s: secret was not restored: %q", tc.name, got)
			}
			if bytes.Contains(got, []byte(protocol.PlaceholderPrefix)) {
				t.Errorf("%s: output still carries a placeholder: %q", tc.name, got)
			}
		})
	}
}

// TestPipelineCrossPathSplitStaysLiteral is T6#3, explicitly a boundary/negative
// case (it passes before the fix and is not fix-verifying): the two halves of a
// placeholder carried in DIFFERENT JSON paths must never be joined. The client
// must see the two literal fragments, no secret, and byte-identical framing.
func TestPipelineCrossPathSplitStaysLiteral(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	placeholder := engine.Placeholder(secret, "api_key")
	if len(placeholder) < 12 {
		t.Fatalf("placeholder too short to split across paths: %q", placeholder)
	}
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	fragA, fragB := placeholder[:9], placeholder[9:]
	events := []string{
		t6Event(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + fragA + `"}}`),
		t6Event(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"` + fragB + `"}}`),
	}
	input := strings.Join(events, "")

	body := t6ClientBody(t, pipe, t6StreamSSE(t, events...).URL)

	if !bytes.Equal(body, []byte(input)) {
		t.Errorf("cross-path split was rewritten:\n got %q\nwant %q", body, input)
	}
	if !bytes.Contains(body, []byte(fragA)) || !bytes.Contains(body, []byte(fragB)) {
		t.Errorf("literal fragments were lost: %q", body)
	}
	if bytes.Contains(body, []byte(secret)) {
		t.Errorf("cross-path split leaked a secret: %q", body)
	}
}

// TestSSEBackfillerCompletesPlaceholderInUnterminatedFinalEvent is T6#4: the
// completing fragment arrives in the final record, which has no trailing blank
// line and is therefore surfaced only by Close(). The secret must still be
// restored and the missing terminator preserved.
func TestSSEBackfillerCompletesPlaceholderInUnterminatedFinalEvent(t *testing.T) {
	head := t6Event(`{"delta":{"content":"` + t4Placeholder[:6] + `"}}`) // "__PII_", no completion
	tail := `data: {"delta":{"content":"` + t4Placeholder[6:] + `"}}`    // completion, no blank line
	if strings.Contains(tail, "\n\n") {
		t.Fatal("fixture error: the final record must not be terminated")
	}

	got := t4Run(t, []byte(head+tail))
	want := t6Event(`{"delta":{"content":""}}`) + `data: {"delta":{"content":"` + t4Secret + `"}}`
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("Close-path completion:\n got %q\nwant %q", got, want)
	}
	if !bytes.HasSuffix(got, []byte(t4Secret+`"}}`)) {
		t.Errorf("final record lost its terminator semantics: %q", got)
	}
	if bytes.Contains(got, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("output still carries a placeholder: %q", got)
	}
}

// TestSSEBackfillerMultiplePlaceholdersAndUncompletableTail is T6#5: a field
// carrying several placeholders backfills each one, and an opening followed by
// a long literal with no closing suffix is proven uncompletable and emitted
// verbatim instead of being withheld forever.
func TestSSEBackfillerMultiplePlaceholdersAndUncompletableTail(t *testing.T) {
	const maxLen = 32
	firstPlaceholder, firstSecret := t4Placeholder, t4Secret
	secondPlaceholder, secondSecret := "__PII_api_key_0011223344556677__", "sk-second-secret-0000"
	replace := func(token string) string {
		switch token {
		case firstPlaceholder:
			return firstSecret
		case secondPlaceholder:
			return secondSecret
		default:
			return token
		}
	}
	uncompletable := protocol.PlaceholderPrefix + strings.Repeat("x", 60)
	content := firstPlaceholder + " plus " + secondPlaceholder + " then " + uncompletable
	input := []byte(t6Event(fmt.Sprintf(`{"delta":{"content":%q}}`, content)))

	var dst bytes.Buffer
	b := newSSEBackfiller(&dst, maxLen, replace)
	if _, err := b.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	got := dst.Bytes()

	if !bytes.Contains(got, []byte(firstSecret)) || !bytes.Contains(got, []byte(secondSecret)) {
		t.Errorf("a placeholder in a multi-placeholder field was not restored: %q", got)
	}
	if bytes.Contains(got, []byte(firstPlaceholder)) || bytes.Contains(got, []byte(secondPlaceholder)) {
		t.Errorf("a known placeholder survived backfill: %q", got)
	}
	if !bytes.Contains(got, []byte(uncompletable)) {
		t.Errorf("the proven-uncompletable literal was altered or withheld: %q", got)
	}
}

// TestSSEBackfillerUnknownPlaceholderSplitsAcrossEvents is gap A (the T4
// verifier's critical safety regression): a placeholder-shaped token the engine
// does NOT know is split across events, and a following event changes a
// non-delta field. Because the replacement equals the token, `changed` must stay
// false: the unknown token passes through verbatim and NO redistribution or
// merge occurs. The output must be byte-identical to the input.
func TestSSEBackfillerUnknownPlaceholderSplitsAcrossEvents(t *testing.T) {
	input := []byte(
		t6Event(`{"delta":{"content":"__PII_unk"}}`) +
			t6Event(`{"delta":{"content":"nown_zzz__"}}`) +
			t6Event(`{"model":"gpt-4o"}`),
	)
	got := t4Run(t, input)
	if !bytes.Equal(got, input) {
		t.Fatalf("unknown token triggered a rewrite:\n got %q\nwant %q", got, input)
	}
	if !bytes.Contains(got, []byte("__PII_unk")) || !bytes.Contains(got, []byte("nown_zzz__")) {
		t.Errorf("unknown token fragments were not preserved verbatim: %q", got)
	}
	if bytes.Contains(got, []byte("__PII_unknown_zzz__")) {
		t.Errorf("split unknown token was merged into a contiguous token: %q", got)
	}
}

// TestSSEBackfillerMultiLineDataWithPlaceholderIsPassthrough is the adversarial
// malformed_input probe: a multi-line `data:` payload (DataSingle false) is never
// rewritten even when it carries placeholder-shaped bytes, so the stream stays
// byte-identical (the same holds for a colon-less `data` line, already locked by
// TestSSEBackfillerMalformedPassthrough).
func TestSSEBackfillerMultiLineDataWithPlaceholderIsPassthrough(t *testing.T) {
	input := []byte(
		"data: {\"delta\":{\"content\":\"" + t4Placeholder[:10] + "\"}\n" +
			"data: {\"delta\":{\"content\":\"" + t4Placeholder[10:] + "\"}}\n" +
			"\n",
	)
	got := t4Run(t, input)
	if !bytes.Equal(got, input) {
		t.Fatalf("multi-line data was modified:\n got %q\nwant %q", got, input)
	}
	if bytes.Contains(got, []byte(t4Secret)) {
		t.Errorf("multi-line data leaked the secret: %q", got)
	}
}

// TestPipelineDeflateResponseBackfilled is T6#6: a zlib-wrapped `deflate`
// response is decompressed correctly and then backfilled. Go's transport never
// auto-decompresses deflate, so this reaches the core decoder for real.
func TestPipelineDeflateResponseBackfilled(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	placeholder := engine.Placeholder(secret, "api_key")
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	plain := fmt.Appendf(nil, `{"echo":%q}`, placeholder)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	deflated := buf.Bytes()
	if len(deflated) < 2 || deflated[0] != 0x78 || (int(deflated[0])<<8|int(deflated[1]))%31 != 0 {
		t.Fatalf("deflate fixture is not zlib-framed (header % x)", deflated[:2])
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "deflate")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(deflated)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %q", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(secret)) {
		t.Errorf("deflate response was not backfilled to the secret: %q", body)
	}
	if bytes.Contains(body, []byte(protocol.PlaceholderPrefix)) {
		t.Errorf("deflate response still carries a placeholder: %q", body)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("decoded response kept Content-Encoding = %q, want it removed", enc)
	}
}

// TestPipelineMultiValuedEncodingFailsClosed is T6#7: a multi-valued
// Content-Encoding on one header line (`gzip, br`) carries an undecodable coding,
// so it must fail closed like a bare `br`. The single-line spelling is the one
// reachable through the default transport: Go's client auto-decompresses only a
// lone exact `gzip` value and otherwise leaves the header intact.
func TestPipelineMultiValuedEncodingFailsClosed(t *testing.T) {
	upstreamBody := []byte("multi-valued-encoding-payload-that-must-not-reach-the-client")
	engine := w45Engine(t)
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip, br")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502; body %q", resp.StatusCode, body)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("fail-closed response kept Content-Encoding = %q, want it removed", enc)
	}
	if bytes.Contains(body, upstreamBody) {
		t.Errorf("fail-closed response leaked upstream bytes: %q", body)
	}
}

// TestClassifyContentEncodingMultiValued pins the classifier directly: a
// multi-valued header (one comma-joined line or two header lines) with any
// non-decodable coding is unsupported, and a comma-joined gzip+deflate pair is
// decodable. This is the unit-level counterpart of T6#7, reachable without the
// transport's own decompression.
func TestClassifyContentEncodingMultiValued(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		want   contentEncoding
	}{
		{"comma_joined_undecodable", http.Header{"Content-Encoding": {"gzip, br"}}, encodingUnsupported},
		{"two_lines_undecodable", http.Header{"Content-Encoding": {"gzip", "br"}}, encodingUnsupported},
		{"comma_joined_decodable", http.Header{"Content-Encoding": {"gzip, deflate"}}, encodingDecodable},
		{"identity_only", http.Header{"Content-Encoding": {"identity"}}, encodingIdentity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyContentEncoding(tc.header); got != tc.want {
				t.Fatalf("classifyContentEncoding(%v) = %d, want %d", tc.header.Values("Content-Encoding"), got, tc.want)
			}
		})
	}
}

// TestPipelineRangeRequestDoesNotGzipUpstream is T6#9: under a Range request the
// Go transport must not self-inject `Accept-Encoding: gzip`. The with-Range case
// asserts the upstream sees no compression token; the no-Range control proves
// the assertion is non-vacuous by showing the transport does inject gzip there.
func TestPipelineRangeRequestDoesNotGzipUpstream(t *testing.T) {
	run := func(t *testing.T, rangeHeader string) string {
		t.Helper()
		engine := w45Engine(t)
		pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

		var mu sync.Mutex
		var seen string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = r.Header.Get("Accept-Encoding")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		}))
		t.Cleanup(upstream.Close)

		srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
		t.Cleanup(srv.Close)

		req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/messages", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("through proxy: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.ReadAll(resp.Body)

		mu.Lock()
		defer mu.Unlock()
		return seen
	}

	t.Run("with_range_no_gzip", func(t *testing.T) {
		got := run(t, "bytes=0-1")
		if strings.Contains(got, "gzip") || strings.Contains(got, "deflate") || strings.Contains(got, "br") {
			t.Errorf("Range request advertised compression to the upstream: %q", got)
		}
	})

	t.Run("without_range_control_transport_injects_gzip", func(t *testing.T) {
		got := run(t, "")
		if !strings.Contains(got, "gzip") {
			t.Errorf("control: transport did not self-inject gzip (%q), so the Range assertion is vacuous", got)
		}
	})
}

// TestPipelineConcurrentStreamsShareEngine is T6#10: several SSE streams, each
// restoring its own placeholder, run concurrently through pipelines that share
// one PlaceholderEngine. Run under -race this exercises the engine's concurrency
// contract end to end.
func TestPipelineConcurrentStreamsShareEngine(t *testing.T) {
	const workers = 8
	secret := w45Secret()
	engine := w45Engine(t)
	placeholder := engine.Placeholder(secret, "api_key")
	if len(placeholder) < 16 {
		t.Fatalf("placeholder too short to split: %q", placeholder)
	}
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_, _ = io.WriteString(w, t6Event(`{"delta":{"content":"`+placeholder[:8]+`"}}`))
		_ = rc.Flush()
		_, _ = io.WriteString(w, t6Event(`{"delta":{"content":"`+placeholder[8:]+`"}}`))
		_ = rc.Flush()
	}))
	t.Cleanup(upstream.Close)

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := srv.Client().Get(srv.URL + "/v1/messages")
			if err != nil {
				errs <- fmt.Errorf("worker GET: %w", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- fmt.Errorf("worker read: %w", err)
				return
			}
			if !bytes.Contains(body, []byte(secret)) {
				errs <- fmt.Errorf("worker stream lost the secret: %q", body)
				return
			}
			if bytes.Contains(body, []byte(protocol.PlaceholderPrefix)) {
				errs <- fmt.Errorf("worker stream still carries a placeholder: %q", body)
				return
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

// TestSSEBackfillerHoldbackBoundEnforcedFromConstant is T6#12: the cumulative
// holdback cap must force-flush mid-Write instead of retaining an unbounded
// number of held events. The fixture size is derived from
// sseBackfillMaxHoldbackBytes (never a hardcoded different value).
func TestSSEBackfillerHoldbackBoundEnforcedFromConstant(t *testing.T) {
	if sseBackfillMaxHoldbackBytes <= 0 {
		t.Fatalf("sseBackfillMaxHoldbackBytes = %d, want a positive bound", sseBackfillMaxHoldbackBytes)
	}
	// Each event's leaf content is a lone `_`, which keeps the path window open
	// (a `_` may start `__PII_`) without ever completing a token, so every event
	// is held until the cap trips.
	const event = "data: {\"delta\":{\"content\":\"_\"}}\n\n"
	count := sseBackfillMaxHoldbackBytes/len(event) + 2
	input := []byte(strings.Repeat(event, count))
	if len(input) <= sseBackfillMaxHoldbackBytes {
		t.Fatalf("fixture is %d bytes, not above the %d-byte cap", len(input), sseBackfillMaxHoldbackBytes)
	}

	var dst bytes.Buffer
	b := newSSEBackfiller(&dst, 128, t4Replace)
	if _, err := b.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if dst.Len() == 0 {
		t.Fatalf("cap %d was not enforced: nothing was emitted during Write", sseBackfillMaxHoldbackBytes)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), input) {
		t.Fatalf("force-flushed output differs from input (len got %d, want %d)", dst.Len(), len(input))
	}
}

// TestPipelineSSEIncrementalDeliveryBeforeEOF is T6#13: the upstream keeps the
// connection open, writes one complete event and flushes. The client must
// RECEIVE that event within a bounded (generous) timeout, proving the pipeline
// streams incrementally rather than buffering the whole stream until EOF.
func TestPipelineSSEIncrementalDeliveryBeforeEOF(t *testing.T) {
	secret := w45Secret()
	engine := w45Engine(t)
	placeholder := engine.Placeholder(secret, "api_key")
	pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})

	release := make(chan struct{})
	var once sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_, _ = io.WriteString(w, t6Event(`{"delta":{"content":"`+placeholder+`"}}`))
		_ = rc.Flush()
		<-release // hold the connection open: no EOF for the client
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() { once.Do(func() { close(release) }) })

	srv := httptest.NewServer(pipe.ResponseMiddleware(w45Forwarder(t, upstream.URL, pipe)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/v1/messages")
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	type chunk struct {
		data []byte
	}
	got := make(chan chunk, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		got <- chunk{data: append([]byte(nil), buf[:n]...)}
	}()

	select {
	case c := <-got:
		if !bytes.Contains(c.data, []byte(secret)) {
			t.Errorf("first flushed chunk did not carry the backfilled event: %q", c.data)
		}
		if !bytes.Contains(c.data, []byte("\n\n")) {
			t.Errorf("first flushed chunk is not a complete SSE event: %q", c.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not receive the flushed SSE event before EOF (stream was buffered)")
	}
}
