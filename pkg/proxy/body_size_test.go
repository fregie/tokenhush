package proxy

// body_size_test.go pins group A of the request body-size guard: a request
// whose body exceeds pkg/config's default cap (config.MaxBodyBytes, 64 MiB) is
// refused explicitly with 403 body_too_large and zero upstream dials on both
// read paths, while a body exactly at the cap is admitted byte-for-byte. The
// guard does not exist yet, so every case below is RED and fails by assertion.
//
// The cap is always the default config.MaxBodyBytes, reached through existing
// construction -- no DataPlaneConfig field and no forwarder option -- so these
// tests outlive the removal of the aggregate scan-budget gate.
//
// A6 is unit-level by design: Go's HTTP server caps r.Body at the declared
// Content-Length, so a lying Content-Length is observable only when the
// handler is called directly. The real production shape, chunked with no
// Content-Length at all, is covered alongside it.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
)

// sizedBody streams a body of exactly Total bytes without the test process
// materialising a second copy of a 64 MiB payload. JSON shapes it as one
// walkable document ({"message":"<fill>"}); otherwise it is a flat run of
// non-JSON bytes.
type sizedBody struct {
	Total int64
	JSON  bool
	read  int64
}

// Read implements io.Reader.
func (b *sizedBody) Read(p []byte) (int, error) {
	if b.read >= b.Total {
		return 0, io.EOF
	}
	if !b.JSON {
		n := 0
		for n < len(p) && b.read < b.Total {
			p[n] = 'x'
			n++
			b.read++
		}
		return n, nil
	}
	const prefix = `{"message":"`
	const suffix = `"}`
	fillEnd := b.Total - int64(len(suffix))
	n := 0
	for n < len(p) && b.read < b.Total {
		switch {
		case b.read < int64(len(prefix)):
			p[n] = prefix[b.read]
		case b.read >= fillEnd:
			p[n] = suffix[b.read-fillEnd]
		default:
			p[n] = 'a'
		}
		n++
		b.read++
	}
	return n, nil
}

// overCapJSONBody returns a fresh streamed valid-JSON body one byte over the
// default cap.
func overCapJSONBody() *sizedBody {
	return &sizedBody{Total: config.MaxBodyBytes + 1, JSON: true}
}

// TestBodySizeGuard covers group A of the body-size guard. Every subtest is
// RED today: the guard does not exist, so the over-cap cases either fall
// through to the aggregate scan-budget gate (403 scan_budget_exceeded) or
// reach the upstream, and the at-cap case is refused by that same gate.
func TestBodySizeGuard(t *testing.T) {
	t.Run("A1_declared_content_length_over_cap_is_refused_without_reading_the_body", func(t *testing.T) {
		// Given a small walkable JSON body behind a declared length over the cap.
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: allowRequestEvaluator()})
		body := &countingBody{data: []byte(`{"message":"hello"}`)}
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"message":"hello"}`))
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = config.MaxBodyBytes + 1
		request.Body = io.NopCloser(body)

		// When the data plane serves it.
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, request)

		// Then the declared length alone refuses it, before any read.
		if got := body.bytesRead(); got != 0 {
			t.Errorf("body bytes read = %d, want 0: a declared over-cap length must be rejected before reading", got)
		}
		fields := requireRefusal(t, response, http.StatusForbidden)
		if fields["error"] != "body_too_large" {
			t.Errorf("refusal error = %q, want body_too_large", fields["error"])
		}
		requireNoUpstream(t, upstream, recorder)
	})

	t.Run("A2_absent_or_chunked_content_length_over_cap_is_refused_at_the_read_seam", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			chunked bool
		}{
			{name: "absent_content_length"},
			{name: "chunked_transfer_encoding", chunked: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// Given a real cap+1 JSON body with no declared length.
				walker := &stubWalker{}
				plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker, Evaluator: allowRequestEvaluator()})
				request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", overCapJSONBody())
				request.Header.Set("Content-Type", "application/json")
				request.ContentLength = -1
				if tc.chunked {
					request.TransferEncoding = []string{"chunked"}
				}

				// When the data plane serves it.
				response := httptest.NewRecorder()
				plane.ServeHTTP(response, request)

				// Then the N+1 read seam refuses explicitly, before any walk.
				fields := requireRefusal(t, response, http.StatusForbidden)
				if fields["error"] != "body_too_large" {
					t.Errorf("refusal error = %q, want body_too_large", fields["error"])
				}
				if got := walker.calls.Load(); got != 0 {
					t.Errorf("walker calls = %d, want 0: an over-cap body is never walked", got)
				}
				requireNoUpstream(t, upstream, recorder)
			})
		}
	})

	t.Run("A3_exactly_at_the_cap_is_admitted", func(t *testing.T) {
		// Given a walkable JSON body of exactly the cap, streamed so the test
		// holds no second copy of the payload; this is the one case that runs
		// the full 64 MiB walk and a real upstream round trip.
		walker := &stubWalker{}
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Walker: walker, Evaluator: allowRequestEvaluator()})
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &sizedBody{Total: config.MaxBodyBytes, JSON: true})
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = config.MaxBodyBytes

		// When the data plane serves it.
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, request)

		// Then it is admitted whole, with the identical byte count upstream.
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 at exactly the cap (body %q)", response.Code, response.Body.String())
		}
		seen := requireUpstream(t, upstream)
		if got := int64(len(seen.body)); got != config.MaxBodyBytes {
			t.Errorf("upstream body length = %d, want the full %d bytes", got, config.MaxBodyBytes)
		}
		if !bytes.HasPrefix(seen.body, []byte(`{"message":"`)) || !bytes.HasSuffix(seen.body, []byte(`"}`)) {
			t.Error("the upstream body is not the intact JSON document")
		}
		if got := walker.calls.Load(); got != 1 {
			t.Errorf("walker calls = %d, want exactly 1", got)
		}
		if got := recorder.count(); got != 1 {
			t.Errorf("upstream dials = %d, want exactly 1", got)
		}
	})

	t.Run("A4_cap_plus_one_is_refused_even_without_declared_json", func(t *testing.T) {
		// Given a real cap+1 body on the non-JSON passthrough path: the cap is
		// a memory guard on the total body, not a walk budget.
		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: allowRequestEvaluator()})
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &sizedBody{Total: config.MaxBodyBytes + 1})
		request.Header.Set("Content-Type", "application/octet-stream")
		request.ContentLength = config.MaxBodyBytes + 1

		// When the data plane serves it.
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, request)

		// Then it is refused with the same explicit shape, never forwarded.
		fields := requireRefusal(t, response, http.StatusForbidden)
		if fields["error"] != "body_too_large" {
			t.Errorf("refusal error = %q, want body_too_large", fields["error"])
		}
		requireNoUpstream(t, upstream, recorder)
	})

	t.Run("A5_valid_document_that_continues_past_the_cap_is_refused_not_truncated", func(t *testing.T) {
		// Given a body whose first cap bytes are a complete valid JSON
		// document and whose tail continues past the cap; no Content-Length is
		// declared, so only the read seam can decide.
		const head, tail = `{"pad":"`, `"}`
		doc := bytes.Repeat([]byte("x"), int(config.MaxBodyBytes))
		copy(doc, head)
		copy(doc[len(doc)-len(tail):], tail)
		body := string(doc) + `"continued"`
		if int64(len(body)) <= config.MaxBodyBytes {
			t.Fatalf("fixture is %d bytes, want more than the %d cap", len(body), config.MaxBodyBytes)
		}

		plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: allowRequestEvaluator()})
		request := dataPlanePost(body, "application/json", true)
		request.ContentLength = -1

		// When the data plane serves it.
		response := httptest.NewRecorder()
		plane.ServeHTTP(response, request)

		// Then the whole request is refused: a guard that read only N bytes
		// would have walked and forwarded the truncated document.
		fields := requireRefusal(t, response, http.StatusForbidden)
		if fields["error"] != "body_too_large" {
			t.Errorf("refusal error = %q, want body_too_large", fields["error"])
		}
		requireNoUpstream(t, upstream, recorder)
	})

	t.Run("A6_unit_level_lying_content_length_and_the_production_chunked_shape", func(t *testing.T) {
		// Unit-level: the handler is called directly here, so r.Body is not
		// capped by the server at the declared length. Go's HTTP server does
		// cap it, so this shape is not a production attack.
		t.Run("unit_level_declared_small_sent_large", func(t *testing.T) {
			plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: allowRequestEvaluator()})
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", overCapJSONBody())
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(`{"message":"x"}`))

			response := httptest.NewRecorder()
			plane.ServeHTTP(response, request)

			fields := requireRefusal(t, response, http.StatusForbidden)
			if fields["error"] != "body_too_large" {
				t.Errorf("refusal error = %q, want body_too_large", fields["error"])
			}
			requireNoUpstream(t, upstream, recorder)
		})

		// The real production shape: chunked, no Content-Length at all.
		t.Run("production_chunked_with_no_content_length", func(t *testing.T) {
			plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: allowRequestEvaluator()})
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", overCapJSONBody())
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = -1
			request.TransferEncoding = []string{"chunked"}

			response := httptest.NewRecorder()
			plane.ServeHTTP(response, request)

			fields := requireRefusal(t, response, http.StatusForbidden)
			if fields["error"] != "body_too_large" {
				t.Errorf("refusal error = %q, want body_too_large", fields["error"])
			}
			requireNoUpstream(t, upstream, recorder)
		})
	})

	t.Run("A7_both_read_paths_share_the_bound", func(t *testing.T) {
		t.Run("data_plane_path", func(t *testing.T) {
			plane, upstream, recorder := dataPlaneHarness(t, DataPlaneConfig{Evaluator: allowRequestEvaluator()})
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", overCapJSONBody())
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = -1

			response := httptest.NewRecorder()
			plane.ServeHTTP(response, request)

			fields := requireRefusal(t, response, http.StatusForbidden)
			if fields["error"] != "body_too_large" {
				t.Errorf("refusal error = %q, want body_too_large", fields["error"])
			}
			requireNoUpstream(t, upstream, recorder)
		})

		t.Run("direct_forwarder_path", func(t *testing.T) {
			upstream := newFakeUpstream(t)
			forwarder, recorder := recordedForwarder(t, upstream, nil)
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", overCapJSONBody())
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = -1

			response := httptest.NewRecorder()
			forwarder.ServeHTTP(response, request)

			if got := recorder.count(); got != 0 {
				t.Errorf("upstream dials = %d, want 0: the forwarder must refuse before dialling", got)
			}
			fields := requireRefusal(t, response, http.StatusForbidden)
			if fields["error"] != "body_too_large" {
				t.Errorf("refusal error = %q, want body_too_large", fields["error"])
			}
		})
	})
}
