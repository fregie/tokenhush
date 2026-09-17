package redact

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// TestHighEntropyStructuralIdentifierExemption pins the Finding-3 precision
// fix: the enumerated provider identifier shapes are skipped whole, while a
// genuine random high-entropy secret with no exempt prefix is still flagged.
func TestHighEntropyStructuralIdentifierExemption(t *testing.T) {
	det := NewHighEntropyDetector()
	genuine := "kR8mQ2vZ9pL4wX7nT1bY6cH3jF5dS0aG"

	cases := []detectorCase{
		{name: "openai_tool_call_id", content: "id call_01aZbYcXdWeVfUgThSiJkLmNoP end"},
		{name: "anthropic_tool_use_id", content: "id toolu_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "openai_completion_id", content: "id chatcmpl-9xQ2mZpR7tLkWvB4nHsDfGjK end"},
		{name: "anthropic_message_id", content: "id msg_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "openai_response_id", content: "id resp_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "request_id", content: "id req_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "trace_id", content: "id trace_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "span_id", content: "id span_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "run_id", content: "id run_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "job_id", content: "id job_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "build_id", content: "id build_01A9xQ2mZpR7tLkWvB4nHsDfGj end"},
		{name: "random_secret_without_prefix_still_flagged", content: "token " + genuine + " end", found: []string{genuine}},
		{name: "exempt_prefix_random_stem_is_the_recorded_gap", content: "id call_" + genuine + " end"},
	}
	runDetectorCases(t, det, typeHighEntropy, highEntropyConfidence, cases)
}

// TestHighEntropyPrefixedHashExemption pins the SRI / npm-integrity exemption:
// a well-formed `<algo>-<base64>` value is skipped whole (including the
// `?<options>` suffix SRI allows), while a run that merely starts with a hash
// name but is not well-formed stays flagged.
func TestHighEntropyPrefixedHashExemption(t *testing.T) {
	det := NewHighEntropyDetector()
	digest := base64.StdEncoding.EncodeToString([]byte(pseudoRandom(64))) // 88 chars
	sri := "sha512-" + digest
	urlSafe := "sha512-" + pseudoRandom(40) + "_x"

	cases := []detectorCase{
		{name: "sha512_sri_exempt", content: "integrity " + sri},
		{name: "sha256_sri_exempt", content: "integrity sha256-" + base64.StdEncoding.EncodeToString([]byte(pseudoRandom(32)))},
		{name: "md5_sri_exempt", content: "integrity md5-" + base64.StdEncoding.EncodeToString([]byte(pseudoRandom(16)))},
		{name: "blake3_sri_exempt", content: "integrity blake3-" + base64.StdEncoding.EncodeToString([]byte(pseudoRandom(32)))},
		{name: "sri_with_options_suffix_exempt", content: "integrity " + sri + "?foo=bar"},
		{name: "url_safe_body_not_exempt_still_flagged", content: "integrity " + urlSafe, found: []string{urlSafe}},
	}
	runDetectorCases(t, det, typeHighEntropy, highEntropyConfidence, cases)
}

// TestHighEntropyPayloadKeyValueExemption pins the context rule for inline
// payload keys: a base64 run below structuralPayloadMinRun is exempt only when
// it is the string value of an enumerated payload-carrying key, while the same
// run under a generic key stays redacted.
func TestHighEntropyPayloadKeyValueExemption(t *testing.T) {
	det := NewHighEntropyDetector()
	payload := base64.StdEncoding.EncodeToString([]byte(pseudoRandom(90))) // 120 chars, below min
	if len(payload) >= structuralPayloadMinRun {
		t.Fatalf("fixture error: payload is %d bytes, want below %d", len(payload), structuralPayloadMinRun)
	}

	cases := []detectorCase{
		{name: "file_data_key_exempt", content: `{"file_data":"` + payload + `"}`},
		{name: "data_key_exempt", content: `{"data":"` + payload + `"}`},
		{name: "b64_key_exempt", content: `{"b64":"` + payload + `"}`},
		{name: "base64_key_exempt", content: `{"base64":"` + payload + `"}`},
		{name: "blob_key_exempt", content: `{"blob":"` + payload + `"}`},
		{name: "payload_key_exempt", content: `{"payload":"` + payload + `"}`},
		{name: "attachment_key_exempt", content: `{"attachment":"` + payload + `"}`},
		{name: "image_url_key_exempt", content: `{"image_url":"` + payload + `"}`},
		{name: "audio_key_exempt", content: `{"audio":"` + payload + `"}`},
		{name: "content_bytes_key_exempt", content: `{"content_bytes":"` + payload + `"}`},
		{name: "case_insensitive_key_exempt", content: `{"File_Data":"` + payload + `"}`},
		{name: "whitespace_before_value_exempt", content: `{"file_data" : "` + payload + `"}`},
		{name: "generic_key_still_flagged", content: `{"input":"` + payload + `"}`, found: []string{payload}},
		{name: "unquoted_value_not_exempt_still_flagged", content: `{"file_data":` + payload + `}`, found: []string{payload}},
	}
	runDetectorCases(t, det, typeHighEntropy, highEntropyConfidence, cases)
}

// TestHighEntropyPayloadAndArtifactExemptions pins the payload/artifact
// exemptions the F3 precedent was extended with: data-URI base64, payload-length
// base64 and hash-addressed absolute paths are skipped whole, while the same
// shapes without their discriminator are still flagged.
func TestHighEntropyPayloadAndArtifactExemptions(t *testing.T) {
	det := NewHighEntropyDetector()
	// A diverse 40-char hex segment: a low-entropy repetition would fall below
	// the entropy floor on its own, making the exempt cases vacuous.
	hex40 := strings.Repeat("0123456789abcdef", 2) + "01234567"

	imageB64 := base64.StdEncoding.EncodeToString([]byte(pseudoRandom(150)))
	shortB64 := base64.StdEncoding.EncodeToString([]byte(pseudoRandom(60)))
	payloadAtMin := pseudoRandom(structuralPayloadMinRun)
	payloadBelowMin := pseudoRandom(structuralPayloadMinRun - 1)
	artifactPath := "/tmp/build/" + hex40 + "/out.bin"
	plainLongPath := "/tmp/build/" + pseudoRandom(40) + "/out.bin"
	relativeArtifact := "dist/" + hex40 + "/out.bin"
	plainRelative := "dist/" + pseudoRandom(40) + "/out.bin"

	cases := []detectorCase{
		{name: "data_uri_base64_payload_exempt", content: "data:image/png;base64," + imageB64},
		{name: "base64_payload_without_data_uri_marker_still_flagged",
			content: "blob " + shortB64, found: []string{shortB64}},
		{name: "payload_run_at_min_exempt", content: "blob " + payloadAtMin + " end"},
		{name: "run_below_payload_min_still_flagged",
			content: "blob " + payloadBelowMin + " end", found: []string{payloadBelowMin}},
		{name: "sha256_artifact_path_exempt", content: "wrote " + artifactPath + " ok"},
		{name: "absolute_path_without_long_hash_still_flagged",
			content: "wrote " + plainLongPath + " ok", found: []string{strings.TrimSuffix(plainLongPath, ".bin")}},
		{name: "relative_hash_artifact_path_exempt", content: "wrote " + relativeArtifact + " ok"},
		{name: "relative_path_without_long_hash_still_flagged",
			content: "wrote " + plainRelative + " ok", found: []string{strings.TrimSuffix(plainRelative, ".bin")}},
	}
	runDetectorCases(t, det, typeHighEntropy, highEntropyConfidence, cases)
}

// TestHighEntropyPlainFieldBase64Exemption pins the live case that motivated
// lowering structuralPayloadMinRun from 256 to 128: a 200-character base64 run
// sitting in an ordinary JSON string field — no data-URI marker, no provider
// prefix — is an opaque payload, not a credential, and must not be redacted.
// The length (200) is the observed live case; it is deliberately not derived
// from the constant, so the test keeps asserting the same shape after the
// threshold moves.
func TestHighEntropyPlainFieldBase64Exemption(t *testing.T) {
	const liveCasePayloadLen = 200
	det := NewHighEntropyDetector()
	payload := pseudoRandom(liveCasePayloadLen)

	runDetectorCases(t, det, typeHighEntropy, highEntropyConfidence, []detectorCase{
		{name: "plain_field_base64_at_live_length_exempt", content: `{"data":"` + payload + `"}`},
	})
}

// TestStructuralIdentifierContains pins the egress helper that closes the hole
// the exemptions would otherwise open: a known secret is "inside" an exempted
// run when the run matches any exemption class, but an allowlist-shaped wrapper
// or ordinary prose is not.
func TestStructuralIdentifierContains(t *testing.T) {
	genuine := "kR8mQ2vZ9pL4wX7nT1bY6cH3jF5dS0aG"
	hex40 := strings.Repeat("ab12", 10)
	payloadRun := pseudoRandom(200) + genuine + pseudoRandom(24)

	if len(payloadRun) < structuralPayloadMinRun {
		t.Fatalf("fixture error: payload run is %d bytes, want at least %d", len(payloadRun), structuralPayloadMinRun)
	}

	cases := []struct {
		name    string
		content string
		needle  string
		want    bool
	}{
		{name: "known_secret_inside_tool_call_id", content: "call_" + genuine, needle: genuine, want: true},
		{name: "known_secret_inside_tool_use_id", content: "toolu_" + genuine, needle: genuine, want: true},
		{name: "known_secret_inside_request_id", content: "req_" + genuine, needle: genuine, want: true},
		{name: "known_secret_inside_trace_id", content: "trace_" + genuine, needle: genuine, want: true},
		{name: "known_secret_inside_prefixed_hash", content: "sha512-" + genuine, needle: genuine, want: true},
		{name: "known_secret_inside_payload_key_value", content: `{"file_data":"` + genuine + `"}`, needle: genuine, want: true},
		{name: "known_secret_inside_relative_hashed_path", content: "dist/" + hex40 + "/" + genuine + "/out", needle: genuine, want: true},
		{name: "known_secret_inside_data_uri_payload", content: "data:image/png;base64," + genuine, needle: genuine, want: true},
		{name: "known_secret_inside_payload_length_run", content: payloadRun, needle: genuine, want: true},
		{name: "known_secret_inside_hashed_artifact_path", content: "/tmp/build/" + hex40 + "/" + genuine + "/out", needle: genuine, want: true},
		{name: "known_secret_in_allowlist_wrapper", content: "keep." + genuine + ".keep", needle: genuine, want: false},
		{name: "known_secret_in_plain_sentence", content: "the value is " + genuine + " here", needle: genuine, want: false},
		{name: "known_secret_in_short_base64_run", content: base64.StdEncoding.EncodeToString([]byte(genuine)), needle: genuine, want: false},
		{name: "empty_needle_never_matches", content: "call_" + genuine, needle: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StructuralIdentifierContains([]byte(tc.content), []byte(tc.needle)); got != tc.want {
				t.Fatalf("StructuralIdentifierContains(%q, %q) = %v, want %v", tc.content, tc.needle, got, tc.want)
			}
		})
	}
}

// TestHighEntropyPayloadKeyPathExemption pins the path half of the payload-key
// rule: a plain JSON leaf whose member name is a payload-carrying key is exempt
// below the length floor, because the leaf's decoded value alone cannot carry
// its member name. An array element or a non-enumerated name still takes the
// length rule.
func TestHighEntropyPayloadKeyPathExemption(t *testing.T) {
	det := NewHighEntropyDetector()
	payload := base64.StdEncoding.EncodeToString([]byte(pseudoRandom(90))) // 120 chars, below min
	if len(payload) >= structuralPayloadMinRun {
		t.Fatalf("fixture error: payload is %d bytes, want below %d", len(payload), structuralPayloadMinRun)
	}
	doc := func(path string) *extension.Document {
		return &extension.Document{
			Phase:  extension.RequestContent,
			Tool:   "test",
			Leaves: []extension.Leaf{{Path: path, Content: []byte(payload), Len: len(payload)}},
		}
	}

	for _, path := range []string{"/file_data", "/request/file_data", "/tool_call#/data", "/image_url", "/content_bytes"} {
		if got := mustFindings(t, det, doc(path)); len(got) != 0 {
			t.Errorf("path %q: findings = %d, want 0", path, len(got))
		}
	}
	for _, path := range []string{"/content", "/input", "/data/0", "/file_data_extra"} {
		if got := mustFindings(t, det, doc(path)); len(got) != 1 {
			t.Errorf("path %q: findings = %d, want 1", path, len(got))
		}
	}
}

// TestKnownStructuralIdentifierExemptions locks the honesty list to its
// documentation artifact and requires every implemented grammar to be listed.
func TestKnownStructuralIdentifierExemptions(t *testing.T) {
	list := KnownStructuralIdentifierExemptions()
	if len(list) == 0 {
		t.Fatal("KnownStructuralIdentifierExemptions() is empty")
	}

	path := filepath.Join("testdata", "known_structural_exemptions.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	parsed := parseUncoveredList(raw)
	if !equalStrings(list, parsed) {
		t.Fatalf("accessor and %s drifted:\n accessor=%q\n file=%q", path, list, parsed)
	}

	for _, grammar := range []string{"call_", "toolu_", "chatcmpl-", "msg_", "resp_", "req_", "trace_", "span_", "run_", "job_", "build_", "sha512-", "data:", "payload-carrying key", "128", "hex segment"} {
		if !anyLineContains(list, grammar) {
			t.Fatalf("the %q grammar is not recorded: %q", grammar, list)
		}
	}
	if !anyLineContains(list, "residual risk") {
		t.Fatalf("the residual-risk line is not recorded: %q", list)
	}
	t.Logf("known structural identifier exemptions (%d): %q", len(list), list)
}
