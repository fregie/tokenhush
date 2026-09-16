package redact

import (
	"os"
	"path/filepath"
	"testing"
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
		{name: "random_secret_without_prefix_still_flagged", content: "token " + genuine + " end", found: []string{genuine}},
		{name: "exempt_prefix_random_stem_is_the_recorded_gap", content: "id call_" + genuine + " end"},
	}
	runDetectorCases(t, det, typeHighEntropy, highEntropyConfidence, cases)
}

// TestStructuralIdentifierContains pins the egress helper that closes the hole
// the exemption would otherwise open: a known secret is "inside" an exempted
// run when the run matches the grammar, but an allowlist-shaped wrapper is not.
func TestStructuralIdentifierContains(t *testing.T) {
	genuine := "kR8mQ2vZ9pL4wX7nT1bY6cH3jF5dS0aG"

	cases := []struct {
		name    string
		content string
		needle  string
		want    bool
	}{
		{name: "known_secret_inside_tool_call_id", content: "call_" + genuine, needle: genuine, want: true},
		{name: "known_secret_inside_tool_use_id", content: "toolu_" + genuine, needle: genuine, want: true},
		{name: "known_secret_in_allowlist_wrapper", content: "keep." + genuine + ".keep", needle: genuine, want: false},
		{name: "known_secret_in_plain_sentence", content: "the value is " + genuine + " here", needle: genuine, want: false},
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

	for _, grammar := range []string{"call_", "toolu_", "chatcmpl-", "msg_", "resp_"} {
		if !anyLineContains(list, grammar) {
			t.Fatalf("the %q grammar is not recorded: %q", grammar, list)
		}
	}
	if !anyLineContains(list, "residual risk") {
		t.Fatalf("the residual-risk line is not recorded: %q", list)
	}
	t.Logf("known structural identifier exemptions (%d): %q", len(list), list)
}
