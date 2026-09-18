package redact

import (
	"bytes"
	"encoding/json"
	"testing"
)

// sseJSONEnvelope renders one SSE record whose data value is a real JSON
// document carrying p in a choices[0].delta.content string.
func sseJSONEnvelope(t *testing.T, p string) string {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"choices": []any{
			map[string]any{"delta": map[string]string{"content": p}},
		},
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return "data: " + string(doc) + "\n\n"
}

func TestSSEBackfillJSONEnvelopeStaysParseable(t *testing.T) {
	back, p := mintRestorable(t, pemSecret, "private_key")
	in := sseJSONEnvelope(t, p)

	out := NewSSEBackfiller(back, nil).process([]byte(in))
	events := decodeStream(t, out)
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	for i, ev := range events {
		if !json.Valid(ev.Data) {
			t.Fatalf("event %d data is not valid JSON: %q", i, ev.Data)
		}
		var doc struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(ev.Data, &doc); err != nil {
			t.Fatalf("event %d unmarshal: %v", i, err)
		}
		if got := doc.Choices[0].Delta.Content; got != string(pemSecret) {
			t.Fatalf("event %d content = %q, want %q", i, got, pemSecret)
		}
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder survived the SSE restore: %q", out)
	}
}

func TestSSEBackfillRawFragmentsStayByteIdentical(t *testing.T) {
	back, _ := mintRestorable(t, pemSecret, "private_key")
	in := "data: [DONE]\n\n" +
		"event: ping\ndata: alive\n\n" +
		"event: delta\ndata: plain text delta\n\n"

	out := NewSSEBackfiller(back, nil).process([]byte(in))
	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("raw fragments changed:\n got %q\nwant %q", out, in)
	}
}

// TestPlaceholderMatcherTokenLenRequiresPrefix: a token is only recognised at
// its true start. The bytes before `__PII_` belong to the surrounding document
// and must never be absorbed into the token, or a JSON envelope's quote would
// be replaced along with the placeholder.
func TestPlaceholderMatcherTokenLenRequiresPrefix(t *testing.T) {
	const token = "__PII_email_abc123def456__"
	m := placeholderMatcher{}

	if got := m.TokenLen([]byte(token)); got != len(token) {
		t.Fatalf("TokenLen(%q) = %d, want %d", token, got, len(token))
	}
	for _, shifted := range []string{
		`"` + token,
		`":"` + token + `"`,
		"before " + token,
		`before "` + token,
	} {
		if got := m.TokenLen([]byte(shifted)); got != 0 {
			t.Fatalf("TokenLen(%q) = %d, want 0 (no token starts at a non-prefix byte)", shifted, got)
		}
	}
}
